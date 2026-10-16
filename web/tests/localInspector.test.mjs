import assert from 'node:assert/strict'
import test from 'node:test'
import { createHash, webcrypto } from 'node:crypto'
import {
  compareLocalArtifacts, digestArtifactFile, digestArtifactSelection, LIMITS,
  parseCandidateJSON, readCandidateFile, SAMPLE_CANDIDATE, validateCandidate,
} from '../src/localInspector.js'

const bytes = s => new TextEncoder().encode(s)
const sha = s => createHash('sha256').update(s).digest('hex')
const fakeFile = (text, name = 'artifact.json') => {
  const content = bytes(text)
  return { name, size: content.byteLength, text: async () => text, arrayBuffer: async () => content.buffer }
}
function validCandidate() {
  return {
    schema_version: 2, feature: 'Owned test feature',
    authorization: { scope: 'Owned', basis: 'Owner-created test', approved_by: 'Owner' },
    snapshot_sha256: sha('snapshot'),
    rules: [{ id: 'R1', behavior: 'Searching a term in a title returns matching results.',
      evidence: [{ id: 'E1', kind: 'test', provenance: 'VERIFIED',
        summary: 'Owned reproducible test case', artifact_sha256: sha('result') }],
    }],
  }
}

test('structurally valid v2 candidate is accepted without claiming proof', () => {
  const doc = validCandidate()
  assert.deepEqual(validateCandidate(doc), [])
  assert.deepEqual(parseCandidateJSON(JSON.stringify(doc)), doc)
})

test('shipped public sample is marked SYNTHETIC and not VERIFIED', () => {
  assert.deepEqual(validateCandidate(SAMPLE_CANDIDATE), [])
  assert.match(SAMPLE_CANDIDATE.feature, /SYNTHETIC/)
  assert.equal(compareLocalArtifacts(SAMPLE_CANDIDATE).declaredVerified, false)
})

test('rejects legacy version, absent authorization and unsupported source code', () => {
  const wrong = validCandidate(); wrong.schema_version = 1
  assert.ok(validateCandidate(wrong).length)
  const missing = validCandidate(); delete missing.authorization
  assert.ok(validateCandidate(missing).length)
  const extra = validCandidate(); extra.rules[0].source_code = 'not allowed'
  assert.ok(validateCandidate(extra).length)
})

test('rejects duplicate IDs, multiline and invented provenance categories', () => {
  const duplicated = validCandidate()
  duplicated.rules.push(JSON.parse(JSON.stringify(duplicated.rules[0])))
  assert.ok(validateCandidate(duplicated).some(error => error.includes('duplicate')))
  const invalid = validCandidate()
  invalid.rules[0].evidence[0].provenance = 'magic'
  assert.ok(validateCandidate(invalid).length)
  const line = validCandidate()
  line.rules[0].behavior = 'Valid\n# Unreviewed instructions'
  assert.ok(validateCandidate(line).length)
})

test('rejects invalid JSON, oversized candidate and oversized manifest file', async () => {
  assert.throws(() => parseCandidateJSON('{no'), /valid JSON/)
  assert.throws(() => parseCandidateJSON('x'.repeat(LIMITS.manifestBytes + 1)), /too large/)
  await assert.rejects(readCandidateFile({ size: LIMITS.manifestBytes + 1 }), /512 KiB/)
})

test('hashes real byte payloads locally with native Web Crypto', async () => {
  const file = fakeFile('result')
  const info = await digestArtifactFile(file, webcrypto.subtle)
  assert.equal(info.sha256, sha('result'))
  assert.equal(info.name, 'artifact.json')
  const list = await digestArtifactSelection([fakeFile('snapshot'), file], webcrypto.subtle)
  assert.equal(list.length, 2)
})

test('reports the target snapshot and evidence only on exact SHA-256 matches', () => {
  const doc = validCandidate()
  const partial = compareLocalArtifacts(doc, [{ name: 'snapshot', sha256: sha('snapshot') }])
  assert.equal(partial.matched, 1)
  assert.equal(partial.allBytesMatched, false)
  const full = compareLocalArtifacts(doc, [
    { name: 'snapshot', sha256: sha('snapshot') },
    { name: 'result', sha256: sha('result') },
  ])
  assert.equal(full.allBytesMatched, true)
  assert.equal(full.declaredVerified, true)
  assert.equal(full.total, 2)
  const mismatched = compareLocalArtifacts(doc, [{ name: 'wrong', sha256: sha('not-result') }])
  assert.equal(mismatched.unmatchedFiles.length, 1)
  assert.equal(mismatched.matched, 0)
})

test('truthy and malformed file references cannot fake cryptographic matches', () => {
  const doc = validCandidate()
  assert.equal(compareLocalArtifacts(doc, [{ sha256: true }]).allBytesMatched, false)
  assert.equal(compareLocalArtifacts(doc, []).matched, 0)
  assert.throws(() => compareLocalArtifacts({}), /Invalid candidate/)
})

test('file count, byte limits and missing Web Crypto fail closed', async () => {
  const many = Array.from({ length: LIMITS.artifactFiles + 1 }, () => fakeFile('x'))
  await assert.rejects(digestArtifactSelection(many, webcrypto.subtle), /at most 12/)
  await assert.rejects(digestArtifactFile({ name: 'large', size: LIMITS.artifactBytes + 1 }, webcrypto.subtle), /16 MiB/)
  await assert.rejects(digestArtifactFile(fakeFile('x'), null), /unavailable/)
})
