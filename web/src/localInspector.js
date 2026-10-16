/**
 * Read-only, browser-only v2 candidate inspector.
 * No fetch(), browser storage, approval, or export of real builder packets.
 */
export const LIMITS = Object.freeze({
  manifestBytes: 512 * 1024, artifactBytes: 16 * 1024 * 1024,
  artifactFiles: 12, rules: 64, evidenceRecords: 256,
})
const SHA = /^[0-9a-f]{64}$/
const ID = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/
const PROVENANCE = new Set(['OBSERVED', 'VERIFIED', 'INFERRED', 'DREAMED', 'SIMULATED', 'UNKNOWN'])
const KINDS = new Set(['observation', 'test'])
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const oneLine = value => typeof value === 'string' && value.trim().length > 0 && !/[\r\n]/.test(value)
const validHash = value => typeof value === 'string' && SHA.test(value)
const unexpectedKeys = (obj, allowed, place, problems) => {
  for (const key of Object.keys(obj)) if (!allowed.includes(key)) problems.push(place + ': unexpected field ' + key)
}

/** Structural inspection; claimed provenance is not treated as independently verified. */
export function validateCandidate(doc) {
  const problems = []
  if (!object(doc)) return ['Candidate must be a JSON object.']
  unexpectedKeys(doc, ['schema_version', 'feature', 'authorization', 'snapshot_sha256', 'rules'], 'candidate', problems)
  if (doc.schema_version !== 2) problems.push('Only Evidence Vault candidate schema v2 is supported.')
  if (!oneLine(doc.feature) || doc.feature.length > 160) problems.push('Feature name must be 1-160 single-line characters.')
  if (!validHash(doc.snapshot_sha256)) problems.push('Snapshot digest must be a lowercase SHA-256 hex string.')
  if (!object(doc.authorization)) problems.push('Authorization declaration is missing.')
  else {
    unexpectedKeys(doc.authorization, ['scope','basis','approved_by'], 'authorization', problems)
    for (const key of ['scope','basis','approved_by']) {
      if (!oneLine(doc.authorization[key])) problems.push('Authorization ' + key + ' must be a nonempty single line.')
    }
  }
  if (!Array.isArray(doc.rules) || doc.rules.length === 0 || doc.rules.length > LIMITS.rules) {
    problems.push('Rules must be a nonempty array with at most ' + LIMITS.rules + ' entries.')
    return problems
  }
  let totalEvidence = 0
  const ruleIds = new Set()
  const evidenceIds = new Set()
  doc.rules.forEach((rule, index) => {
    const loc = 'R[' + index + ']'
    if (!object(rule)) { problems.push(loc + ' must be an object.'); return }
    unexpectedKeys(rule, ['id','behavior','evidence'], loc, problems)
    if (typeof rule.id !== 'string' || !ID.test(rule.id) || ruleIds.has(rule.id)) {
      problems.push(loc + ': invalid or duplicate rule identifier.')
    } else ruleIds.add(rule.id)
    const behavior = rule.behavior
    if (!oneLine(behavior) || behavior.length > 2000 || behavior.includes(String.fromCharCode(96).repeat(3))) {
      problems.push(loc + ': behavioral rule must be single-line text with no code fence (max 2000 characters).')
    }
    if (!Array.isArray(rule.evidence) || !rule.evidence.length) {
      problems.push(loc + ': at least one evidence record is required.')
      return
    }
    totalEvidence += rule.evidence.length
    rule.evidence.forEach((evidence, number) => {
      const ref = loc + '.E[' + number + ']'
      if (!object(evidence)) { problems.push(ref + ' must be an object.'); return }
      unexpectedKeys(evidence, ['id','kind','provenance','summary','artifact_sha256'], ref, problems)
      if (typeof evidence.id !== 'string' || !ID.test(evidence.id) || evidenceIds.has(evidence.id)) {
        problems.push(ref + ': invalid or duplicate evidence identifier.')
      } else evidenceIds.add(evidence.id)
      if (typeof evidence.kind !== 'string' || !KINDS.has(evidence.kind)) problems.push(ref + ': kind must be observation or test.')
      if (typeof evidence.provenance !== 'string' || !PROVENANCE.has(evidence.provenance)) problems.push(ref + ': unknown NBG provenance.')
      if (!oneLine(evidence.summary)) problems.push(ref + ': summary must be a single nonempty line.')
      if (!validHash(evidence.artifact_sha256)) problems.push(ref + ': evidence SHA-256 digest must be lowercase hex.')
    })
  })
  if (totalEvidence > LIMITS.evidenceRecords) problems.push('Too many evidence records (max ' + LIMITS.evidenceRecords + ').')
  return problems.slice(0, 30)
}

export function parseCandidateJSON(text) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).byteLength > LIMITS.manifestBytes) {
    throw new Error('Manifest is too large (maximum 512 KiB).')
  }
  let parsed
  try { parsed = JSON.parse(text) }
  catch { throw new Error('Manifest must contain valid JSON.') }
  const problems = validateCandidate(parsed)
  if (problems.length) throw new Error(problems.slice(0, 5).join(' ') + (problems.length > 5 ? ' (and more)' : ''))
  return parsed
}

export async function readCandidateFile(file) {
  if (!file || !Number.isSafeInteger(file.size) || file.size > LIMITS.manifestBytes) {
    throw new Error('Choose a candidate JSON file no larger than 512 KiB.')
  }
  return parseCandidateJSON(await file.text())
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('')
}

/** Native Web Crypto: no file bytes are ever uploaded or persisted. */
export async function digestArtifactFile(file, subtle = globalThis.crypto?.subtle) {
  if (!file || !Number.isSafeInteger(file.size) || file.size > LIMITS.artifactBytes) {
    throw new Error('Each selected artifact must be at most 16 MiB.')
  }
  if (!subtle?.digest) throw new Error('SHA-256 unavailable. Open over HTTPS in a modern browser.')
  const hash = await subtle.digest('SHA-256', await file.arrayBuffer())
  return {
    name: typeof file.name === 'string' ? file.name.slice(0, 120) : 'selected file',
    size: file.size, sha256: hex(hash),
  }
}

export async function digestArtifactSelection(files, subtle = globalThis.crypto?.subtle) {
  const selected = Array.from(files || [])
  if (selected.length > LIMITS.artifactFiles) throw new Error('Select at most 12 files at a time.')
  if (selected.some(file => !Number.isSafeInteger(file.size) || file.size > LIMITS.artifactBytes)) {
    throw new Error('Each selected file must be at most 16 MiB.')
  }
  const items = []
  for (const file of selected) items.push(await digestArtifactFile(file, subtle))
  return items
}

export function compareLocalArtifacts(doc, hashedFiles = []) {
  const errors = validateCandidate(doc)
  if (errors.length) throw new Error('Invalid candidate: ' + errors[0])
  const supplied = new Map()
  for (const file of hashedFiles) {
    if (validHash(file.sha256)) {
      if (!supplied.has(file.sha256)) supplied.set(file.sha256, [])
      supplied.get(file.sha256).push(file.name)
    }
  }
  const references = [
    { id: 'SNAPSHOT', rule: 'TARGET', provenance: 'UNASSESSED', summary: 'Investigator-supplied target snapshot file', sha256: doc.snapshot_sha256 },
    ...doc.rules.flatMap(rule => rule.evidence.map(item => ({
      id: item.id, rule: rule.id, provenance: item.provenance,
      summary: item.summary, sha256: item.artifact_sha256,
    }))),
  ]
  const rows = references.map(ref => ({ ...ref, matchingFiles: supplied.get(ref.sha256) ?? [], matched: supplied.has(ref.sha256) }))
  const referencedDigests = new Set(references.map(ref => ref.sha256))
  const unmatchedFiles = hashedFiles.filter(file => !referencedDigests.has(file.sha256))
  return {
    rows, matched: rows.filter(row => row.matched).length, total: rows.length,
    unmatchedFiles, allBytesMatched: rows.length > 0 && rows.every(row => row.matched),
    declaredVerified: doc.rules.every(rule => rule.evidence.every(item => item.provenance === 'VERIFIED')),
  }
}

/** Sample deliberately has no real evidence or approval. */
export const SAMPLE_CANDIDATE = Object.freeze({
  schema_version: 2,
  feature: 'SYNTHETIC SAMPLE: title lookup',
  authorization: {
    scope: 'Synthetic demonstration only',
    basis: 'Fabricated in PhiCleanroom public UI',
    approved_by: 'SAMPLE, NOT AUTHORIZATION',
  },
  snapshot_sha256: 'a'.repeat(64),
  rules: [{
    id: 'R1',
    behavior: 'When a title term matches an item, the item appears in results.',
    evidence: [{
      id: 'E1', kind: 'test', provenance: 'SIMULATED',
      summary: 'Synthetic example evidence, not a real executed test',
      artifact_sha256: 'b'.repeat(64),
    }],
  }],
})
