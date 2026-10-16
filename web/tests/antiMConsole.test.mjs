import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'
import {
  SLOTS, REQUIREMENTS, evaluateCompletion, readSlot, rejectDuplicateNames,
  shaText, syntheticCompletion, validateDocument,
} from '../src/antiMConsole.js'

const utf8 = text => new TextEncoder().encode(text)
const file = (text, name='receipt.json') => {
  const bytes=utf8(text)
  return {name,size:bytes.byteLength,arrayBuffer:async()=>bytes.buffer.slice(0)}
}
const clone = value => JSON.parse(JSON.stringify(value))

test('synthetic demonstration has valid local SHA links but cannot assert human approval',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  for(const {key} of SLOTS)assert.ok(records[key])
  const result=evaluateCompletion(records)
  assert.equal(result.linksMatch,true)
  assert.equal(result.matched,7)
  assert.equal(result.gates.at(-1).state,'NOT_CHECKED')
  assert.ok(!result.gates.some(item=>item.label.includes('DONE')))
  assert.equal(records.contract.doc.requires_human_release,true)
  assert.equal(records.verifier.doc.authority,'NONE')
})

test('empty state remains waiting, never defaults to a reviewed state',()=>{
  const result=evaluateCompletion({})
  assert.equal(result.linksMatch,false)
  assert.equal(result.matched,0)
  assert.equal(result.missing,7)
  assert.equal(result.gates.at(-1).state,'NOT_CHECKED')
})

test('changed source bytes force mismatch, not passing status',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  records.source={...records.source,sha256:await shaText('tampered content',webcrypto.subtle)}
  const result=evaluateCompletion(records)
  assert.equal(result.headline,'LOCAL EVIDENCE MISMATCH')
  assert.equal(result.linksMatch,false)
  assert.equal(result.gates.find(g=>g.id==='source').state,'MISMATCH')
})

test('changed receipt bytes invalidate hash-based link even with same parsed fields',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  records.builder={...records.builder,sha256:await shaText('altered receipt',webcrypto.subtle)}
  const result=evaluateCompletion(records)
  assert.equal(result.gates.find(g=>g.id==='builder').state,'MISMATCH')
  assert.equal(result.linksMatch,false)
})

test('altered stage, spec or builder image are detected as lineage mismatches',async()=>{
  for(const field of ['stage_sha256','spec_sha256','builder_image_id']){
    const records=await syntheticCompletion(webcrypto.subtle)
    records.contract.doc[field]=field==='builder_image_id'?'sha256:'+'f'.repeat(64):'f'.repeat(64)
    const result=evaluateCompletion(records)
    assert.equal(result.gates.find(g=>g.id==='lineage').state,'MISMATCH',field)
    assert.equal(result.linksMatch,false)
  }
})

test('contract with disabled human approval or removed mutation requirement fails closed',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  const altered=clone(records.contract.doc)
  altered.requires_human_release=false
  assert.throws(()=>validateDocument('contract',altered),/Human release/)
  altered.requires_human_release=true
  altered.required_mutants=altered.required_mutants.slice(0,2)
  assert.throws(()=>validateDocument('contract',altered),/omits/)
})

test('no forged verification status, source mutant or missing acceptance case passes',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  for(const change of ['status','authority','checks','mutants','image']){
    const altered=clone(records.verifier.doc)
    if(change==='status')altered.status='DONE'
    if(change==='authority')altered.authority='APPROVED'
    if(change==='checks')altered.checks.pop()
    if(change==='mutants')altered.mutants[0].status='SURVIVED'
    if(change==='image')altered.verifier_image_id='latest'
    assert.throws(()=>validateDocument('verifier',altered),undefined,change)
  }
})

test('builder receipt requires narrow declared Docker policy',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  const altered=clone(records.builder.doc)
  altered.container_policy.network='bridge'
  assert.throws(()=>validateDocument('builder',altered),/policy/)
  altered.container_policy.network='none'
  altered.artifacts[0].path='../source.py'
  assert.throws(()=>validateDocument('builder',altered),/search.py/)
})

test('local input parsing actually hashes raw bytes, rejects malformed and duplicate JSON keys',async()=>{
  const records=await syntheticCompletion(webcrypto.subtle)
  const encoded=JSON.stringify(records.contract.doc,null,2)+'\n'
  const read=await readSlot('contract',file(encoded,'completion.json'),webcrypto.subtle)
  assert.equal(read.sha256,await shaText(encoded,webcrypto.subtle))
  assert.equal(read.doc.kind,records.contract.doc.kind)
  const malformed=file('{"schema_version":1,"schema_version":1}')
  await assert.rejects(readSlot('contract',malformed,webcrypto.subtle),/Duplicate JSON/)
  const nested=file('{"x":{"a":1,"a":2}}')
  await assert.rejects(readSlot('contract',nested,webcrypto.subtle),/Duplicate JSON/)
  assert.doesNotThrow(()=>rejectDuplicateNames('{"a":"escaped \\" quote","b":2}'))
})

test('local source is only hashed and never parsed/executed',async()=>{
  const source='print("would execute only if imported")\n'
  const record=await readSlot('source',file(source,'search.py'),webcrypto.subtle)
  assert.equal(record.sha256,await shaText(source,webcrypto.subtle))
  assert.equal(record.doc,undefined)
})

test('empty, oversized and malformed inputs are rejected',async()=>{
  await assert.rejects(readSlot('contract',{size:0,arrayBuffer:async()=>new ArrayBuffer(0)}),/nonempty/)
  await assert.rejects(readSlot('source',{size:16385}),/16 KiB/)
  await assert.rejects(readSlot('unknown',file('{}')),/Unknown input/)
  await assert.rejects(readSlot('contract',file('not json'),webcrypto.subtle),/Invalid JSON/)
})

test('missing Web Crypto fails instead of pretending to check a hash',async()=>{
  await assert.rejects(readSlot('source',file('test'),null),/SHA-256 unavailable/)
})

test('all reference suites remain pinned to 7 exact checks and 3 distinct mutants',()=>{
  assert.equal(REQUIREMENTS.checks.length,7)
  assert.equal(REQUIREMENTS.mutants.length,3)
  assert.equal(new Set(REQUIREMENTS.checks).size,7)
  assert.equal(new Set(REQUIREMENTS.mutants).size,3)
})
