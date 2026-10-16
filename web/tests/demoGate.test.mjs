import assert from 'node:assert/strict'
import test from 'node:test'
import { CONTROL_FIELDS, evaluateDemo, INITIAL_CHECKS } from '../src/demoGate.js'

test('starts blocked before human approval', () => {
  const result = evaluateDemo(INITIAL_CHECKS)
  assert.equal(result.canExport, false)
  assert.deepEqual(result.missing, ['Explicit review'])
})

test('all recorded controls allow simulated export', () => {
  const result = evaluateDemo(Object.fromEntries(CONTROL_FIELDS.map(({key}) => [key, true])))
  assert.equal(result.canExport, true)
  assert.equal(result.reviewed, 4)
})

test('each deliberately broken control fails closed', () => {
  for (const {key} of CONTROL_FIELDS) {
    const checks = Object.fromEntries(CONTROL_FIELDS.map(({key: name}) => [name, true]))
    checks[key] = false
    assert.equal(evaluateDemo(checks).canExport, false, key)
  }
})

test('missing control is never assumed to be true', () => {
  assert.equal(evaluateDemo({humanApproval: true}).canExport, false)
})

test('truthy strings cannot pass the simulated gate', () => {
  const checks = Object.fromEntries(CONTROL_FIELDS.map(({key}) => [key, true]))
  checks.humanApproval = 'true'
  assert.equal(evaluateDemo(checks).canExport, false)
})
