// In-browser teaching simulation only. The real evidence gate is the Python CLI.
export const INITIAL_CHECKS = Object.freeze({
  authorized: true,
  artifactMatches: true,
  provenanceVerified: true,
  humanApproval: false,
})

export const CONTROL_FIELDS = Object.freeze([
  { key: 'authorized', short: 'Scope authorized', title: 'Authorized target', detail: 'The investigator has documented permission to inspect this behavior.' },
  { key: 'artifactMatches', short: 'SHA-256 matches', title: 'Evidence integrity', detail: 'A stored artifact and source snapshot match their recorded SHA-256 digests.' },
  { key: 'provenanceVerified', short: 'Provenance VERIFIED', title: 'Verified evidence', detail: 'The reviewer has checked the observation. Inference is not silently promoted to fact.' },
  { key: 'humanApproval', short: 'Human approval', title: 'Explicit review', detail: 'The exact frozen specification has a current human-entered approval for each rule.' },
])

export function evaluateDemo(checks) {
  const missing = CONTROL_FIELDS.filter(({ key }) => checks[key] !== true)
  return {
    canExport: missing.length === 0,
    state: missing.length === 0 ? 'ELIGIBLE FOR SPEC EXPORT' : 'BLOCKED BY EVIDENCE GATE',
    missing: missing.map((item) => item.title),
    reviewed: CONTROL_FIELDS.length - missing.length,
    total: CONTROL_FIELDS.length,
  }
}
