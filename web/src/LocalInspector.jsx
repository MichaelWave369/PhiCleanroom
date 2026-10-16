import React, { useRef, useState } from 'react'
import {
  compareLocalArtifacts, digestArtifactSelection, LIMITS, readCandidateFile,
  SAMPLE_CANDIDATE,
} from './localInspector.js'

const shortHash = (value) => value.slice(0, 15) + '…' + value.slice(-9)

export default function LocalInspector() {
  const [candidate, setCandidate] = useState(null)
  const [candidateName, setCandidateName] = useState('')
  const [selectedFiles, setSelectedFiles] = useState([])
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const session = useRef(0)
  const candidateInput = useRef(null)
  const artifactInput = useRef(null)

  const assessment = candidate ? compareLocalArtifacts(candidate, selectedFiles) : null

  function reset() {
    session.current += 1
    setCandidate(null)
    setCandidateName('')
    setSelectedFiles([])
    setError('')
    setBusy('')
    if (candidateInput.current) candidateInput.current.value = ''
    if (artifactInput.current) artifactInput.current.value = ''
  }

  function loadSample() {
    reset()
    setCandidate(SAMPLE_CANDIDATE)
    setCandidateName('SYNTHETIC SAMPLE / NO REAL EVIDENCE')
  }

  async function loadCandidate(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const token = ++session.current
    setBusy('Reading candidate manifest…')
    setError('')
    setCandidate(null)
    setCandidateName('')
    setSelectedFiles([])
    if (artifactInput.current) artifactInput.current.value = ''
    try {
      const parsed = await readCandidateFile(file)
      if (token !== session.current) return
      setCandidate(parsed)
      setCandidateName(file.name.slice(0, 120))
    } catch (cause) {
      if (token === session.current) setError(cause.message || 'Could not inspect manifest.')
    } finally {
      if (token === session.current) setBusy('')
      event.target.value = ''
    }
  }

  async function hashFiles(event) {
    const files = Array.from(event.target.files || [])
    if (!files.length || !candidate) return
    const token = ++session.current
    setBusy('Hashing selected files locally…')
    setError('')
    setSelectedFiles([])
    try {
      const results = await digestArtifactSelection(files)
      if (token === session.current) setSelectedFiles(results)
    } catch (cause) {
      if (token === session.current) setError(cause.message || 'Cannot calculate SHA-256.')
    } finally {
      if (token === session.current) setBusy('')
      event.target.value = ''
    }
  }

  return <section className="page-section inspector-section" aria-labelledby="inspector-title">
    <div className="section-shell" id="inspector">
      <div className="section-header">
        <div className="section-index"><span>03</span><span className="section-index-rule" /> LOCAL MANIFEST INSPECTOR</div>
        <h2 id="inspector-title">Bring the evidence. <span className="mint-text">Keep the control.</span></h2>
        <p>Open a PhiCleanroom Evidence Vault v2 candidate and compare its declared SHA-256 digests with files you select from your device. This is a browser-side read-only inspection, not a release or approval workflow.</p>
      </div>

      <div className="inspector-wrap">
        <div className="inspector-top"><span><i className="inspector-led" /> LOCAL ONLY / NO FILE UPLOADS</span><span>READ-ONLY • EPHEMERAL SESSION</span></div>
        <div className="inspector-columns">
          <div className="inspector-upload">
            <div className="inspector-step-label">01 / LOAD CANDIDATE</div>
            <h3>Your v2 manifest, your device.</h3>
            <p>Read an authorized <code>candidate.json</code> with rules, provenance claims, and evidence hashes. Nothing is sent to a server or saved by this page.</p>
            <label className="file-picker">
              <span aria-hidden="true">＋</span> Choose v2 JSON manifest
              <input ref={candidateInput} type="file" accept=".json,application/json" onChange={loadCandidate} disabled={Boolean(busy)} aria-label="Choose local Evidence Vault candidate JSON" />
            </label>
            <button type="button" className="inspector-example" onClick={loadSample} disabled={Boolean(busy)}>Load synthetic sample <span>↗</span></button>
            <div className="inspector-divider" />
            <div className="inspector-step-label">02 / VERIFY FILE BYTES</div>
            <h3>Compare the artifacts.</h3>
            <p>Select the snapshot file and evidence files referenced by the manifest. Only the calculated hashes are kept temporarily in memory.</p>
            <label className={'file-picker secondary ' + (!candidate ? 'disabled' : '')}>
              <span aria-hidden="true">⌁</span> Choose local artifact files
              <input ref={artifactInput} type="file" multiple onChange={hashFiles} disabled={!candidate || Boolean(busy)} aria-label="Select snapshot and evidence files for local SHA-256 matching" />
            </label>
            <small className="inspector-limit">At most {LIMITS.artifactFiles} files · {LIMITS.artifactBytes / 1048576} MiB each · {LIMITS.manifestBytes / 1024} KiB manifest</small>
            <div className="inspector-reset-wrap"><button type="button" onClick={reset} className="reset-button" disabled={Boolean(busy)}>Clear session ↺</button></div>
          </div>
          <div className="inspector-results">
            <div className="inspector-titleline"><span>03 / INSPECTED RECORD</span><span>NOT AN APPROVAL</span></div>
            {busy && <div className="inspector-activity" role="status">{busy}</div>}
            {error && <div className="inspector-error" role="alert">BLOCKED: {error}</div>}
            {!candidate ? <div className="inspector-empty"><span aria-hidden="true">◇</span><h3>Awaiting local manifest</h3><p>No candidate has been opened. Start with a v2 JSON file or explore the clearly labeled synthetic sample.</p></div> :
              <>
                <div className="inspector-manifest-head">
                  <span>OPENED LOCALLY · {candidateName}</span>
                  <h3>{candidate.feature}</h3>
                  <p>Declared authority: {candidate.authorization.scope}</p>
                </div>
                <div className="inspector-counters">
                  <div><span>RULES</span><b>{candidate.rules.length}</b></div>
                  <div><span>FILES MATCHED</span><b>{assessment.matched}/{assessment.total}</b></div>
                  <div><span>PROVENANCE</span><b className={!assessment.declaredVerified ? 'warn' : ''}>{assessment.declaredVerified ? 'CLAIMED VERIFIED' : 'MIXED / UNVERIFIED'}</b></div>
                </div>
                <div className={'inspector-summary ' + (assessment.allBytesMatched ? 'complete' : '')}>
                  <b>{assessment.allBytesMatched ? 'ALL REFERENCED BYTES MATCH' : 'INCOMPLETE ARTIFACT MATCHING'}</b>
                  <p>{assessment.allBytesMatched ? 'All supplied file digests match the declared references. This does not prove correct behavior or approve a specification.' : 'Select referenced local files to establish byte equality. Missing files are not treated as verified.'}</p>
                </div>
                <div className="inspector-rule-list">
                  {candidate.rules.map(rule => <article key={rule.id} className="inspector-rule">
                    <div className="inspector-rule-top"><span>{rule.id}</span><span>{rule.evidence.length} RECORD(S)</span></div>
                    <p>{rule.behavior}</p>
                    {rule.evidence.map(record => <div className="inspector-proof" key={record.id}><span className="proof-state">{assessment.rows.find(row => row.id === record.id)?.matched ? '● MATCH' : '○ MISSING'}</span><span className="proof-desc">{record.id} · {record.provenance} (declared) · {record.summary}</span></div>)}
                  </article>)}
                </div>
                <div className="inspector-artifacts">
                  <div className="inspector-step-label">REFERENCED SHA-256 DIGESTS</div>
                  {assessment.rows.map(row => <div className="inspector-hash-row" key={row.id}><span className={row.matched ? 'hash-ok' : 'hash-missing'}>{row.matched ? '✓' : '○'}</span><strong>{row.rule} / {row.id}</strong><code title={row.sha256}>{shortHash(row.sha256)}</code></div>)}
                </div>
                {assessment.unmatchedFiles.length > 0 && <p className="inspector-unmatched">Selected file(s) not matching any referenced digest: {assessment.unmatchedFiles.map(item => item.name).join(', ')}</p>}
                <div className="inspector-footnote">SHA-256 proves selected bytes match declared hashes, not that the contents are true. Human review, provenance verification, stage approval, and the real Python vault remain separate.</div>
              </>}
          </div>
        </div>
        <div className="inspector-bottom"><span>FILES STAY IN YOUR BROWSER SESSION</span><span>NO NETWORK UPLOAD • NO STORAGE • NO RELEASE AUTHORITY</span></div>
      </div>
    </div>
  </section>
}
