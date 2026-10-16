import React, { useRef, useState } from 'react'
import { evaluateCompletion, readSlot, SLOTS, syntheticCompletion } from './antiMConsole.js'

const cut = (value, head=17) => value ? value.slice(0,head)+'…'+value.slice(-8) : 'Not loaded'
const STATE = {
  MATCH: { mark:'✓', label:'LOCAL MATCH', tone:'am-success' },
  MISMATCH: { mark:'×', label:'MISMATCH', tone:'am-fail' },
  MISSING: { mark:'○', label:'WAITING', tone:'am-wait' },
  NOT_CHECKED: { mark:'◇', label:'NOT CHECKED', tone:'am-unknown' },
}
const empty=()=>({contract:null,builder:null,verifier:null,source:null})

export default function AntiMConsole(){
  const [files,setFiles]=useState(empty)
  const [errors,setErrors]=useState({})
  const [busy,setBusy]=useState(false)
  const [synthetic,setSynthetic]=useState(false)
  const inputs=useRef({})
  const token=useRef(0)
  const report=evaluateCompletion(files)
  const contract=files.contract?.doc
  const verifier=files.verifier?.doc

  function reset(){
    token.current++
    setFiles(empty())
    setErrors({})
    setSynthetic(false)
    setBusy(false)
    for(const input of Object.values(inputs.current)) if(input)input.value=''
  }
  async function selectFile(slot,event){
    const file=event.target.files?.[0]
    if(!file)return
    const request=++token.current
    setSynthetic(false)
    setBusy(true)
    setErrors(previous=>({...previous,[slot]:null}))
    setFiles(current=>({...current,[slot]:null}))
    try{
      const result=await readSlot(slot,file)
      if(request!==token.current)return
      setFiles(current=>({...current,[slot]:result}))
    }catch(cause){
      if(request===token.current)setErrors(previous=>({...previous,[slot]:cause?.message||'File could not be inspected.'}))
    }finally{
      if(request===token.current)setBusy(false)
      event.target.value=''
    }
  }
  async function loadSynthetic(){
    const request=++token.current
    setBusy(true)
    setErrors({})
    setFiles(empty())
    try{
      const result=await syntheticCompletion()
      if(request!==token.current)return
      setFiles(result)
      setSynthetic(true)
    }catch(cause){
      if(request===token.current)setErrors({contract:cause?.message||'Synthetic fixture unavailable.'})
    }finally{if(request===token.current)setBusy(false)}
  }

  return <section className="page-section antim-section" aria-labelledby="antim-title" id="anti-m">
    <div className="section-shell">
      <div className="section-header">
        <div className="section-index"><span>04</span><span className="section-index-rule" /> ANTI-M COMPLETION CONSOLE / LOCAL VIEWER</div>
        <h2 id="antim-title">No receipt. <span className="mint-text">No DONE.</span></h2>
        <p>Inspect the complete Anti-M v1 evidence chain without uploading files. The console hashes locally selected documents and source bytes, checks the cross-document links, and deliberately keeps live Vault approval and human identity <b>unverified</b>.</p>
      </div>
      <div className="antim-shell">
        <div className="antim-header">
          <span><i className="inspector-led" /> ANTI-M / EVIDENCE CONSOLE 01</span>
          <span>LOCAL-ONLY • READ-ONLY • NO RELEASE CAPABILITY</span>
        </div>
        <div className="antim-main">
          <div className="antim-load">
            <div className="inspector-step-label">01 / RECONCILE LOCAL FILES</div>
            <h3>Show the work.</h3>
            <p>The four inputs below come from your own Anti-M and Docker workflow. No secret keys, vault objects, source archives or attestation credentials are needed.</p>
            <div className="antim-file-list">
              {SLOTS.map((item,index)=><div className={'antim-file '+(files[item.key]?'present':'')} key={item.key}>
                <div className="antim-file-top"><span>0{index+1} / {item.title}</span><span>{files[item.key]?'SELECTED':'REQUIRED'}</span></div>
                <label className="antim-picker">
                  <input ref={node=>{inputs.current[item.key]=node}} type="file"
                    accept={item.key==='source'?'.py,text/x-python':'.json,application/json'}
                    disabled={busy} onChange={e=>selectFile(item.key,e)}
                    aria-label={'Choose local '+item.title} />
                  <span aria-hidden="true">{files[item.key]?'✓':'＋'}</span>
                  <strong>{files[item.key]?.name||'Choose '+item.name}</strong>
                  <span className="antim-pick-action">BROWSE</span>
                </label>
                {files[item.key]&&<div className="antim-sha"><span>SHA-256</span><code title={files[item.key].sha256}>{cut(files[item.key].sha256,19)}</code></div>}
                {errors[item.key]&&<div className="antim-input-error" role="alert">BLOCKED: {errors[item.key]}</div>}
              </div>)}
            </div>
            <div className="antim-actions">
              <button type="button" onClick={loadSynthetic} disabled={busy} className="antim-demo">{busy?'WORKING…':'LOAD SYNTHETIC DEMO'} <span>↗</span></button>
              <button type="button" onClick={reset} disabled={busy} className="reset-button">Clear session ↺</button>
            </div>
            <p className="antim-note">All operations run inside this browser tab. No files are uploaded and no source is executed. For sensitive investigation artifacts, prefer the local Python CLI over any hosted webpage.</p>
          </div>
          <div className="antim-right">
            <div className="antim-readout-top"><span>02 / COMPLETION EVIDENCE</span><span>PUBLIC VIEWER · ZERO AUTHORITY</span></div>
            {synthetic&&<div className="antim-demo-banner">SYNTHETIC SAMPLE ONLY. Every hash, receipt and test result in this example is fabricated to demonstrate the interface.</div>}
            <div className={'antim-decision '+(report.failures?'has-failure':report.linksMatch?'has-matches':'needs-files')}>
              <div className="antim-decision-mark">{report.failures?'×':report.linksMatch?'✓':'◇'}</div>
              <div>
                <div className="antim-overline">LOCAL CRYPTOGRAPHIC RECONCILIATION</div>
                <h3>{report.headline}</h3>
                <p>{report.detail}</p>
              </div>
            </div>
            <div className="antim-progress-header"><span>LOCAL LINKS RECONCILED</span><strong>{report.matched}/7</strong></div>
            <div className="antim-progress-track"><span style={{width:(report.matched/7*100)+'%'}} /></div>
            <div className="antim-gates" aria-live="polite">
              {report.gates.map(item=>{const status=STATE[item.state];return <div className="antim-gate" key={item.id}>
                <div className={'antim-gate-mark '+status.tone}>{status.mark}</div>
                <div className="antim-gate-copy"><b>{item.label}</b><p>{item.detail}</p></div>
                <div className={'antim-status '+status.tone}>{status.label}</div>
              </div>})}
            </div>
            <div className="antim-metrics">
              <div><span>ACCEPTANCE CHECKS</span><strong>{verifier?'7 / 7':'—'}</strong><small>{verifier?'Claimed passing in receipt':'No verifier receipt'}</small></div>
              <div><span>SOURCE MUTATIONS</span><strong>{verifier?'3 / 3':'—'}</strong><small>{verifier?'Claimed killed by assertions':'No mutation records'}</small></div>
              <div><span>HUMAN RELEASE</span><strong>LOCKED</strong><small>Only private CLI can record review intent</small></div>
            </div>
            {contract&&<div className="antim-binding">
              <div className="inspector-step-label">FROZEN IDENTIFIERS / UNTRUSTED DECLARATIONS</div>
              <dl>
                <div><dt>Stage SHA-256</dt><dd title={contract.stage_sha256}>{cut(contract.stage_sha256)}</dd></div>
                <div><dt>Vault ledger head</dt><dd title={contract.vault_ledger_head}>{cut(contract.vault_ledger_head)}</dd></div>
                <div><dt>Specification SHA-256</dt><dd title={contract.spec_sha256}>{cut(contract.spec_sha256)}</dd></div>
                <div><dt>Source SHA-256</dt><dd title={contract.source_sha256}>{cut(contract.source_sha256)}</dd></div>
              </dl>
            </div>}
          </div>
        </div>
        <div className="antim-bottom">
          <div className="antim-bottom-mark">!</div>
          <div><strong>NO AUTOMATIC DONE. NO AUTOMATIC RELEASE.</strong>
            <p>Matching hashes prove agreement between selected files, not that those files came from a real execution or honest human review. A signed-in operator must run the actual Anti-M CLI against the private Vault to revalidate approval. This public console never requests an HMAC key or verifies identities.</p>
            <a href="https://github.com/MichaelWave369/PhiCleanroom/blob/main/docs/ANTI_M.md" target="_blank" rel="noreferrer">READ THE ANTI-M OPERATOR GUIDE ↗</a>
          </div>
        </div>
      </div>
    </div>
  </section>
}
