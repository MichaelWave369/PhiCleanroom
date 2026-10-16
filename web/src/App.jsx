import React, { useMemo, useState } from 'react'
import { CONTROL_FIELDS, INITIAL_CHECKS, evaluateDemo } from './demoGate.js'

const REPO = 'https://github.com/MichaelWave369/PhiCleanroom'

const stages = [
  { number: '01', name: 'Observe', eyebrow: 'INVESTIGATOR', status: 'CURRENT / MANUAL',
    headline: 'Investigate behavior, not implementation.',
    description: 'Start with an owned or authorized target. Record what a feature does, which environment produced the result, and what evidence actually demonstrates the rule.',
    proof: 'Authorized scope · observation notes · pinned snapshot manifest' },
  { number: '02', name: 'Verify', eyebrow: 'EVIDENCE VAULT', status: 'CURRENT / CLI',
    headline: 'Keep the artifact. Check the bytes.',
    description: 'The Evidence Vault stores content-addressed artifacts, checks their SHA-256 digests, and binds each proposed behavior to a frozen candidate version.',
    proof: 'Stored artifacts · SHA-256 verification · frozen candidate digest' },
  { number: '03', name: 'Review', eyebrow: 'HUMAN JUDGMENT', status: 'CURRENT / CLI',
    headline: 'Approval is specific, recorded and reversible.',
    description: 'A reviewer evaluates each rule against the real evidence. Approve, return, or reject. A changed candidate needs a new approval; a later return blocks export.',
    proof: 'Per-rule decision · hash-linked local ledger · explicit review' },
  { number: '04', name: 'Separate', eyebrow: 'SPECIFICATION BOUNDARY', status: 'PARTIAL / CLI',
    headline: 'The builder packet contains only the contract.',
    description: 'An approved candidate can export a behavior-only SPEC.md. Actual process isolation must be provisioned separately so the builder cannot access the original.',
    proof: 'SPEC.md only · no evidence artifacts · OS isolation still planned' },
  { number: '05', name: 'Challenge', eyebrow: 'INDEPENDENT TESTING', status: 'ROADMAP',
    headline: 'Try to prove the implementation wrong.',
    description: 'The planned verification runner will bind tests to a code snapshot, check required behaviors and deliberately injected faults, and treat unknowns as blockers.',
    proof: 'Acceptance tests · genuine code mutations · fresh test receipts' },
  { number: '06', name: 'Release', eyebrow: 'ANTI-M GOVERNANCE', status: 'ROADMAP',
    headline: 'A green test is not permission to ship.',
    description: 'Anti-M will require validated completion evidence, a bounded repair history, and explicit human release approval before marking the work DONE.',
    proof: 'Traceable completion · human sign-off · auditable release receipt' },
]

const capabilityCards = [
  { mark: 'LIVE / CORE', title: 'Evidence Vault v2', desc: 'Local SHA-256 object storage, frozen candidate records and re-verification of stored evidence.', id: 'CAP-01' },
  { mark: 'LIVE / CORE', title: 'Review Ledger', desc: 'Per-rule approve, return and reject events, linked to exact candidate digests.', id: 'CAP-02' },
  { mark: 'LIVE / CORE', title: 'Spec-only Export', desc: 'A behavior-only builder packet, with a separately stored audit receipt.', id: 'CAP-03' },
  { mark: 'NEXT / PLANNED', title: 'Worker Adapters', desc: 'Provider-neutral investigation, judging and building interfaces, with controlled access.', id: 'CAP-04' },
  { mark: 'NEXT / PLANNED', title: 'Isolation & Mutation', desc: 'Separate execution boundaries and independently verifiable fault-injection tests.', id: 'CAP-05' },
  { mark: 'NEXT / PLANNED', title: 'Anti-M Release', desc: 'Signed completion criteria, verified test coverage and explicit human ship authorization.', id: 'CAP-06' },
]

function ArrowIcon({ diagonal = false, size = 18 }) {
  return diagonal
    ? <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M7 17 17 7M8 7h9v9" /></svg>
    : <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d="M4 12h16m-7-7 7 7-7 7" /></svg>
}
function Mark({ small = false }) {
  return <span className={'brand-mark ' + (small ? 'brand-mark-small' : '')} aria-hidden="true">Φ</span>
}
function SectionHeading({ id, number, overline, title, description }) {
  return <div className="section-header" id={id}>
    <div className="section-index"><span>{number}</span><span className="section-index-rule" />{overline}</div>
    <h2 id={id + '-title'}>{title}</h2>
    {description && <p>{description}</p>}
  </div>
}
function VisualStation() {
  return <div className="visual-station" aria-label="Illustrated clean-room separation from investigator through evidence gate to independent builder" role="img">
    <div className="station-label station-label-top"><span className="spark-dot" /> SEPARATION PROTOCOL <span>V / 0.2</span></div>
    <div className="orbit orbit-one" />
    <div className="orbit orbit-two" />
    <div className="orbit orbit-three" />
    <div className="orbit orbit-four" />
    <div className="orbital-grid" />
    <div className="station-nucleus"><div className="nucleus-inner">Φ</div></div>
    <div className="orbit-node orbit-node-a" />
    <div className="orbit-node orbit-node-b" />
    <div className="orbit-node orbit-node-c" />
    <div className="station-readout readout-left"><small>INPUT / 01</small><b>OBSERVED</b><span>Authorized behavior</span></div>
    <div className="station-readout readout-right"><small>OUTPUT / 04</small><b>INDEPENDENT</b><span>Spec-only rebuild</span></div>
    <div className="station-core-line" />
    <div className="station-bottom"><span>RESEARCH</span><span className="dash-line" /><span>GATE</span><span className="dash-line" /><span>BUILD</span></div>
    <div className="station-foot">NO DIRECT SOURCE TRANSFER <span>◈</span> NO AUTOMATIC RELEASE</div>
  </div>
}
function Hero() {
  return <section className="hero section-shell" id="top">
    <div className="hero-copy">
      <div className="micro-tag"><span className="micro-light" /> OPEN SOURCE / EVIDENCE-GOVERNED ENGINEERING</div>
      <h1>Original code.<br /><em>Proven behavior.</em></h1>
      <p className="hero-lede">A clean-room engineering workflow that separates investigation from implementation. Every rule needs evidence. Every approval leaves a record. Every release stays human-governed.</p>
      <div className="hero-actions">
        <a className="button button-primary" href="#pipeline">Explore the protocol <ArrowIcon /></a>
        <a className="button button-quiet" href={REPO} target="_blank" rel="noreferrer">View source <ArrowIcon diagonal size={16} /></a>
      </div>
      <div className="hero-meta">
        <div><span className="meta-key">FOUNDATION</span><strong>Evidence Vault v2</strong></div>
        <span className="meta-divider" />
        <div><span className="meta-key">MODEL POLICY</span><strong>Provider neutral</strong></div>
        <span className="meta-divider" />
        <div><span className="meta-key">RELEASE POLICY</span><strong>Human authority</strong></div>
      </div>
    </div>
    <VisualStation />
  </section>
}
function Pipeline() {
  const [active, setActive] = useState(1)
  const stage = stages[active]
  return <section className="page-section" aria-labelledby="pipeline-title">
    <div className="section-shell">
      <SectionHeading id="pipeline" number="01" overline="THE SYSTEM" title="Six disciplines. One clean boundary." description="The investigator describes reality. The reviewer approves the contract. The builder never needs the original. Implemented stages and future stages are labeled separately." />
      <div className="pipeline-wrap">
        <div className="pipeline-rail" aria-label="Explore six stages of the proposed clean-room workflow">
          {stages.map((item, idx) => <button type="button" key={item.number} className={'pipeline-step ' + (active === idx ? 'selected' : '')} onClick={() => setActive(idx)} aria-pressed={active === idx}>
            <span className="pipeline-number">{item.number}</span>
            <span className="pipeline-name">{item.name}</span>
            <span className={'pipeline-mini-state ' + (item.status.includes('ROADMAP') ? 'planned' : '')} />
          </button>)}
        </div>
        <div className="pipeline-detail" aria-live="polite">
          <div className="detail-topline"><span>{stage.eyebrow}</span><span className={'tiny-status ' + (stage.status.includes('ROADMAP') ? 'tiny-roadmap' : '')}>{stage.status}</span></div>
          <div className="detail-grid">
            <div><div className="detail-numeral">{stage.number}<span>/06</span></div><h3>{stage.headline}</h3><p>{stage.description}</p></div>
            <div className="detail-graphic"><div className="detail-graphic-ring"><span>{stage.number}</span></div><div className="detail-graphic-caption">GATED / STAGE {stage.number}</div></div>
          </div>
          <div className="detail-bottom"><span>ACCEPTANCE MATERIAL</span><strong>{stage.proof}</strong></div>
        </div>
      </div>
    </div>
  </section>
}
function Lab() {
  const [checks, setChecks] = useState({ ...INITIAL_CHECKS })
  const [tab, setTab] = useState('spec')
  const assessment = useMemo(() => evaluateDemo(checks), [checks])
  const specExample = [
    '# APPROVED BEHAVIORAL SPECIFICATION',
    '',
    'Feature: Example title search',
    '',
    '## R1',
    '',
    'A title query returns matching items.',
    '',
    'Original source code is not included.',
  ].join('\n')
  const receiptExample = [
    '{',
    '  "mode": "SIMULATED_DEMO",',
    '  "decision": "' + (assessment.canExport ? 'eligible' : 'blocked') + '",',
    '  "rules": 1,',
    '  "controls_passed": ' + assessment.reviewed + ',',
    '  "source_shared": false',
    '}',
  ].join('\n')
  return <section className="page-section lab-section" aria-labelledby="lab-title">
    <div className="section-shell">
      <SectionHeading id="lab" number="02" overline="INTERACTIVE EXHIBIT" title="The evidence gate, in miniature." description="Flip the conditions and watch the simulated decision change. This browser exhibit neither examines evidence nor authenticates a reviewer. Real verification happens in the local Python vault." />
      <div className="lab-panel">
        <div className="lab-topbar"><div className="lab-dots"><i /><i /><i /></div><span>PHICLEANROOM / GATE EXPLORER</span><span className="lab-demo-label">SIMULATED INPUTS</span></div>
        <div className="lab-columns">
          <div className="lab-controls">
            <div className="lab-heading"><span>01 / CONDITIONS</span><button type="button" className="reset-button" onClick={() => setChecks({ ...INITIAL_CHECKS })}>Reset simulation ↺</button></div>
            <p>Toggle each fictional condition. Every control must pass before this teaching example permits a specification export.</p>
            <div className="check-stack">
              {CONTROL_FIELDS.map((item, index) => <button type="button" key={item.key} role="switch" aria-checked={checks[item.key]} className={'check-row ' + (checks[item.key] ? 'is-on' : '')} onClick={() => setChecks(current => ({...current, [item.key]: !current[item.key]}))}>
                <span className="check-index">0{index + 1}</span><span className="check-copy"><b>{item.title}</b><small>{item.detail}</small></span><span className="switch-track"><span className="switch-thumb" /></span>
              </button>)}
            </div>
            <div className="lab-note"><span>ⓘ</span> Model confidence is never proof. A declared VERIFIED label also requires real inspection outside this demo.</div>
          </div>
          <div className="lab-output">
            <div className="lab-heading"><span>02 / DECISION</span><span>SIMULATOR v0.1</span></div>
            <div className={'gate-status ' + (assessment.canExport ? 'gate-clear' : 'gate-denied')}>
              <div className="gate-icon">{assessment.canExport ? '✓' : '×'}</div>
              <div><span>DETERMINISTIC DEMO RESULT</span><h3>{assessment.state}</h3><p>{assessment.canExport ? 'All four fictional conditions were toggled on. No real approval has occurred.' : assessment.missing.length + ' condition(s) require attention before this simulated packet can proceed.'}</p></div>
            </div>
            <div className="gate-progress"><span>CONDITIONS SATISFIED</span><b>{assessment.reviewed} / {assessment.total}</b></div>
            <div className="progress-track"><div style={{width: (assessment.reviewed / assessment.total * 100) + '%'}} /></div>
            <div className="output-window">
              <div className="output-tabs">
                <button type="button" className={tab === 'spec' ? 'active' : ''} aria-pressed={tab === 'spec'} onClick={() => setTab('spec')}>SPEC.md</button>
                <button type="button" className={tab === 'receipt' ? 'active' : ''} aria-pressed={tab === 'receipt'} onClick={() => setTab('receipt')}>demo-receipt.json</button>
                <span>READ ONLY</span>
              </div>
              {tab === 'spec' && !assessment.canExport
                ? <div className="blocked-preview"><span>⛔</span><b>SPEC LOCKED</b><p>Behavior-only packet unavailable until all simulated conditions pass.</p></div>
                : <pre className="code-preview">{tab === 'spec' ? specExample : receiptExample}</pre>}
            </div>
            <div className="lab-final-note"><span className="status-indicator" /> BROWSER-ONLY SIMULATION. NO DATA SENT. NOT A SECURITY AUDIT.</div>
          </div>
        </div>
      </div>
    </div>
  </section>
}
function Standards() {
  return <section className="page-section" aria-labelledby="standards-title">
    <div className="section-shell">
      <SectionHeading id="standards" number="03" overline="DESIGN PRINCIPLES" title="A proof chain, not a promise." description="Clean-room design is a governance method. Its value comes from verifiable boundaries and narrow claims, not from the number of agents in the room." />
      <div className="standards-grid">
        <article className="standard-card"><span className="standard-glyph">01 /</span><h3>Ledger above ego.</h3><p>A worker's “done” message is a claim. Verified checks, pinned inputs, and human decisions determine the actual state.</p><span className="standard-foot">PROVENANCE OVER CONFIDENCE</span></article>
        <article className="standard-card"><span className="standard-glyph">02 /</span><h3>Information minimization.</h3><p>Only approved behavioral rules cross into the builder packet. Evidence and investigator traces stay on their side of the boundary.</p><span className="standard-foot">BEHAVIOR WITHOUT SOURCE</span></article>
        <article className="standard-card"><span className="standard-glyph">03 /</span><h3>Unknown means stop.</h3><p>Missing, stale, contradictory, or unverified evidence never silently becomes acceptance. Ambiguity returns to review.</p><span className="standard-foot">FAIL CLOSED BY DESIGN</span></article>
        <article className="standard-card"><span className="standard-glyph">04 /</span><h3>Humans own release.</h3><p>No automated judgment can stand in for legal authorization, semantic review, secure isolation, or permission to publish.</p><span className="standard-foot">AUTHORITY IS EXPLICIT</span></article>
      </div>
      <div className="caution-bar"><span className="caution-symbol">!</span><p><b>Important boundary:</b> A clean-room workflow does not itself resolve copyright, patents, licenses, contracts, or trade secrets. Inspect authorized targets only; source access control and review integrity must be enforced outside the browser.</p></div>
    </div>
  </section>
}
function Roadmap() {
  return <section className="page-section roadmap-section" aria-labelledby="roadmap-title">
    <div className="section-shell">
      <SectionHeading id="roadmap" number="04" overline="IMPLEMENTATION STATUS" title="Built honestly. Shipped deliberately." description="Current repository capabilities are kept separate from upcoming integrations. No pretend deployment, no fictional autonomous engineer." />
      <div className="capability-grid">
        {capabilityCards.map((card, idx) => <article key={card.id} className={'capability-card ' + (idx > 2 ? 'capability-planned' : '')}>
          <div className="capability-top"><span className="capability-id">{card.id}</span><span className={'capability-badge ' + (idx > 2 ? 'is-planned' : '')}>{card.mark}</span></div>
          <h3>{card.title}</h3><p>{card.desc}</p>
          <div className="capability-bottom"><span>{idx <= 2 ? 'CORE / AVAILABLE' : 'ROADMAP / UNBUILT'}</span><ArrowIcon diagonal size={15} /></div>
        </article>)}
      </div>
      <div className="roadmap-actions"><div><span className="mono-mini">OPEN THE SOURCE</span><h3>Inspect the system yourself.</h3><p>Python library, unit tests, CLI docs and GitHub Actions history are public. The browser exhibit is not the evidence engine.</p></div><div className="roadmap-links"><a className="button button-primary" target="_blank" rel="noreferrer" href={REPO}>Repository <ArrowIcon diagonal /></a><a className="button button-quiet" target="_blank" rel="noreferrer" href={REPO + '/blob/main/docs/VAULT.md'}>Vault guide <ArrowIcon diagonal size={16} /></a></div></div>
    </div>
  </section>
}
function Footer() {
  return <footer className="site-footer"><div className="section-shell footer-wrap"><div className="footer-brand"><Mark small /><div><strong>PhiCleanroom</strong><span>Evidence before implementation.</span></div></div><div className="footer-center">LEDGER ABOVE EGO <span className="footer-diamond">◆</span> BUILT FOR INDEPENDENT WORK</div><a href={REPO} target="_blank" rel="noreferrer">SOURCE ON GITHUB <ArrowIcon diagonal size={16}/></a></div></footer>
}
export default function App() {
  const [menuOpen, setMenuOpen] = useState(false)
  return <div className="app">
    <header className="site-header"><div className="section-shell header-wrap"><a className="brand" href="#top" aria-label="PhiCleanroom homepage" onClick={() => setMenuOpen(false)}><Mark /><span className="brand-text"><strong>PHI<span>CLEANROOM</span></strong><small>ENGINEERING THE EVIDENCE</small></span></a>
      <nav id="site-navigation" className={'nav-links ' + (menuOpen ? 'is-open' : '')} aria-label="Main navigation">
        {[['Pipeline','#pipeline'],['Evidence Lab','#lab'],['Principles','#standards'],['Roadmap','#roadmap']].map(([label,href]) => <a key={href} onClick={() => setMenuOpen(false)} href={href}>{label}</a>)}
      </nav>
      <div className="header-actions"><a className="header-source" href={REPO} target="_blank" rel="noreferrer">GITHUB <ArrowIcon diagonal size={15} /></a><button type="button" className="mobile-menu" aria-controls="site-navigation" aria-expanded={menuOpen} aria-label={menuOpen ? 'Close navigation' : 'Open navigation'} onClick={() => setMenuOpen(!menuOpen)}>{menuOpen ? '✕' : '☰'}</button></div></div></header>
    <main><Hero /><div className="rule-wide" /><Pipeline /><Lab /><Standards /><Roadmap /></main>
    <Footer />
  </div>
}
