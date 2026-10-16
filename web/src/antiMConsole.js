/**
 * Anti-M static public console. Browser-only cross-checks of local, untrusted
 * files. NEVER authenticates a reviewer, verifies a real Vault, executes code,
 * requests an attestation key, marks DONE or releases anything.
 */
export const REQUIREMENTS = Object.freeze({
  checks: ['exact_title', 'description_exclusion', 'substring_exclusion',
           'no_match', 'case_sensitive', 'duplicate_titles', 'missing_title'],
  mutants: ['always_empty', 'always_all', 'substring_title'],
})
export const SLOTS = Object.freeze([
  { key: 'contract', title: 'Completion contract', name: 'completion-contract.json', max: 32 * 1024 },
  { key: 'builder', title: 'Builder receipt', name: 'builder-receipt.json', max: 32 * 1024 },
  { key: 'verifier', title: 'Independent verifier receipt', name: 'verifier-receipt.json', max: 32 * 1024 },
  { key: 'source', title: 'Quarantined source file', name: 'search.py', max: 16 * 1024 },
])
const HEX = /^[a-f0-9]{64}$/
const IMAGE = /^sha256:[a-f0-9]{64}$/
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const isHash = value => typeof value === 'string' && HEX.test(value)
const ownKeys = (value, fields) => isObject(value) && Object.keys(value).length === fields.length && fields.every(key => Object.prototype.hasOwnProperty.call(value,key))
const arrayEqual = (x,y) => Array.isArray(x) && x.length === y.length && x.every((v,i)=>v===y[i])
const required = (condition, what) => { if (!condition) throw new Error(what) }
const decoder = new TextDecoder('utf-8', { fatal:true })

function hex(digest) {
  return [...new Uint8Array(digest)].map(n=>n.toString(16).padStart(2,'0')).join('')
}
export async function shaBytes(bytes, subtle = globalThis.crypto?.subtle) {
  if (!subtle?.digest) throw new Error('SHA-256 unavailable: use HTTPS and a modern browser.')
  return hex(await subtle.digest('SHA-256', bytes))
}
export async function shaText(text, subtle = globalThis.crypto?.subtle) {
  return shaBytes(new TextEncoder().encode(text), subtle)
}

/* Reject duplicate JSON object names, including nested names, before JSON.parse.
   This lexer only identifies JSON strings and delimiters; JSON.parse validates syntax. */
export function rejectDuplicateNames(text) {
  const frames=[]
  let i=0
  const whitespace=()=>{while(i<text.length && /[\t\n\r ]/.test(text[i]))i++}
  while(i<text.length){
    whitespace()
    const char=text[i]
    if(char==='"'){
      const start=i++
      let escaped=false
      while(i<text.length){
        const c=text[i++]
        if(escaped){escaped=false;continue}
        if(c==='\\'){escaped=true;continue}
        if(c==='"')break
      }
      const parent=frames[frames.length-1]
      if(parent?.type==='object' && parent.wantKey){
        whitespace()
        if(text[i]===':'){
          const key=JSON.parse(text.slice(start,i).trim())
          if(parent.keys.has(key))throw new Error('Duplicate JSON field: '+key.slice(0,80))
          parent.keys.add(key)
          parent.wantKey=false
        }
      }
      continue
    }
    if(char==='{')frames.push({type:'object',wantKey:true,keys:new Set()})
    else if(char==='[')frames.push({type:'array'})
    else if(char==='}'||char===']')frames.pop()
    else if(char===','){
      const parent=frames[frames.length-1]
      if(parent?.type==='object')parent.wantKey=true
    }
    i++
  }
}

export function validateDocument(slot, doc) {
  if(slot==='contract'){
    const fields=['schema_version','kind','scope','stage_sha256','spec_sha256','source_sha256',
      'vault_ledger_head','builder_receipt_sha256','verifier_receipt_sha256','builder_image_id',
      'verifier_image_id','required_checks','required_mutants','requires_human_release']
    required(ownKeys(doc,fields),'Completion contract has missing or unknown fields.')
    required(doc.schema_version===1 && doc.kind==='ANTI_M_COMPLETION_CONTRACT_V1' &&
      doc.scope==='reference-exact-title-v1','Unsupported Anti-M contract version or scope.')
    for(const key of fields.filter(name=>name.endsWith('sha256')||name==='vault_ledger_head')){
      required(isHash(doc[key]),'Malformed contract digest: '+key)
    }
    required(IMAGE.test(doc.builder_image_id)&&IMAGE.test(doc.verifier_image_id),'Unpinned worker image in contract.')
    required(doc.builder_image_id!==doc.verifier_image_id,'Builder and verifier image IDs must differ.')
    required(arrayEqual(doc.required_checks,REQUIREMENTS.checks) &&
      arrayEqual(doc.required_mutants,REQUIREMENTS.mutants),'Completion contract omits required checks or mutants.')
    required(doc.requires_human_release===true,'Human release requirement is mandatory.')
    return
  }
  if(slot==='builder'){
    const fields=['schema_version','kind','status','stage_sha256','spec_sha256','image_id',
      'authority','builder','container_policy','artifacts','note']
    required(ownKeys(doc,fields),'Builder receipt has missing or unknown fields.')
    required(doc.schema_version===1&&doc.kind==='INDEPENDENT_BUILDER_RECEIPT'&&
      doc.status==='QUARANTINED_UNVERIFIED'&&doc.authority==='NONE'&&
      doc.builder==='reference-exact-title-v1','Unrecognized builder receipt or forged authority.')
    required(isHash(doc.stage_sha256)&&isHash(doc.spec_sha256)&&IMAGE.test(doc.image_id),
      'Builder receipt digests/image malformed.')
    required(Array.isArray(doc.artifacts)&&doc.artifacts.length===1&&
      ownKeys(doc.artifacts[0],['path','sha256'])&&doc.artifacts[0].path==='search.py'&&
      isHash(doc.artifacts[0].sha256),'Builder receipt must refer to one hashed search.py.')
    const p=doc.container_policy
    required(isObject(p)&&p.network==='none'&&p.root_filesystem==='read-only'&&
      p.capabilities==='drop ALL'&&p.no_new_privileges===true&&
      p.docker_socket_mounted===false&&p.uid_gid==='65532:65532',
      'Declared builder container policy fails minimum restrictions.')
    required(typeof doc.note==='string','Builder receipt note missing.')
    return
  }
  if(slot==='verifier'){
    const fields=['schema_version','kind','stage_sha256','spec_sha256','source_sha256',
      'verifier_image_id','suite','status','authority','checks','mutants','note']
    required(ownKeys(doc,fields),'Verifier receipt has missing or unknown fields.')
    required(doc.schema_version===1&&doc.kind==='INDEPENDENT_VERIFICATION_RECEIPT'&&
      doc.status==='REFERENCE_CHECKS_PASS'&&doc.authority==='NONE'&&
      doc.suite==='reference-exact-title-acceptance-v1','Unrecognized verifier suite, status or authority.')
    required([doc.stage_sha256,doc.spec_sha256,doc.source_sha256].every(isHash)&&
      IMAGE.test(doc.verifier_image_id),'Verifier digests or image ID malformed.')
    required(Array.isArray(doc.checks)&&doc.checks.length===REQUIREMENTS.checks.length&&
      doc.checks.every((item,index)=>ownKeys(item,['id','status'])&&
        item.id===REQUIREMENTS.checks[index]&&item.status==='PASS'),
      'Verifier receipt is missing a required passing acceptance check.')
    const seen=new Set()
    required(Array.isArray(doc.mutants)&&doc.mutants.length===REQUIREMENTS.mutants.length&&
      doc.mutants.every((item,index)=>{
        if(!ownKeys(item,['id','status','source_sha256','failed_check'])||
           item.id!==REQUIREMENTS.mutants[index]||item.status!=='KILLED_ASSERTION'||
           !isHash(item.source_sha256)||item.source_sha256===doc.source_sha256||
           seen.has(item.source_sha256)||!REQUIREMENTS.checks.includes(item.failed_check))return false
        seen.add(item.source_sha256)
        return true
      }), 'Verifier receipt lacks three unique assertion-killed source mutations.')
    required(typeof doc.note==='string','Verifier receipt note missing.')
    return
  }
  throw new Error('Unknown document type.')
}

/** One local file from one slot, hashed and parsed but never stored or uploaded. */
export async function readSlot(slot, file, subtle = globalThis.crypto?.subtle) {
  const item=SLOTS.find(entry=>entry.key===slot)
  required(item, 'Unknown input slot.')
  required(file && Number.isSafeInteger(file.size) && file.size>0 &&
    file.size<=item.max,'File must be nonempty and at most '+(item.max/1024)+' KiB.')
  const bytes=await file.arrayBuffer()
  required(bytes.byteLength<=item.max,'Oversize file payload.')
  const digest=await shaBytes(bytes,subtle)
  const text=decoder.decode(bytes)
  if(slot==='source')return { slot, name:file.name.slice(0,120),sha256:digest,size:bytes.byteLength }
  rejectDuplicateNames(text)
  let doc
  try{doc=JSON.parse(text)}catch{throw new Error('Invalid JSON file.')}
  validateDocument(slot,doc)
  return {slot,name:file.name.slice(0,120),sha256:digest,size:bytes.byteLength,doc}
}

function gate(id,label,state,detail){
  return {id,label,state,detail}
}
export function evaluateCompletion(files) {
  const c=files.contract?.doc, b=files.builder?.doc, v=files.verifier?.doc
  const s=files.source
  const gates=[]
  gates.push(gate('contract','Frozen Anti-M contract',c?'MATCH':'MISSING',
    c?'Recognized v1 schema, pinned reference checks and human-release requirement.':'Load the frozen completion-contract.json.'))
  gates.push(gate('builder','Builder receipt file bytes',!c||!b?'MISSING':
    c.builder_receipt_sha256===files.builder.sha256?'MATCH':'MISMATCH',
    !c||!b?'Load the actual builder receipt.':'SHA-256 must match the contract, not just the JSON fields.'))
  gates.push(gate('verifier','Verifier receipt file bytes',!c||!v?'MISSING':
    c.verifier_receipt_sha256===files.verifier.sha256?'MATCH':'MISMATCH',
    !c||!v?'Load the actual independent verifier receipt.':'SHA-256 must match the contract.'))
  gates.push(gate('source','Quarantined source file bytes',!c||!s?'MISSING':
    c.source_sha256===s.sha256?'MATCH':'MISMATCH',
    !c||!s?'Load quarantined search.py (never executed).':'The exact bytes are hashed locally; no source is executed.'))
  const bound=!!(c&&b&&v)
  const aligned=bound &&
    c.stage_sha256===b.stage_sha256&&b.stage_sha256===v.stage_sha256&&
    c.spec_sha256===b.spec_sha256&&b.spec_sha256===v.spec_sha256&&
    c.source_sha256===b.artifacts[0].sha256&&b.artifacts[0].sha256===v.source_sha256&&
    c.builder_image_id===b.image_id&&c.verifier_image_id===v.verifier_image_id&&
    c.builder_image_id!==c.verifier_image_id
  gates.push(gate('lineage','Stage, spec and image lineage',bound?(aligned?'MATCH':'MISMATCH'):'MISSING',
    'All three documents must agree about the frozen stage, specification, source and distinct image IDs.'))
  gates.push(gate('checks','Seven acceptance checks',v?'MATCH':'MISSING',
    v?'7/7 declared PASS in the selected receipt. Not independently rerun by this website.':'Select the verifier receipt.'))
  gates.push(gate('mutants','Three source-level mutants',v?'MATCH':'MISSING',
    v?'3/3 declared KILLED_ASSERTION with unique recorded mutation digests. Not independently rerun.':'Select the verifier receipt.'))
  gates.push(gate('vault','Live Vault ledger and reviewer identity','NOT_CHECKED',
    'Public GitHub Pages cannot revalidate private Vault history, source provenance, local key possession or real human identity.'))
  const failures=gates.filter(x=>x.state==='MISMATCH').length
  const missing=gates.filter(x=>x.state==='MISSING').length
  const linksMatch=failures===0 && missing===0
  return {gates,matched:gates.filter(x=>x.state==='MATCH').length,
    linksMatch,failures,missing,
    headline:failures?'LOCAL EVIDENCE MISMATCH':
      missing?'AWAITING COMPLETE EVIDENCE':'LOCAL FILE LINKS MATCH',
    detail:linksMatch?
      'Selected bytes and recorded links agree. This is not a Vault verification, human approval, DONE, or a release permission.':
      'The browser cannot establish the local chain until all required files are present and consistent.'}
}

/** A fully synthetic sample; built from ordinary strings, not a real Vault. */
export async function syntheticCompletion(subtle = globalThis.crypto?.subtle){
  const stage='a'.repeat(64),spec='b'.repeat(64),ledger='c'.repeat(64)
  const image='sha256:'+'d'.repeat(64),other='sha256:'+'e'.repeat(64)
  const source='def search(items, query):\n    return [item for item in items if item.get("title") == query]\n'
  const sourceSha=await shaText(source,subtle)
  const builder={
    schema_version:1,kind:'INDEPENDENT_BUILDER_RECEIPT',status:'QUARANTINED_UNVERIFIED',
    stage_sha256:stage,spec_sha256:spec,image_id:image,authority:'NONE',
    builder:'reference-exact-title-v1',
    container_policy:{network:'none',root_filesystem:'read-only',capabilities:'drop ALL',
      no_new_privileges:true,uid_gid:'65532:65532',docker_socket_mounted:false},
    artifacts:[{path:'search.py',sha256:sourceSha}],note:'SYNTHETIC browser sample. NOT a real Docker run.',
  }
  const verifier={
    schema_version:1,kind:'INDEPENDENT_VERIFICATION_RECEIPT',
    stage_sha256:stage,spec_sha256:spec,source_sha256:sourceSha,
    verifier_image_id:other,suite:'reference-exact-title-acceptance-v1',
    status:'REFERENCE_CHECKS_PASS',authority:'NONE',
    checks:REQUIREMENTS.checks.map(id=>({id,status:'PASS'})),
    mutants:REQUIREMENTS.mutants.map((id,i)=>({
      id,status:'KILLED_ASSERTION',source_sha256:(i+1).toString().repeat(64),
      failed_check:'exact_title'
    })),
    note:'SYNTHETIC demo outcomes, not executed tests.',
  }
  const bText=JSON.stringify(builder,null,2)+'\n',vText=JSON.stringify(verifier,null,2)+'\n'
  const contract={
    schema_version:1,kind:'ANTI_M_COMPLETION_CONTRACT_V1',scope:'reference-exact-title-v1',
    stage_sha256:stage,spec_sha256:spec,source_sha256:sourceSha,
    vault_ledger_head:ledger,
    builder_receipt_sha256:await shaText(bText,subtle),
    verifier_receipt_sha256:await shaText(vText,subtle),
    builder_image_id:image,verifier_image_id:other,
    required_checks:[...REQUIREMENTS.checks],required_mutants:[...REQUIREMENTS.mutants],
    requires_human_release:true,
  }
  for(const [slot,doc] of [['contract',contract],['builder',builder],['verifier',verifier]])validateDocument(slot,doc)
  return {
    contract:{slot:'contract',doc:contract,name:'synthetic-completion-contract.json',
      sha256:await shaText(JSON.stringify(contract,null,2)+'\n',subtle)},
    builder:{slot:'builder',doc:builder,name:'synthetic-builder-receipt.json',
      sha256:await shaText(bText,subtle)},
    verifier:{slot:'verifier',doc:verifier,name:'synthetic-verifier-receipt.json',
      sha256:await shaText(vText,subtle)},
    source:{slot:'source',name:'synthetic-search.py',sha256:sourceSha,size:new TextEncoder().encode(source).length},
  }
}
