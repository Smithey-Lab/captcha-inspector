// Passive, bounded observations. Never read field values, message payloads or worker code.
export function documentSignals(){
  const visible=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none';};
  const inputs=Array.from(document.querySelectorAll('input')).slice(0,200).filter(visible);
  const text=(document.body?.innerText||'').slice(0,10000);
  const source=Array.from(document.scripts).filter(s=>!s.src).slice(0,20).map(s=>s.textContent.slice(0,10000)).join('\n').slice(0,50000);
  let workerControlled=false;try{workerControlled=!!navigator.serviceWorker?.controller;}catch{/* Opaque sandbox origins can deny this accessor. */}
  return {scheme:location.protocol,origin:location.origin==='null'?'opaque':location.origin,passwordField:inputs.some(e=>e.type==='password'||/(?:^|\s)(?:current-password|new-password)(?:\s|$)/.test(e.autocomplete)),emailField:inputs.some(e=>e.type==='email'||/(?:^|\s)username(?:\s|$)/.test(e.autocomplete)||/^(?:loginfmt|username|email)$/i.test(e.name)),loginLanguage:/sign\s*in|log\s*in|password|microsoft\s*365|office\s*365/i.test(text),visibleContent:!!text.trim()||inputs.length>0,workerControlled,workerRegistrationCode:/serviceWorker\s*\.\s*register\s*\(/.test(source),blobCreationCode:/createObjectURL\s*\(/.test(source),messagingCode:/postMessage\s*\(/.test(source)};
}
export function addressSummary(value){
  try{const u=new URL(value);return {scheme:u.protocol,origin:u.origin==='null'?'opaque':u.origin};}catch{return {scheme:'unknown',origin:'unknown'};}
}
export function microsoftRedirect(value){
  try{const u=new URL(value);if(u.hostname!=='login.microsoftonline.com'||!/^\/[^/]+\/oauth2\/(?:v2\.0\/)?authorize\/?$/i.test(u.pathname))return null;
    const target=new URL(u.searchParams.get('redirect_uri'));return /^https?:$/.test(target.protocol)?{origin:u.origin,destinationOrigin:target.origin}:null;
  }catch{return null;}
}
export async function collectBrowserEvidence(page,context,target){
  const frames=page.frames(),priority=f=>/^(blob:|data:|about:srcdoc)/.test(f.url());
  const selected=[...frames.slice(0,1),...frames.slice(1).filter(priority),...frames.slice(1).filter(f=>!priority(f))].slice(0,8);
  const documents=await Promise.all(selected.map(async frame=>{
    let timer;
    try{return {...addressSummary(frame.url()),...await Promise.race([frame.evaluate(documentSignals),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('capture timeout')),1500);})]),captured:true};}
    catch{return {...addressSummary(frame.url()),captured:false};}finally{clearTimeout(timer);}
  }));
  const workers=context.serviceWorkers().slice(0,8).map(w=>addressSummary(w.url()));
  return {documents,workers,microsoftRedirect:microsoftRedirect(target),framesSeen:frames.length,framesOmitted:Math.max(0,frames.length-selected.length),framesFailed:documents.filter(d=>!d.captured).length,serviceWorkerBypass:true};
}
export function browserFindings(evidence={}){
  const findings=[],documents=Array.isArray(evidence.documents)?evidence.documents.slice(0,8):[];
  const generated=documents.filter(d=>d.captured&&['blob:','data:','about:'].includes(d.scheme)&&(d.passwordField||(d.emailField&&d.loginLanguage)));
  if(generated.length)findings.push({id:'browser-local-login',title:'Sign-in form inside a browser-generated document',severity:'high',source:'rendered document structure',evidence:generated.map(d=>`${d.scheme} document (${d.origin}); ${d.passwordField?'visible password field':'email field and sign-in language'}`).join('; '),description:'A login form is rendered from browser-local content rather than a normal HTTP page. This matches a technique used in browser-based phishing. Legitimate applications can also do this; do not enter credentials until independently verified.'});
  if(evidence.microsoftRedirect)findings.push({id:'microsoft-oauth-redirect',title:'Microsoft OAuth redirect in submitted address',severity:'info',source:'submitted URL structure',evidence:`${evidence.microsoftRedirect.origin} -> ${evidence.microsoftRedirect.destinationOrigin}`,description:'Microsoft authentication URLs can redirect onward. This is normal OAuth behavior and does not establish that the destination or subsequent page is trustworthy.'});
  const worker=documents.some(d=>d.workerControlled||d.workerRegistrationCode)||(evidence.workers?.length>0);
  if(worker)findings.push({id:'service-worker-evidence',title:'Service-worker evidence observed',severity:'info',source:'browser state or inline script',evidence:'Worker instance, document controller, or registration code observed; registration code alone does not prove execution.',description:'Service workers are used by legitimate applications and can also support phishing workflows. Worker network interception remains bypassed during inspection; this can change page behavior.'});
  if(generated.length&&documents.some(d=>d.messagingCode||d.blobCreationCode))findings.push({id:'browser-local-support',title:'Browser-local rendering or messaging code',severity:'info',source:'inline script syntax',evidence:'createObjectURL or postMessage syntax observed alongside a browser-generated sign-in document.',description:'Supporting evidence only. Message payloads and external scripts were not inspected, and this does not prove command-and-control activity.'});
  return {findings,suspicious:generated.length>0};
}
export function hasLoadedEvidence(snapshot,evidence){
  return (/^(https?:|blob:|data:)/i.test(snapshot.url||'')&&!!snapshot.text?.trim())||evidence.documents.some(d=>d.captured&&d.visibleContent);
}
