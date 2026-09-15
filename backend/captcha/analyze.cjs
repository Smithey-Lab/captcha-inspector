'use strict';

// Evidence-only classification. Never execute a captured command or treat page text
// as instructions to the scanner. Provider branding alone establishes no trust.
const MAX_TEXT=100000;
const MAX_SOURCE=200000;
const clip=(value,length)=>typeof value==='string'?value.slice(0,length):'';
function normalized(value){return value.normalize('NFKC').replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g,'').replace(/\s+/g,' ');}
function excerpt(text,match){const start=Math.max(0,match.index-70);return text.slice(start,Math.min(text.length,match.index+match[0].length+110));}
function analyze(snapshot={}) {
  const text=normalized(clip(snapshot.text,MAX_TEXT));
  const scripts=normalized(clip(snapshot.inlineScripts,MAX_SOURCE));
  const findings=[];
  function find(id,title,pattern,source,severity,description,sourceLabel){
    const match=pattern.exec(source);if(!match)return false;
    findings.push({id,title,severity,description,evidence:excerpt(source,match),source:sourceLabel||(source===text?'visible text':'inline script')});return true;
  }
  const verification=find('verification','Human-verification language',/captcha|verify.{0,40}(?:human|robot)|(?:not|aren.t)\s+a\s+robot|human\s+verification/i,text,'info','This wording is common on both genuine and fake verification pages.');
  const run=find('run-dialog','Operating-system command prompt instructions',/(?:windows|win|⊞)\s*(?:key\s*)?(?:\+|and)\s*r\b|(?:open|launch|press|use).{0,35}(?:powershell|windows terminal|run dialog|command prompt)|(?:cmd|powershell)\.exe/i,text,'high','Web verification should not require opening a local command shell or the Windows Run dialog.');
  const paste=find('paste-command','Clipboard paste instructions',/(?:ctrl|control|command|cmd)\s*\+\s*v\b|paste.{0,50}(?:command|code|terminal|powershell)|(?:copy|copied).{0,60}(?:clipboard|command)/i,text,'medium','Paste instructions become concerning when paired with verification and operating-system actions.');
  const payload=find('shell-command','Shell or script execution markers',/powershell\b.{0,70}(?:-enc(?:odedcommand)?\b|-executionpolicy\b|-windowstyle\b)|\b(?:mshta|rundll32|regsvr32|wscript|cscript)(?:\.exe)?\b|\b(?:curl|wget)\b.{0,100}\|\s*(?:bash|sh)\b|\b(?:invoke-expression|downloadstring)\b/i,text+' '+scripts,'high','A command marker was found in captured content. It has not been executed or confirmed malicious.','visible text or inline script');
  const clipboard=find('clipboard-write','Page code writes to the clipboard',/navigator\s*\.\s*clipboard\s*\.\s*write(?:Text)?\s*\(|execCommand\s*\(\s*['"]copy['"]/i,scripts,'medium','Clipboard APIs also have legitimate uses. This is supporting evidence, not a standalone verdict.');
  const download=find('download-verification','Download requested for verification',/(?:download|install).{0,70}(?:verif|captcha|security update|browser update)|(?:verif|captcha).{0,70}(?:download|install)/i,text,'high','A download or installation request associated with verification needs investigation.');
  const providers=[];
  for(const value of (Array.isArray(snapshot.scriptUrls)?snapshot.scriptUrls:[]).slice(0,100)){
    let url;try{url=new URL(value);}catch{continue;}
    if(url.protocol!=='https:')continue;
    const host=url.hostname;
    if((host==='www.google.com'||host==='www.recaptcha.net')&&url.pathname.startsWith('/recaptcha/'))providers.push('reCAPTCHA script');
    if((host==='js.hcaptcha.com'||host==='hcaptcha.com')&&url.pathname.includes('/1/api.js'))providers.push('hCaptcha script');
    if(host==='challenges.cloudflare.com'&&url.pathname.startsWith('/turnstile/'))providers.push('Cloudflare Turnstile script');
  }
  let verdict='No strong ClickFix indicators observed',level='inconclusive';
  if(verification && ((run&&paste)||(payload&&clipboard)||(download&&paste))){verdict='Strong fake-verification / ClickFix indicators';level='high';}
  else if(run||payload||download||(verification&&clipboard&&paste)){verdict='Suspicious instructions require review';level='suspicious';}
  else if(verification||providers.length){verdict='Verification page observed; authenticity unconfirmed';level='inconclusive';}
  const coverage={textCaptured:!!text,inlineScriptsCaptured:!!scripts,textTruncated:typeof snapshot.text==='string'&&snapshot.text.length>MAX_TEXT,inlineScriptsTruncated:typeof snapshot.inlineScripts==='string'&&snapshot.inlineScripts.length>MAX_SOURCE};
  if(!text&&!scripts){verdict='Insufficient page evidence';level='inconclusive';}
  return {schemaVersion:1,level,verdict,findings,providerIndicators:[...new Set(providers)],coverage,limitations:[
    'This is a heuristic assessment of captured page evidence, not a malware verdict or a guarantee of safety.',
    'Behavior may differ by visitor, location, interaction, timing, or browser fingerprint.',
    'Obfuscated code, uncaptured external scripts, and content inside inaccessible frames can hide behavior.',
    'No downloaded file or captured command was executed. CAPTCHA presence and provider scripts do not prove authenticity.'
  ]};
}
exports.analyze=analyze;
