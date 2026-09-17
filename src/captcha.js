import {installViewerProtection,hostChange,readableReport} from './captcha-protection.js';
import {inputReadiness,viewerAssetBase} from './captcha-input.js';
import {createCaptureHistory,describeAge,MAX_REPORTS} from './captcha-history.js';
const $=id=>document.getElementById(id);
let endpoint='',token='',endsAt=0,captures=0,report=null,connection=null,clock=null,busy=false,opening=false,liveUrl='',generation=0,nextCapture=0,viewOnly=false,connecting=false,starting=false;
const history=createCaptureHistory();
const historyPanel=document.createElement('div');
const status=(text,error=false)=>{$('sandbox-status').textContent=text;$('sandbox-status').dataset.state=error?'error':'ready';};
const viewStatus=(text)=>{$('sandbox-view-status').textContent=text;};
const element=(tag,text)=>{const item=document.createElement(tag);item.textContent=text;return item;};
function active(){return !!token&&Date.now()<endsAt*1000;}
function controls(){const live=active();$('sandbox-start').disabled=busy||opening||starting||live||!endpoint;$('sandbox-capture').disabled=busy||opening||starting||connecting||!live||captures>=3||Date.now()<nextCapture;$('sandbox-stop').disabled=!live&&!token;$('sandbox-open').disabled=busy||opening||starting||connecting||!live;$('sandbox-reconnect').disabled=busy||opening||starting||connecting||!live;const full=$('sandbox-fullscreen');if(full)full.disabled=opening||starting;}
function fit(){const frame=$('sandbox-viewport'),display=$('sandbox-display');const scale=Math.min(frame.clientWidth/1280,Math.max(180,window.innerHeight-210)/800,1);frame.style.height=`${800*scale}px`;display.style.transform=`scale(${scale})`;display.style.left=`${Math.max(0,(frame.clientWidth-1280*scale)/2)}px`;}
new ResizeObserver(fit).observe($('sandbox-viewport'));window.addEventListener('resize',fit);
installViewerProtection({root:$('sandbox-viewport'),notice:text=>{$('sandbox-protection-status').textContent=text;},isViewOnly:()=>viewOnly});
$('sandbox-view-only').addEventListener('change',event=>{viewOnly=event.target.checked;$('sandbox-input-shield').hidden=!viewOnly;$('sandbox-protection-status').textContent=viewOnly?'View-only mode. The remote page and session timer continue running.':'Interactive mode. Clipboard sharing and file transfer remain disabled.';});
async function request(body){const response=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(31000),cache:'no-store'});let data;try{data=await response.json();}catch{throw new Error('The service could not respond. Any started browser still expires automatically.');}if(!response.ok)throw new Error(data.message||'The service is temporarily unavailable.');return data;}
function renderReport(value){$('sandbox-host-change').hidden=!hostChange(value.requestedUrl,value.url);const change=hostChange(value.requestedUrl,value.url);$('sandbox-host-change').textContent=change?`Different host at capture: ${change.from} to ${change.to}. This can be a redirect or navigation; it does not establish whether the page is safe.`:'';$('sandbox-results').hidden=false;$('sandbox-verdict').textContent=value.verdict;$('sandbox-verdict').dataset.level=value.level;$('sandbox-report-meta').textContent=`Requested: ${value.requestedUrl||''} | Viewed: ${value.url||''} | HTTP ${value.httpStatus??'unknown'} | ${value.title||'Untitled page'}`;const list=$('sandbox-findings');list.replaceChildren();for(const finding of value.findings||[]){const card=element('article','');card.className='checker-result-card';card.append(element('h3',finding.title),element('p',finding.description),element('p',`Evidence source: ${finding.source}`),element('blockquote',finding.evidence));list.append(card);}if(!list.children.length)list.append(element('p','No matching indicators in the captured evidence. This does not establish safety.'));const notes=$('sandbox-limitations');notes.replaceChildren(element('h3','Coverage and limitations'));notes.append(element('p',`Provider indicators: ${(value.providerIndicators||[]).join(', ')||'None observed'}. Frames on page: ${value.frameCount??'unknown'}.`));for(const item of value.providerEvidence||[])notes.append(element('p',`${item.provider} · ${item.source}: ${item.evidence}`));if(value.navigationNote)notes.append(element('p',value.navigationNote));if(value.coverage?.textTruncated||value.coverage?.inlineScriptsTruncated)notes.append(element('p','Evidence reached a capture size limit; some content was omitted.'));const ul=element('ul','');for(const line of value.limitations||[])ul.append(element('li',line));notes.append(ul);$('sandbox-screenshot-wrap').hidden=!value.screenshot;if(value.screenshot)$('sandbox-screenshot').src=`data:image/jpeg;base64,${value.screenshot}`;else $('sandbox-screenshot').removeAttribute('src');}
function renderHistory(){
  historyPanel.replaceChildren();
  const head=element('h3','Capture history');
  const note=element('p',`Reports are retained locally in this tab only (${history.size}/${MAX_REPORTS} stored). Clearing evidence removes it from this tab but does not reset capture quotas and does not delete server submission logs.`);
  const list=element('ul','');
  const selected=history.selectedId();
  for(const entry of history.list()){
    const item=element('li','');
    const pick=element('button',`Report captured ${entry.capturedAt} · ${describeAge(entry.capturedAt)}${entry.id===selected?' (selected)':''}`);
    pick.type='button';
    pick.className='checker-secondary';
    pick.setAttribute('aria-pressed',entry.id===selected?'true':'false');
    pick.addEventListener('click',()=>{if(!history.select(entry.id))return;showSelected();});
    const clear=element('button','Clear this evidence');
    clear.type='button';
    clear.className='checker-secondary';
    clear.addEventListener('click',()=>{history.remove(entry.id);showSelected();});
    item.append(pick,clear);
    list.append(item);
  }
  if(!list.children.length)list.append(element('li','No report evidence retained in this tab.'));
  const clearAll=element('button','Clear all report evidence');
  clearAll.type='button';
  clearAll.className='checker-secondary';
  clearAll.disabled=!history.size;
  clearAll.addEventListener('click',()=>{history.clear();showSelected();});
  historyPanel.append(head,note,list,clearAll);
}
function showSelected(){
  const selected=history.report();
  report=selected;
  if(!selected){
    $('sandbox-host-change').hidden=true;
    $('sandbox-host-change').textContent='';
    $('sandbox-verdict').textContent='';
    $('sandbox-verdict').removeAttribute('data-level');
    $('sandbox-report-meta').textContent='';
    $('sandbox-findings').replaceChildren();
    $('sandbox-limitations').replaceChildren();
    $('sandbox-screenshot').removeAttribute('src');
    $('sandbox-screenshot-wrap').hidden=true;
  }
  $('sandbox-results').hidden=!selected;
  const exportJson=$('sandbox-export'),exportText=$('sandbox-export-text');
  if(exportJson)exportJson.disabled=!selected;
  if(exportText)exportText.disabled=!selected;
  if(selected)renderReport(selected);
  renderHistory();
}
function render(value){
  report=value;
  if(history.isFull)history.replace(value);
  else history.add(value);
  showSelected();
}
function disconnect(){generation++;connection?.disconnect();connection=null;connecting=false;clearInterval(clock);clock=null;$('sandbox-display').replaceChildren();controls();}
function countdown(){if(!token){return;}const remaining=Math.max(0,Math.ceil(endsAt-Date.now()/1000));$('sandbox-timer').textContent=`${Math.floor(remaining/60)}:${String(remaining%60).padStart(2,'0')} remaining · no extensions`;controls();if(!remaining){token='';busy=false;opening=false;starting=false;disconnect();viewStatus('Session expired. Captured reports remain available below. Start a new session to inspect another page.');}}
async function connect(url){
  if(connecting)return;
  const current=token;
  if(!current||Date.now()>=endsAt*1000)return;
  connecting=true;controls();
  const attempt=++generation;connection?.disconnect();connection=null;$('sandbox-display').replaceChildren();viewStatus('Connecting live controls...');
  try{
    const parsed=new URL(url);if(parsed.protocol!=='https:'||parsed.hostname!=='bedrock-agentcore.us-east-1.amazonaws.com')throw new Error('Unexpected viewer endpoint.');
    const dcv=window.dcv;if(!dcv)throw new Error('Viewer could not load.');
    const diagnostics=[];
    dcv.setLogHandler(({domain,message,levelName})=>{
      if(attempt!==generation)return;
      if(!['WARN','ERROR'].includes(levelName)&&(!/channel|input/i.test(String(domain))||!/created channel|unable to create|not enabled|not available|status update|failed|rejected|not found/i.test(String(message))))return;
      const safe=String(message).replace(/(?:https?|wss?):\/\/\S+/g,'[endpoint]').replace(/[A-Za-z0-9_=-]{40,}/g,'[redacted]').slice(0,200);
      diagnostics.push(safe);if(diagnostics.length>8)diagnostics.shift();
      $('sandbox-display').dataset.diagnostics=diagnostics.join(' | ');
      console.info('Viewer diagnostic:',safe);
    });
    dcv.setLogLevel(dcv.LogLevel.INFO);
    const extra=()=>parsed.searchParams;
    const readiness=inputReadiness(text=>{if(attempt===generation)viewStatus(text);},()=>attempt===generation&&!!token&&Date.now()<endsAt*1000);
    const auth=await new Promise((resolve,reject)=>{const timeout=setTimeout(()=>reject(new Error('Viewer connection timed out.')),10000);dcv.authenticate(url,{httpExtraSearchParams:extra,promptCredentials:()=>{clearTimeout(timeout);reject(new Error('Viewer authorization failed.'));},error:()=>{clearTimeout(timeout);reject(new Error('Viewer connection failed.'));},success:(_,sessions)=>{clearTimeout(timeout);resolve(sessions[0]);}});});
    if(attempt!==generation||current!==token||Date.now()>=endsAt*1000)return;
    const conn=await dcv.connect({url,sessionId:auth.sessionId,authToken:auth.authToken,divId:'sandbox-display',baseUrl:viewerAssetBase(window.location.origin),enabledChannels:['display','input'],clipboardAutoSync:false,volumeLevel:0,observers:{httpExtraSearchParams:extra,featuresUpdate:readiness.changed,disconnect:()=>{if(attempt!==generation)return;viewStatus('Remote view disconnected. The automatic session timeout still applies. Use Reconnect view to retry.');}}});
    if(!conn?.disconnect)throw new Error('Viewer connection failed.');
    if(attempt!==generation||current!==token||Date.now()>=endsAt*1000){conn.disconnect();return;}
    connection=conn;conn.captureClipboardEvents(false);
    await conn.requestDisplayLayout([{name:'Main Display',rect:{x:0,y:0,width:1280,height:800},primary:true}]).catch(()=>{});
    if(attempt!==generation||current!==token)return;
    fit();
    await readiness.attach(conn);
  }catch(error){
    if(attempt===generation&&current===token)viewStatus(`${error.message} Use Reconnect view to retry within this session.`);
  }finally{
    if(attempt===generation)connecting=false;
    controls();
  }
}
async function openSubmitted(automatic=false){if(!token||opening||busy)return;if(!automatic&&(starting||connecting))return;const current=token;if(!current||Date.now()>=endsAt*1000)return;opening=true;controls();status('Opening your submitted URL and checking the page...');try{const data=await request({action:'open',token:current});if(current!==token)return;render(data.report);status(data.report.navigationNote||'Page opened. Interact in the live view, then capture a report.',data.report.pageLoaded===false||data.report.httpStatus>=400);}catch(error){if(current===token)status(error.message,true);}finally{if(current===token){opening=false;controls();}}}
$('sandbox-form').addEventListener('submit',async event=>{event.preventDefault();if(busy||starting||token)return;busy=true;starting=true;controls();status('Starting your time-limited browser...');let current='';try{const data=await request({action:'start',target:$('sandbox-target').value.trim(),streamFirst:true});token=data.token;current=data.token;liveUrl=data.liveUrl;endsAt=Date.now()/1000+Math.min(28800,Math.max(0,data.remainingSeconds||0));captures=0;nextCapture=0;opening=false;$('sandbox-capture').textContent=`Capture report (${3-captures} left)`;$('sandbox-session').hidden=false;fit();$('sandbox-session').scrollIntoView({block:'start',behavior:'instant'});countdown();clock=setInterval(countdown,1000);busy=false;controls();connect(liveUrl);if(data.needsOpen){viewStatus('Browser starting. The submitted URL opens automatically in about five seconds.');await new Promise(resolve=>setTimeout(resolve,5000));if(current&&current===token&&active())await openSubmitted(true);}else if(data.report)render(data.report);}catch(error){if(!current||current===token)status(error.message,true);}finally{if(!current||current===token){busy=false;starting=false;}controls();}});
$('sandbox-open').addEventListener('click',()=>{if(!active()||busy||starting||connecting||opening)return;openSubmitted(false);});
$('sandbox-reconnect').addEventListener('click',()=>{if(!active()||busy||starting||connecting||opening)return;viewStatus('Reconnecting live controls...');connect(liveUrl);});
$('sandbox-fullscreen').addEventListener('click',async()=>{try{if(document.fullscreenElement)await document.exitFullscreen();else await $('sandbox-session').requestFullscreen();fit();}catch{status('Full screen is unavailable in this browser.',true);}});
$('sandbox-capture').addEventListener('click',async()=>{const current=token;if(!current||busy||opening||connecting||starting)return;busy=true;nextCapture=Date.now()+20000;controls();status('Capturing visible evidence...');try{const data=await request({action:'capture',token:current});if(current!==token)return;captures++;render(data.report);$('sandbox-capture').textContent=`Capture report (${3-captures} left)`;status('Report captured. Allow 20 seconds before the next capture.');}catch(error){if(current===token)status(error.message,true);}finally{if(current===token){busy=false;controls();}}});
$('sandbox-stop').addEventListener('click',async()=>{const current=token;if(!current)return;token='';starting=false;opening=false;busy=true;disconnect();viewStatus('Remote view disconnected.');$('sandbox-timer').textContent='Ending session...';try{const data=await request({action:'stop',token:current});status(data.message);$('sandbox-timer').textContent='Session stopped';}catch(error){status(error.message,true);$('sandbox-timer').textContent='Disconnected; automatic expiry still applies';}finally{busy=false;controls();}});
$('sandbox-export-text').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([readableReport(report)],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='smithey-lab-inspection.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
$('sandbox-export').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download='smithey-lab-captcha-report.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
window.addEventListener('pagehide',()=>{connection?.disconnect();if(token&&endpoint)fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'stop',token}),keepalive:true}).catch(()=>{});});
$('sandbox-results').append(historyPanel);
showSelected();
controls();
try{const response=await fetch('/captcha-config.json',{cache:'no-store'});const config=await response.json();if(config.enabled&&config.endpoint){const url=new URL(config.endpoint);if(url.protocol!=='https:'||!url.hostname.endsWith('.execute-api.us-east-1.amazonaws.com'))throw new Error();endpoint=url.href;status('Ready. Session setup uses part of the session allowance.');}else status('The sandbox is being prepared and is not accepting sessions yet.');}catch{status('Availability could not be checked. Please reload later.',true);}controls();
