export function shouldBlockViewerEvent(event,viewOnly=false){
  if(event.type==='keydown'&&['Tab','Escape'].includes(event.key))return false;
  if(['copy','cut','paste','dragstart','dragover','drop'].includes(event.type))return true;
  if(viewOnly&&!['keyup'].includes(event.type))return true;
  const key=String(event.key||'').toLowerCase();
  return (event.ctrlKey||event.metaKey)&&['c','v','x'].includes(key)||key==='insert'&&(event.shiftKey||event.ctrlKey)||key==='delete'&&event.shiftKey;
}
export function installViewerProtection({root,notice,isViewOnly,eventRoot=window}){
  const protect=event=>{
    const target=event.target;
    if(!root.contains(target))return;
    if(!shouldBlockViewerEvent(event,isViewOnly()))return;
    event.preventDefault();event.stopImmediatePropagation();
    notice(isViewOnly()?'View-only mode: turn off View only to interact. The session timer still runs.':'Copy/paste and file dragging are blocked in the remote view. Your device clipboard is not read or changed.');
  };
  const types=['copy','cut','paste','dragstart','dragover','drop','keydown','keyup','pointerdown','pointerup','mousedown','mouseup','click','dblclick','wheel','touchstart','touchmove'];
  for(const type of types)eventRoot.addEventListener(type,protect,{capture:true,passive:false});
  return ()=>{for(const type of types)eventRoot.removeEventListener(type,protect,true);};
}
export function hostChange(requested,viewed){
  try{const a=new URL(requested),b=new URL(viewed);if(!/^https?:$/.test(a.protocol)||!/^https?:$/.test(b.protocol))return null;
    return a.hostname!==b.hostname?{from:a.hostname,to:b.hostname}:null;
  }catch{return null;}
}
export function readableReport(report){
  const defang=value=>String(value||'').replace(/https:\/\//gi,'hxxps://').replace(/http:\/\//gi,'hxxp://');
  return ['SMITHEY LAB - INSPECTION EVIDENCE','Untrusted page content. Do not run copied commands. URLs below are defanged.',
    `Captured: ${report.capturedAt||'Unknown'}`,`Requested: ${defang(report.requestedUrl)}`,`Viewed: ${defang(report.url)}`,
    `Assessment: ${report.verdict}`,report.navigationNote||'',
    ...(report.findings||[]).flatMap(f=>['',f.title,f.description,`Source: ${f.source}`,`Evidence: ${defang(f.evidence)}`]),
    '',...(report.limitations||[])].join('\n');
}
