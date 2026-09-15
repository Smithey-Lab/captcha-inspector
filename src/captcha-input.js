// DCV strips leading slashes from relative baseUrl values and resolves them
// against the current page. An absolute URL is required on nested tool routes.
export function viewerAssetBase(origin){return new URL('/assets/dcv',origin).href;}

export function inputReadiness(publish,isCurrent){
  let connection;
  let revision=0;
  const refresh=async()=>{
    const current=++revision;
    if(!connection)return;
    const states=await Promise.all(['mouse','keyboard'].map(async name=>{
      try{return {name,enabled:(await connection.queryFeature(name)).enabled===true};}
      catch{return {name,enabled:null};}
    }));
    if(current!==revision||!isCurrent())return;
    publish(states.every(s=>s.enabled)?'Live controls ready. Click inside the remote page to focus it.':`Live picture connected; ${states.map(s=>`${s.name}: ${s.enabled===null?'waiting':s.enabled?'ready':'unavailable'}`).join('; ')}. Controls may pause while a report is captured.`);
  };
  return {changed:()=>{void refresh();},attach:value=>{connection=value;return refresh();}};
}
