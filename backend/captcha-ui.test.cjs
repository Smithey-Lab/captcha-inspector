const test=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const {join}=require('node:path');

async function harness(){
  const history=await import('../src/captcha-history.js');
  const nodes=new Map(),calls=[],timers=[];
  let finishCapture;
  function element(){return {children:[],dataset:{},style:{},handlers:{},clientWidth:1280,value:'example.com',textContent:'',append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;},removeAttribute(key){delete this[key];},setAttribute(key,value){this[key]=value;},addEventListener(type,fn){this.handlers[type]=fn;},scrollIntoView(){}};}
  const get=id=>{if(!nodes.has(id))nodes.set(id,element());return nodes.get(id);};
  const report={capturedAt:'2026-01-01T00:00:00Z',requestedUrl:'https://example.com',url:'https://example.com',verdict:'Initial report',screenshot:'fixture',findings:[],limitations:[]};
  const fetch=async(_url,options)=>{
    if(!options?.body)return {ok:true,json:async()=>({enabled:true,endpoint:'https://fixture.execute-api.us-east-1.amazonaws.com/sandbox'})};
    const body=JSON.parse(options.body);calls.push(body.action);
    if(body.action==='capture')await new Promise(resolve=>{finishCapture=resolve;});
    return {ok:true,json:async()=>body.action==='start'?{token:'fixture-token',liveUrl:'https://bedrock-agentcore.us-east-1.amazonaws.com/fixture',remainingSeconds:60,needsOpen:true}:body.action==='stop'?{message:'Stopped'}:{report:{...report,verdict:body.action==='capture'?'Late report':'Initial report'}}};
  };
  const dcv={LogLevel:{INFO:1},setLogHandler(){},setLogLevel(){},authenticate(_url,options){calls.push('authenticate');options.success(null,[{sessionId:'fixture',authToken:'fixture'}]);},async connect(){calls.push('connect');return {disconnect(){},captureClipboardEvents(){},async requestDisplayLayout(){}};}};
  const env={document:{getElementById:get,createElement:element},window:{innerHeight:1000,location:{origin:'https://example.test'},addEventListener(){},dcv},ResizeObserver:class{observe(){}},fetch,setTimeout:(fn,ms)=>{timers.push({fn,ms});return timers.length;},clearTimeout(){},setInterval(){return 1;},clearInterval(){},installViewerProtection(){},hostChange:()=>null,readableReport:()=>'',inputReadiness:()=>({changed(){},async attach(){}}),viewerAssetBase:()=> 'https://example.test/assets/dcv/',...history};
  const source=readFileSync(join(__dirname,'../src/captcha.js'),'utf8').replace(/^import .*;\r?\n/gm,'');
  const AsyncFunction=Object.getPrototypeOf(async function(){}).constructor;
  await new AsyncFunction(...Object.keys(env),source)(...Object.values(env));
  const flush=async()=>{for(let i=0;i<20;i++)await Promise.resolve();};
  return {get,calls,flush,start:()=>get('sandbox-form').handlers.submit({preventDefault(){}}),delay:async()=>{timers.find(t=>t.ms===5000).fn();await flush();},finishCapture:()=>finishCapture()};
}

test('startup connects immediately, gates manual capture, and opens once after delay',async()=>{
  const h=await harness(),started=h.start();await h.flush();
  assert.ok(h.calls.includes('connect'));
  assert.equal(h.calls.includes('open'),false);
  assert.equal(h.get('sandbox-capture').disabled,true);
  await h.get('sandbox-capture').handlers.click();assert.equal(h.calls.includes('capture'),false);
  await h.delay();await started;
  assert.equal(h.calls.filter(x=>x==='open').length,1);
  assert.equal(h.get('sandbox-capture').disabled,false);
});

test('stop during capture sends stop and ignores the late report; clearing removes DOM evidence',async()=>{
  const h=await harness(),started=h.start();await h.flush();await h.delay();await started;
  const captured=h.get('sandbox-capture').handlers.click();await h.flush();
  assert.ok(h.calls.includes('capture'));
  await h.get('sandbox-stop').handlers.click();assert.ok(h.calls.includes('stop'));
  h.finishCapture();await captured;
  assert.equal(h.get('sandbox-verdict').textContent,'Initial report');
  const panel=h.get('sandbox-results').children[0];
  await panel.children.at(-1).handlers.click();
  assert.equal(h.get('sandbox-screenshot').src,undefined);
  assert.equal(h.get('sandbox-report-meta').textContent,'');
  assert.equal(h.get('sandbox-findings').children.length,0);
  assert.equal(h.get('sandbox-export').disabled,true);
});

test('stop during startup prevents the delayed open',async()=>{
  const h=await harness(),started=h.start();await h.flush();
  await h.get('sandbox-stop').handlers.click();await h.delay();await started;
  assert.equal(h.calls.includes('open'),false);
});
