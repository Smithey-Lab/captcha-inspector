import {createHash,randomBytes} from 'node:crypto';
import {DynamoDBClient} from '@aws-sdk/client-dynamodb';
import {DynamoDBDocumentClient,GetCommand,UpdateCommand,TransactWriteCommand} from '@aws-sdk/lib-dynamodb';
import {BedrockAgentCoreClient,StartBrowserSessionCommand,StopBrowserSessionCommand} from '@aws-sdk/client-bedrock-agentcore';
import {Browser} from 'bedrock-agentcore/browser';
import {chromium} from 'playwright-core';
import checker from '../net-target.cjs';
import analyzer from './analyze.cjs';
import {auditWriter} from './audit.mjs';
import {quotaDetails,failureDetails} from './errors.mjs';

export const LIMITS=Object.freeze({daily:5,monthly:100,networkDaily:2,seconds:60,captures:3,leaseSeconds:120});
const hash=value=>createHash('sha256').update(value).digest('hex');
const safeFailure=error=>String(error?.message||'Unknown failure').split('\n')[0].replace(/(?:https?|wss?):\/\/\S+/gi,'[URL]').slice(0,240);
const seconds=()=>Math.floor(Date.now()/1000);
const options={region:process.env.AWS_REGION||'us-east-1',maxAttempts:1,requestHandler:{connectionTimeout:1500,requestTimeout:7000}};
const db=DynamoDBDocumentClient.from(new DynamoDBClient(options));
const core=new BedrockAgentCoreClient(options);
const table=()=>process.env.RATE_TABLE;
const identifier=()=>process.env.BROWSER_ID;
export function parseSandboxTarget(value){
  const target=checker.parseTarget(value);
  const raw=value.trim();
  // Validate the authority with the shared public-target policy, but keep the submitted page.
  const submitted=new URL(raw.includes('://')?raw:raw===target.host&&raw.includes(':')?target.origin:`https://${raw}`);
  return {...target,url:target.origin+submitted.pathname+submitted.search+submitted.hash};
}
export function quotaTransaction({table,network,now,key,member=false}){
  const day=Math.floor(now/86400),month=new Date(now*1000).toISOString().slice(0,7);
  const counter=(id,limit,expires)=>({Update:{TableName:table,Key:{id},UpdateExpression:'SET expires = :expires ADD #n :one',ConditionExpression:'attribute_not_exists(#n) OR #n < :limit',ExpressionAttributeNames:{'#n':'count'},ExpressionAttributeValues:{':expires':expires,':one':1,':limit':limit}}});
  return {TransactItems:[
    counter(`sandbox:day:${day}`,LIMITS.daily,now+172800),
    counter(`sandbox:month:${month}`,LIMITS.monthly,now+35*86400),
    ...(!member?[counter(`sandbox:network:${hash(`${day}:${network}`)}`,LIMITS.networkDaily,now+172800)]:[]),
    {Update:{TableName:table,Key:{id:'sandbox:lease'},UpdateExpression:'SET untilTime = :until, ownerKey = :owner, expires = :expires',ConditionExpression:'attribute_not_exists(untilTime) OR untilTime <= :now',ExpressionAttributeValues:{':until':now+LIMITS.leaseSeconds,':owner':key,':expires':now+3600,':now':now}}},
    {Put:{TableName:table,Item:{id:key,sourceHash:hash(`${day}:${network}`),createdAt:now,expires:now+900,state:'starting',captures:0},ConditionExpression:'attribute_not_exists(id)'}}
  ]};
}
export function isQuota(error){return error.name==='TransactionCanceledException'&&error.CancellationReasons?.some(r=>r.Code==='ConditionalCheckFailed');}
async function save(key,fields){
  const names={},values={};const updates=Object.entries(fields).map(([k,v],i)=>{names[`#k${i}`]=k;values[`:v${i}`]=v;return `#k${i} = :v${i}`;});
  return db.send(new UpdateCommand({TableName:table(),Key:{id:key},UpdateExpression:'SET '+updates.join(', '),ConditionExpression:'attribute_exists(id)',ExpressionAttributeNames:names,ExpressionAttributeValues:values}));
}
async function stop(sessionId){if(sessionId)await core.send(new StopBrowserSessionCommand({browserIdentifier:identifier(),sessionId}));}
// Never return automation credentials or CDP URLs to the visitor.
async function capture(sessionId,target,initial=false){
  const browserClient=new Browser({region:options.region,identifier:identifier()});browserClient.attachSession(sessionId);
  const connection=await browserClient.generateWebSocketUrl();
  const browser=await chromium.connectOverCDP(connection.url,{headers:connection.headers,timeout:7000});
  try{
    const context=browser.contexts()[0];if(!context)throw new Error('No browser context');
    const pages=context.pages().filter(p=>!p.isClosed());
    let page=pages.at(-1)||await context.newPage();
    if(!initial)for(const candidate of [...pages].reverse()){
      if(await candidate.evaluate(()=>document.visibilityState==='visible').catch(()=>false)){page=candidate;break;}
    }
    page.setDefaultTimeout(3500);page.setDefaultNavigationTimeout(7000);
    const cdp=await context.newCDPSession(page);
    await cdp.send('Browser.setDownloadBehavior',{behavior:'deny'});
    await cdp.send('Network.setBypassServiceWorker',{bypass:true});
    await context.clearPermissions();
    // Guard requests while gathering evidence. The microVM uses AWS public networking,
    // never the site's VPC. This application-level check is not a network firewall.
    let requests=0;
    const resolved=new Map();
    const guard=async route=>{
      try{
        if(++requests>100)return await route.abort();
        const request=route.request();if(!['GET','HEAD','POST','OPTIONS'].includes(request.method()))return await route.abort();
        const url=new URL(request.url());const parsed=checker.parseTarget(url.origin);
        if(!resolved.has(url.origin))resolved.set(url.origin,checker.resolveTarget(parsed));
        await resolved.get(url.origin);
        await route.continue();
      }catch{await route.abort().catch(()=>{});}
    };
    // Only intercept navigation. Attaching a fresh route during a report can break live forms.
    if(initial)await context.route('**/*',guard);
    let navigationNote='',httpStatus=null,navigationCode=null;
    if(initial){try{const response=await page.goto(target,{waitUntil:'domcontentloaded',timeout:8000});httpStatus=response?.status()??null;}catch(error){const failure=failureDetails(error,'open');navigationCode=failure.code;navigationNote=failure.message;}finally{await context.unrouteAll({behavior:'ignoreErrors'});}}
    const snapshot=await page.evaluate(()=>({
      title:document.title.slice(0,300),url:location.href.slice(0,2048),
      text:(document.body?.innerText||'').slice(0,100001),
      inlineScripts:Array.from(document.scripts).filter(s=>!s.src).slice(0,100).map(s=>s.textContent.slice(0,50000)).join('\n').slice(0,200001),
      scriptUrls:Array.from(document.scripts).filter(s=>s.src).slice(0,100).map(s=>s.src.slice(0,2048)),
      frameCount:document.querySelectorAll('iframe,frame').length
    }));
    const report=analyzer.analyze(snapshot);
    const pageLoaded=/^https?:\/\//i.test(snapshot.url)&&!!snapshot.text.trim();
    if(!pageLoaded){report.level='inconclusive';report.verdict='Website did not load';navigationNote=(navigationNote?navigationNote+' ':'')+'The requested page is not visible. Use Open submitted URL to retry within this session, or stop the browser.';}
    if(httpStatus>=400){report.level='inconclusive';report.verdict=`Website returned HTTP ${httpStatus}`;navigationNote='The website returned an error to the AWS browser. Its response can differ from the page you see on your own network.';}
    let screenshot=null;
    try{const bytes=await page.screenshot({type:'jpeg',quality:40,timeout:3500,fullPage:false});if(bytes.length<=220000)screenshot=bytes.toString('base64');}catch{/* Optional evidence or diagnostic unavailable; core request continues. */}
    return {...report,pageLoaded,httpStatus,navigationCode,title:snapshot.title,url:snapshot.url,requestedUrl:target,capturedAt:new Date().toISOString(),frameCount:snapshot.frameCount,navigationNote,screenshot};
  }finally{await browser.close();}
}
export function createHandler(deps={}){
  const reserve=deps.reserve||((args)=>db.send(new TransactWriteCommand(quotaTransaction(args))));
  const startBrowser=deps.startBrowser||(args=>core.send(new StartBrowserSessionCommand(args)));
  const takeCapture=deps.capture||capture;
  const stopBrowser=deps.stop||stop;
  const persist=deps.save||save;
  const read=deps.read||(async key=>(await db.send(new GetCommand({TableName:table(),Key:{id:key},ConsistentRead:true}))).Item);
  const clock=deps.now||seconds;
  const env=deps.env||process.env;
  const audit=auditWriter(db,env.RATE_TABLE,clock);
  const recordSubmission=deps.recordSubmission||audit.submit;
  const log=async(key,type,details={})=>{try{await (deps.auditUpdate||audit.append)(key,type,details);}catch{console.error('Sandbox audit event write failed');}};
  const update=async(key,fields)=>{
    await persist(key,fields);
    if(fields.state)await log(key,fields.state,fields.endsAt?{endsAt:fields.endsAt}:{});
    if(fields.failureStage)await log(key,'operation_failed',{stage:fields.failureStage,code:fields.failureCode||'SERVICE_ERROR'});
  };
  return async event=>{
    const origin=event.headers?.origin;
    const allowed=new Set((env.ALLOWED_ORIGINS||'').split(','));
    const headers={'content-type':'application/json','cache-control':'no-store','vary':'Origin'};
    if(allowed.has(origin))headers['access-control-allow-origin']=origin;
    const reply=(statusCode,value,extra={})=>({statusCode,headers:{...headers,...extra},body:JSON.stringify(value)});
    if(!allowed.has(origin))return reply(403,{message:'Request not permitted.'});
    if(event.requestContext?.http?.method!=='POST')return reply(405,{message:'Use POST.'});
    if(!(event.headers?.['content-type']||'').toLowerCase().startsWith('application/json'))return reply(415,{message:'Use JSON.'});
    if(typeof event.body!=='string'||event.body.length>4096)return reply(413,{message:'Request too large.'});
    let input,network;
    // Only the IAM-authorized member Lambda supplies this top-level field. HTTP
    // API payloads put all visitor-controlled fields inside event.body.
    const member=typeof event.memberSub==='string'&&/^[a-f0-9-]{36}$/.test(event.memberSub);
    try{input=JSON.parse(event.isBase64Encoded?Buffer.from(event.body,'base64').toString('utf8'):event.body);network=member?'member:'+event.memberSub:checker.networkKey(event.requestContext.http.sourceIp);}catch{return reply(400,{message:'Invalid request.'});}
    if(!input||!['start','open','capture','stop'].includes(input.action))return reply(400,{message:'Choose a supported action.'});
    if(input.action==='start'){
      if(env.SANDBOX_ENABLED!=='true')return reply(503,{message:'The sandbox is paused. Please try later.'});
      let target;try{target=parseSandboxTarget(input.target);}catch(error){return reply(400,{message:error.message});}
      const token=randomBytes(32).toString('hex'),key=`sandbox:session:${hash(token)}`,now=clock();
      try{await recordSubmission({key,target:target.url,network,now,memberSub:member?event.memberSub:undefined});}catch{return reply(503,{message:'Submission recording is unavailable or its daily limit is reached. No browser was started.'});}
      try{await reserve({table:env.RATE_TABLE,network,now,key,member});}catch(error){
        if(!isQuota(error)){await log(key,'limiter_failed',{code:'LIMITER_UNAVAILABLE'});return reply(503,{code:'LIMITER_UNAVAILABLE',message:'The sandbox limit service is unavailable. No browser was started.'});}
        const leaseIndex=member?2:3;
        let leaseUntil;
        if(error.CancellationReasons?.[leaseIndex]?.Code==='ConditionalCheckFailed')try{leaseUntil=(await read('sandbox:lease'))?.untilTime;}catch{/* Optional evidence or diagnostic unavailable; core request continues. */}
        const detail=quotaDetails(error,{member,now,leaseUntil});
        await log(key,'rate_limited',{codes:detail.reasons.map(r=>r.code),retryAt:detail.retryAt});
        return reply(429,detail,{'retry-after':String(Math.max(1,detail.retryAt-now))});
      }
      let sessionId,stage='resolve';
      try{
        // DNS and all billable activity occur only after the atomic reservation.
        await (deps.resolve||checker.resolveTarget)(target);
        stage='start';
        const startedAt=clock();
        const session=await startBrowser({browserIdentifier:env.BROWSER_ID,name:'smithey-lab-sandbox',clientToken:hash(token),sessionTimeoutSeconds:LIMITS.seconds,viewPort:{width:1280,height:800}});
        sessionId=session.sessionId;if(!sessionId)throw new Error('No session');
        const end=startedAt+LIMITS.seconds;
        stage='save';
        await update(key,{sessionId,target:target.url,endsAt:end,state:'active'});
        stage='capture';
        let report;
        if(!input.streamFirst)try{report=await takeCapture(sessionId,target.url,true);}catch(error){
          await update(key,{failureStage:'capture',failureCode:failureDetails(error,'capture').code,failure:safeFailure(error)}).catch(()=>{});
          report={...analyzer.analyze({}),requestedUrl:target.url,capturedAt:new Date().toISOString(),navigationNote:'The page could not be opened or captured. The browser is not ready for inspection.',screenshot:null};
        }
        stage='sign';
        const client=deps.browserClient?deps.browserClient():new Browser({region:options.region,identifier:env.BROWSER_ID});client.attachSession(sessionId);
        const liveUrl=await client.generateLiveViewUrl(LIMITS.seconds);
        return reply(200,{token,target:target.url,endsAt:end,remainingSeconds:Math.max(0,end-clock()),liveUrl,report:report||null,needsOpen:!!input.streamFirst,limits:LIMITS,viewport:{width:1280,height:800}});
      }catch(error){
        if(sessionId)await stopBrowser(sessionId).catch(()=>{});
        // Short operator-only diagnostic, without URLs, headers, stacks or page content.
        const failure=safeFailure(error);
        await update(key,{state:'failed',failureStage:stage,failureCode:failureDetails(error,stage).code,failure}).catch(()=>{});
        return reply(503,{code:failureDetails(error,stage).code,message:failureDetails(error,stage).message+' This start attempt counts toward your allowance. Any created browser expires automatically.'});
      }
    }
    if(typeof input.token!=='string'||! /^[a-f0-9]{64}$/.test(input.token))return reply(403,{message:'Invalid session.'});
    const key=`sandbox:session:${hash(input.token)}`;
    let record;try{record=await read(key);}catch{return reply(503,{message:'Session lookup unavailable.'});}
    if(!record||record.sourceHash!==hash(`${Math.floor(record.createdAt/86400)}:${network}`))return reply(403,{message:'Invalid session.'});
    if(input.action==='stop'){
      if(record.state!=='active')return reply(200,{message:'Session is already closed.'});
      try{await stopBrowser(record.sessionId);await update(key,{state:'stopped'});return reply(200,{message:'Browser stopped. Your report remains in this tab.'});}catch(error){await log(key,'operation_failed',{stage:'stop',code:failureDetails(error,'stop').code});return reply(503,{code:failureDetails(error,'stop').code,message:failureDetails(error,'stop').message+' The automatic session timeout still applies.'});}
    }
    if(record.state!=='active'||record.endsAt<=clock())return reply(410,{message:'Session expired. The last captured report remains available in this tab.'});
    if(input.action==='open'){
      try{
        if(deps.reserveOpen)await deps.reserveOpen(key,clock());
        else await db.send(new UpdateCommand({TableName:table(),Key:{id:key},UpdateExpression:'SET operationUntil = :until ADD opens :one',ConditionExpression:'#state = :active AND endsAt > :now AND (attribute_not_exists(opens) OR opens < :limit) AND (attribute_not_exists(operationUntil) OR operationUntil <= :now)',ExpressionAttributeNames:{'#state':'state'},ExpressionAttributeValues:{':active':'active',':now':clock(),':until':clock()+28,':one':1,':limit':2}}));
      }catch{return reply(429,{message:'Opening is already in progress, or both navigation attempts are used. You can still interact with the remote browser.'});}
      try{const report=await takeCapture(record.sessionId,record.target,true);await log(key,'opened',{pageLoaded:report.pageLoaded===true,httpStatus:report.httpStatus??null,code:report.navigationCode||(report.httpStatus>=400?'HTTP_ERROR':report.pageLoaded?'PAGE_LOADED':'PAGE_NOT_LOADED')});return reply(200,{report});}catch(error){await update(key,{failureStage:'open',failureCode:failureDetails(error,'open').code,failure:safeFailure(error)}).catch(()=>{});return reply(503,{code:failureDetails(error,'open').code,message:failureDetails(error,'open').message+' Use Open submitted URL once more within this session, or stop the browser.'});}finally{await update(key,{operationUntil:clock()}).catch(()=>{});}
    }
    try{
      if(deps.reserveCapture)await deps.reserveCapture(key,clock());
      else await db.send(new UpdateCommand({TableName:table(),Key:{id:key},UpdateExpression:'SET nextCapture = :next, operationUntil = :until ADD captures :one',ConditionExpression:'#state = :active AND endsAt > :now AND captures < :limit AND (attribute_not_exists(nextCapture) OR nextCapture <= :now) AND (attribute_not_exists(operationUntil) OR operationUntil <= :now)',ExpressionAttributeNames:{'#state':'state'},ExpressionAttributeValues:{':active':'active',':now':clock(),':next':clock()+20,':until':clock()+28,':one':1,':limit':LIMITS.captures}}));
    }catch{return reply(429,{message:'Report limit reached. Allow 20 seconds between captures; at most three extra captures per session.'});}
    try{const report=await takeCapture(record.sessionId,record.target);await log(key,'captured',{level:report.level||'inconclusive'});return reply(200,{report});}catch(error){await update(key,{failureStage:'capture',failureCode:failureDetails(error,'capture').code,failure:safeFailure(error)}).catch(()=>{});return reply(503,{code:failureDetails(error,'capture').code,message:failureDetails(error,'capture').message+' Your previous report is unchanged.'});}finally{await update(key,{operationUntil:clock()}).catch(()=>{});}
  };
}
export const handler=createHandler();
