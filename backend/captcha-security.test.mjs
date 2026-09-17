import {test} from 'node:test';
import assert from 'node:assert/strict';
import {sealTarget,openTarget} from './captcha/target-vault.mjs';
import {submissionTransaction} from './captcha/audit.mjs';
import {createHandler} from './captcha/service.mjs';
test('target ciphertext requires the original token and record and detects tampering',()=>{
 const token='ab'.repeat(32),key='sandbox:session:test',url='https://example.com/private-token?secret=abc#private';
 const sealed=sealTarget(url,token,key);
 assert.equal(openTarget(sealed,token,key),url);
 assert.notDeepEqual(sealTarget(url,token,key),sealed);
 assert.doesNotMatch(JSON.stringify(sealed),/private|secret|example/);
 assert.throws(()=>openTarget(sealed,'cd'.repeat(32),key));
 assert.throws(()=>openTarget(sealed,token,key+'x'));
 assert.throws(()=>openTarget({...sealed,tag:Buffer.from(sealed.tag,'base64').subarray(0,4).toString('base64')},token,key));
 const data=Buffer.from(sealed.data,'base64');data[0]^=1;
 assert.throws(()=>openTarget({...sealed,data:data.toString('base64')},token,key));
});
test('exhausted public and network audit budgets do not consume any member budget',async()=>{
 const rows=new Map();let sequence=0;
 const submit=async args=>{
  const tx=submissionTransaction({table:'test',...args});
  for(const x of tx.TransactItems){if(x.Update&&(rows.get(x.Update.Key.id)||0)>=x.Update.ExpressionAttributeValues[':max'])throw Object.assign(new Error(),{name:'TransactionCanceledException',CancellationReasons:[{Code:'ConditionalCheckFailed'}]});}
  for(const x of tx.TransactItems)if(x.Update)rows.set(x.Update.Key.id,(rows.get(x.Update.Key.id)||0)+1);
 };
 const args=network=>({key:`sandbox:session:${sequence++}`,target:'https://example.com/private?queryname=value#fragment',network,now:1789344000});
 for(let network=0;network<50;network++)for(let i=0;i<20;i++)await submit(args('network'+network));
 await assert.rejects(submit(args('new-network')));
 const memberSub='11111111-1111-1111-1111-111111111111';
 for(let i=0;i<100;i++)await submit({...args('member:'+memberSub),memberSub});
 await assert.rejects(submit({...args('member:'+memberSub),memberSub}));
 await submit({...args('different-member'),memberSub:'22222222-2222-2222-2222-222222222222'});
 const tx=submissionTransaction({table:'test',...args('network')});
 assert.equal(tx.TransactItems.at(-1).Put.Item.submittedUrl,'https://example.com');
 assert.doesNotMatch(JSON.stringify(tx),/private|queryname|fragment|value/);
});
test('audit quota returns 429 and prevents reservation and paid browser work',async()=>{
 let work=0;
 const handler=createHandler({read:async()=>undefined,env:{ALLOWED_ORIGINS:'https://smitheylab.com',SANDBOX_ENABLED:'true'},recordSubmission:async()=>{throw Object.assign(new Error(),{name:'TransactionCanceledException',CancellationReasons:[{Code:'ConditionalCheckFailed'}]});},reserve:async()=>work++,startBrowser:async()=>work++});
 const r=await handler({headers:{origin:'https://smitheylab.com','content-type':'application/json'},requestContext:{http:{method:'POST',sourceIp:'8.8.8.8'}},body:JSON.stringify({action:'start',target:'example.com'})});
 assert.equal(r.statusCode,429);assert.equal(work,0);assert.ok(Number(r.headers['retry-after'])>0);
});
