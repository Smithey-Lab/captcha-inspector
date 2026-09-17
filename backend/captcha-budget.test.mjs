import test from 'node:test';
import assert from 'node:assert/strict';
import {DEFAULT_BUDGET,validateBudget,durationFor,budgetItems} from './captcha/budget.mjs';
import {createHandler,quotaTransaction} from './captcha/service.mjs';
test('budgets reject unlimited, fractional, inverted and provider-exceeding limits',()=>{
 for(const n of [0,-1,Infinity,NaN,null,'300',60.5])assert.throws(()=>validateBudget({...DEFAULT_BUDGET,dailySeconds:n}));
 assert.throws(()=>validateBudget({...DEFAULT_BUDGET,maxSessionSeconds:301}));
 assert.throws(()=>validateBudget({dailySeconds:86400,monthlySeconds:90000,maxSessionSeconds:28801}));
 assert.equal(durationFor({member:false,requested:28800,budget:DEFAULT_BUDGET}),60);
 assert.throws(()=>durationFor({member:true,requested:61,budget:DEFAULT_BUDGET}));
});
test('time reservation is atomic with start limits and settings revision',()=>{
 const budget={dailySeconds:300,monthlySeconds:6000,maxSessionSeconds:300,revision:4};
 const tx=quotaTransaction({table:'t',network:'n',now:1000,key:'k',member:true,seconds:240,budget});
 assert.equal(tx.TransactItems.length,7);
 const [day,month,guard]=tx.TransactItems.slice(-3);
 assert.equal(day.Update.ExpressionAttributeValues[':seconds'],240);
 assert.equal(day.Update.ExpressionAttributeValues[':remaining'],60);
 assert.equal(month.Update.ExpressionAttributeValues[':remaining'],5760);
 assert.equal(guard.ConditionCheck.ExpressionAttributeValues[':revision'],4);
 assert.equal(tx.TransactItems[2].Update.ExpressionAttributeValues[':until'],1300);
 assert.equal(budgetItems({table:'t',now:1000,seconds:60,budget:DEFAULT_BUDGET}).at(-1).ConditionCheck.ConditionExpression,'attribute_not_exists(id)');
});
test('trusted member duration drives provider expiry, signed view, record and reservation',async()=>{
 const calls={},budget={dailySeconds:300,monthlySeconds:6000,maxSessionSeconds:300,revision:1};
 const handler=createHandler({env:{ALLOWED_ORIGINS:'https://smitheylab.com',SANDBOX_ENABLED:'true',RATE_TABLE:'t',BROWSER_ID:'b'},now:()=>1000,read:async()=>budget,recordSubmission:async()=>{},auditUpdate:async()=>{},reserve:async v=>{calls.reservation=v;},resolve:async()=>{},startBrowser:async v=>{calls.start=v;return {sessionId:'s'};},save:async(_,v)=>{calls.record=v;},handover:async()=>{},browserClient:()=>({attachSession(){},generateLiveViewUrl:async v=>{calls.signed=v;return 'https://example.test';}})});
 const base={headers:{origin:'https://smitheylab.com','content-type':'application/json'},requestContext:{http:{method:'POST',sourceIp:'8.8.8.8'}},body:JSON.stringify({action:'start',target:'example.com',sessionSeconds:240,streamFirst:true})};
 const result=await handler({...base,memberSub:'11111111-1111-1111-1111-111111111111',memberMaxSeconds:240});
 assert.equal(result.statusCode,200);assert.equal(calls.start.sessionTimeoutSeconds,240);assert.equal(calls.record.endsAt,1240);assert.equal(calls.signed,240);assert.equal(calls.reservation.seconds,240);
 const publicResult=await handler(base);assert.equal(publicResult.statusCode,200);assert.equal(calls.start.sessionTimeoutSeconds,60);
});
