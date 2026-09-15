import {test} from 'node:test';
import assert from 'node:assert/strict';
import {quotaDetails,failureDetails} from './captcha/errors.mjs';
const now=Date.UTC(2026,11,31,23,59)/1000;
const rejected=(...indices)=>({CancellationReasons:Array.from({length:5},(_,i)=>({Code:indices.includes(i)?'ConditionalCheckFailed':'None'}))});
test('daily and monthly rejections expose exact UTC rollover and all failed limits',()=>{
  const result=quotaDetails(rejected(0,1,2),{now});
  assert.deepEqual(result.reasons.map(r=>r.code),['GLOBAL_DAILY_LIMIT','GLOBAL_MONTHLY_LIMIT','NETWORK_DAILY_LIMIT']);
  assert.equal(result.retryAt,Date.UTC(2027,0,1)/1000);
  assert.match(result.message,/2027-01-01 00:00:00 UTC/);
});
test('member lease index cannot be confused with public network rejection',()=>{
  assert.equal(quotaDetails(rejected(2),{now}).code,'NETWORK_DAILY_LIMIT');
  const member=quotaDetails(rejected(2),{now,member:true,leaseUntil:now+48});
  assert.equal(member.code,'SESSION_BUSY');assert.equal(member.retryAt,now+48);
  assert.equal(quotaDetails(rejected(3),{now,leaseUntil:now+32}).retryAt,now+32);
});
test('non-counter reservation conflict does not invent an exhausted allowance',()=>{
  const result=quotaDetails(rejected(4),{now});assert.equal(result.code,'ADMISSION_CONFLICT');assert.deepEqual(result.reasons,[]);
});
test('failure reasons are classified without exposing raw URLs, tokens or stack text',()=>{
  const samples=[['ERR_NAME_NOT_RESOLVED','DNS_NOT_FOUND'],['net::ERR_CERT_DATE_INVALID','TLS_ERROR'],['connect ECONNREFUSED','CONNECTION_REFUSED'],['Navigation timed out','TIMEOUT'],['private answer','TARGET_RESTRICTED']];
  for(const [message,code] of samples){const result=failureDetails(new Error(message+' https://private.example/?token=secret'),'open');assert.equal(result.code,code);assert.doesNotMatch(JSON.stringify(result),/private.example|secret|token=/);}
  assert.equal(failureDetails({name:'AccessDeniedException'},'start').code,'SERVICE_PERMISSION_ERROR');
  assert.equal(failureDetails(new Error('unknown'), 'capture').code,'CAPTURE_FAILED');
});
