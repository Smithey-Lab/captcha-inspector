import test from 'node:test';
import assert from 'node:assert/strict';
import {addressSummary,microsoftRedirect,collectBrowserEvidence,browserFindings,hasLoadedEvidence} from './captcha/browser-evidence.mjs';
const doc=(scheme,extra={})=>({scheme,origin:'https://example.com',captured:true,visibleContent:true,...extra});
test('browser-generated credential forms are flagged across blob, data and srcdoc documents',()=>{
 for(const scheme of ['blob:','data:','about:']){
  const e={documents:[doc(scheme,{passwordField:true})]};assert.equal(browserFindings(e).suspicious,true);
  assert.equal(hasLoadedEvidence({url:'blob:https://example.com/id',text:''},e),true);
 }
 assert.equal(browserFindings({documents:[doc('blob:',{emailField:true,loginLanguage:true})]}).suspicious,true);
});
test('blob previews, ordinary sign-in and standalone OAuth/worker evidence are not phishing verdicts',()=>{
 for(const e of [{documents:[doc('blob:')]},{documents:[doc('https:',{passwordField:true})]},{documents:[doc('blob:',{emailField:true})]},{documents:[doc('https:',{workerControlled:true})],microsoftRedirect:{origin:'https://login.microsoftonline.com',destinationOrigin:'https://teams.microsoft.com'}}])assert.equal(browserFindings(e).suspicious,false);
 assert.equal(hasLoadedEvidence({url:'about:blank',text:''},{documents:[]}),false);
});
test('address and OAuth evidence excludes credentials, paths, parameters and blob identifiers',()=>{
 assert.deepEqual(addressSummary('blob:https://example.com/private-id'),{scheme:'blob:',origin:'https://example.com'});
 const url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize?state=PRIVATE&redirect_uri='+encodeURIComponent('https://teams.microsoft.com/private?token=SECRET');
 assert.deepEqual(microsoftRedirect(url),{origin:'https://login.microsoftonline.com',destinationOrigin:'https://teams.microsoft.com'});
 assert.equal(microsoftRedirect(url.replace('login.microsoftonline.com','login.microsoftonline.com.evil.test')),null);
 assert.doesNotMatch(JSON.stringify(microsoftRedirect(url)),/PRIVATE|SECRET|private/);
});
test('collection is capped and failed frame reads do not erase other documents',async()=>{
 let calls=0;const frames=Array.from({length:10},(_,i)=>({url:()=>i?'blob:https://example.com/id':'https://example.com/path?secret=yes',evaluate:async()=>{calls++;if(i===1)throw Error('detached');return {passwordField:i===2,visibleContent:true};}}));
 const e=await collectBrowserEvidence({frames:()=>frames},{serviceWorkers:()=>[]},'https://example.com');
 assert.equal(calls,8);assert.equal(e.framesOmitted,2);assert.equal(e.framesFailed,1);assert.equal(browserFindings(e).suspicious,true);
 assert.doesNotMatch(JSON.stringify(e),/secret|\/path|\/id/);
});
