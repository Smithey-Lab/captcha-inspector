import {chromium} from 'playwright-core';
import {createServer} from 'node:http';
import assert from 'node:assert/strict';
import {collectBrowserEvidence,browserFindings,hasLoadedEvidence} from '../backend/captcha/browser-evidence.mjs';
const payload='<h1>Microsoft 365 sign in</h1><form><input type="email" value="DO_NOT_COLLECT_EMAIL"><input type="password" value="DO_NOT_COLLECT_PASSWORD"></form>';
const server=createServer((req,res)=>{res.setHeader('content-type','text/html');res.end(req.url==='/normal'?payload:`<h1>Document preview</h1><iframe sandbox="allow-scripts" id="child"></iframe><script>child.src=URL.createObjectURL(new Blob([${JSON.stringify(payload)}],{type:'text/html'}));</script>`);}).listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
const browser=await chromium.launch({channel:process.env.BROWSER_CHANNEL||'msedge',headless:true});
try{const context=await browser.newContext(),page=await context.newPage();const base='http://127.0.0.1:'+server.address().port;
await page.goto(base+'/');await page.frameLocator('#child').locator('input[type=password]').waitFor();
const evidence=await collectBrowserEvidence(page,context,'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?redirect_uri=https%3A%2F%2Fteams.microsoft.com%2F');assert.equal(browserFindings(evidence).suspicious,true);assert.equal(evidence.framesFailed,0);assert.doesNotMatch(JSON.stringify(evidence),/DO_NOT_COLLECT/);
await page.evaluate(html=>{const frame=document.createElement('iframe');frame.sandbox='allow-scripts';frame.srcdoc=html;document.body.replaceChildren(frame);},payload);await page.frameLocator('iframe').locator('input[type=password]').waitFor();const sd=await collectBrowserEvidence(page,context,base);assert.equal(browserFindings(sd).suspicious,true);
await page.goto(base+'/normal');assert.equal(browserFindings(await collectBrowserEvidence(page,context,base)).suspicious,false);
await page.evaluate(html=>{location.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));},payload);await page.waitForURL(/^blob:/,{timeout:5000});await page.locator('input[type=password]').waitFor();const top=await collectBrowserEvidence(page,context,base);assert.equal(browserFindings(top).suspicious,true);assert.equal(hasLoadedEvidence({url:page.url(),text:''},top),true);
console.log('Local Chromium: opaque sandboxed blob login and top-level blob login detected; ordinary HTTP login not classified as phishing; no form values collected. No AWS sessions.');
}finally{await browser.close();server.close();}
