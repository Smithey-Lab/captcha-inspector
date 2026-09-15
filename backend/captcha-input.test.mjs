import test from 'node:test';
import assert from 'node:assert/strict';
import {inputReadiness,viewerAssetBase} from '../src/captcha-input.js';
test('decoder assets use an absolute URL independent of public or member route',()=>{
  for(const path of ['/tools/captcha-inspector/','/app/captcha-inspector/','/']){
    const page=new URL(path,'https://example.com');
    const base=viewerAssetBase(page.origin);
    assert.equal(base,'https://example.com/assets/dcv');
    assert.equal(new URL(base+'/dcv/lz4decoder-worker.js',page).pathname,'/assets/dcv/dcv/lz4decoder-worker.js');
  }
});
test('late feature notifications update readiness and expired connections stay silent',async()=>{
  let ready=false,current=true;const messages=[];
  const observer=inputReadiness(text=>messages.push(text),()=>current);
  observer.changed();
  await observer.attach({queryFeature:async()=>{if(!ready)throw Error('not notified');return {enabled:true};}});
  assert.match(messages.at(-1),/waiting/);
  ready=true;observer.changed();await new Promise(resolve=>setImmediate(resolve));
  assert.match(messages.at(-1),/Live controls ready/);
  const count=messages.length;current=false;observer.changed();await new Promise(resolve=>setImmediate(resolve));assert.equal(messages.length,count);
});
