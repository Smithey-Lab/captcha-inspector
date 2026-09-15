import {test} from 'node:test';
import assert from 'node:assert/strict';
import {shouldBlockViewerEvent,installViewerProtection,hostChange,readableReport} from '../src/captcha-protection.js';
test('clipboard gestures are blocked across keyboard platforms and context-menu events',()=>{
  for(const type of ['copy','cut','paste','drop','dragover','dragstart'])assert.equal(shouldBlockViewerEvent({type}),true);
  for(const event of [{key:'v',ctrlKey:true},{key:'C',metaKey:true},{key:'x',ctrlKey:true},{key:'Insert',shiftKey:true},{key:'Insert',ctrlKey:true},{key:'Delete',shiftKey:true}])assert.equal(shouldBlockViewerEvent({type:'keydown',...event}),true);
  assert.equal(shouldBlockViewerEvent({type:'keydown',key:'v'}),false);
  assert.equal(shouldBlockViewerEvent({type:'click'}),false);
});
test('view-only blocks input while preserving focus escape and key release',()=>{
  for(const type of ['click','wheel','pointerdown','touchstart','keydown'])assert.equal(shouldBlockViewerEvent({type,key:'a'},true),true);
  for(const key of ['Tab','Escape'])assert.equal(shouldBlockViewerEvent({type:'keydown',key},true),false);
  assert.equal(shouldBlockViewerEvent({type:'keyup',key:'Shift'},true),false);
});
test('protection is scoped to viewer, stops propagation and never reads clipboard payload',()=>{
  const listeners=new Map(),viewer={},input={},notices=[];
  const dispose=installViewerProtection({root:{contains:target=>target===viewer},notice:message=>notices.push(message),isViewOnly:()=>false,eventRoot:{addEventListener:(type,fn)=>listeners.set(type,fn),removeEventListener:type=>listeners.delete(type)}});
  let prevented=0,stopped=0;
  const e={type:'paste',target:input,preventDefault(){prevented++;},stopImmediatePropagation(){stopped++;},get clipboardData(){throw new Error('Must never inspect clipboard');}};
  listeners.get('paste')(e);assert.equal(prevented,0);e.target=viewer;listeners.get('paste')(e);assert.equal(prevented,1);assert.equal(stopped,1);assert.equal(notices.length,1);dispose();assert.equal(listeners.size,0);
});
test('host notices compare parsed hosts and tolerate missing/blank/error URLs',()=>{
  assert.deepEqual(hostChange('https://example.com/path','https://other.com/'),{from:'example.com',to:'other.com'});
  assert.equal(hostChange('https://example.com/a','https://example.com/b'),null);
  assert.equal(hostChange('https://example.com','about:blank'),null);
  assert.equal(hostChange(undefined,undefined),null);
});
test('readable export is text with defanged web addresses and no session credentials',()=>{
  const result=readableReport({verdict:'Review',requestedUrl:'https://example.com',url:'http://other.com',token:'never-export',liveUrl:'https://private-session',findings:[{title:'Clipboard',description:'Review',source:'script',evidence:'https://example.com/payload'}]});
  assert.match(result,/hxxps:\/\/example.com/);assert.doesNotMatch(result,/https?:\/\/|never-export|private-session/);
});
