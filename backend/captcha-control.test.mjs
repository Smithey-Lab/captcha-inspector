import test from 'node:test';
import assert from 'node:assert/strict';
import {withAutomation} from './captcha/control.mjs';

test('automation returns control after success and failures, including failed enable',async()=>{
  for(const failure of ['none','enable','operation']){
    const calls=[];
    const run=()=>withAutomation(async state=>{calls.push(state);if(failure==='enable'&&state==='ENABLED')throw Error('enable failed');},async()=>{calls.push('operation');if(failure==='operation')throw Error('operation failed');return 'report';});
    if(failure==='none')assert.equal(await run(),'report');else await assert.rejects(run);
    assert.deepEqual(calls,failure==='enable'?['ENABLED','DISABLED']:['ENABLED','operation','DISABLED']);
  }
});
test('failed handover cannot report a successful interactive operation',async()=>{
  await assert.rejects(()=>withAutomation(async state=>{if(state==='DISABLED')throw Error('handover failed');},async()=> 'report'),/handover failed/);
});
