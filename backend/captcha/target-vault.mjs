import {createHash,createCipheriv,createDecipheriv,randomBytes} from 'node:crypto';
// The bearer token remains with the visitor; a database read cannot recover URLs.
const keyFor=token=>{
  if(!/^[a-f0-9]{64}$/.test(token))throw new Error('Invalid session token');
  return createHash('sha256').update('smithey-lab/captcha-target/v1\0').update(Buffer.from(token,'hex')).digest();
};
export function sealTarget(target,token,recordKey){
  const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',keyFor(token),iv);
  cipher.setAAD(Buffer.from(recordKey));
  const ciphertext=Buffer.concat([cipher.update(target,'utf8'),cipher.final()]);
  return {v:1,iv:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),data:ciphertext.toString('base64')};
}
export function openTarget(value,token,recordKey){
  if(!value||value.v!==1||typeof value.data!=='string'||value.data.length>12000)throw new Error('Invalid encrypted target');
  const iv=Buffer.from(value.iv,'base64');
  if(iv.length!==12)throw new Error('Invalid encrypted target');
  const decipher=createDecipheriv('aes-256-gcm',keyFor(token),iv,{authTagLength:16});
  decipher.setAAD(Buffer.from(recordKey));
  decipher.setAuthTag(Buffer.from(value.tag,'base64'));
  return Buffer.concat([decipher.update(Buffer.from(value.data,'base64')),decipher.final()]).toString('utf8');
}
