import {lstat,readdir,rm} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
const generated=new Set(['dist','src/assets/dcv','src/coding-studio']);
export async function cleanGenerated(root,name){
 if(!generated.has(name))throw new Error('Refusing to remove a non-generated directory');
 const base=resolve(root),target=resolve(base,name),rel=relative(base,target);
 if(!rel||rel.startsWith('..')||resolve(target)===base)throw new Error('Unsafe cleanup path');
 // Reject junctions/symlinks in every ancestor before any recursive removal.
 let current=base;
 for(const part of rel.split(sep)){
  current=resolve(current,part);
  const stat=await lstat(current).catch(e=>{if(e.code!=='ENOENT')throw e;return null;});
  if(stat?.isSymbolicLink())throw new Error('Refusing cleanup through a symbolic link');
 }
 await rm(target,{recursive:true,force:true});
}
export async function publicFiles(root,prefix=''){
 const result=[];
 for(const e of await readdir(resolve(root,prefix),{withFileTypes:true})){
  const name=prefix+e.name;
  if(e.isSymbolicLink()||e.name.startsWith('.')||e.name==='node_modules')throw new Error(`Non-public entry in build: ${name}`);
  if(e.isDirectory())result.push(...await publicFiles(root,name+'/'));
  else if(!/\.(?:html|js|mjs|css|json|xml|txt|svg|png|jpg|jpeg|webp|gif|ico|woff2?|ttf|wasm|mp4|webm)$/i.test(name))throw new Error(`Unapproved public file type: ${name}`);
  else result.push(name);
 }
 return result.sort();
}
