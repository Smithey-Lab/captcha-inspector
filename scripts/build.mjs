import {cp,mkdir,readFile} from 'node:fs/promises';
import {cleanGenerated,publicFiles} from './public-files.mjs';
for(const directory of ['dist','src/assets/dcv'])await cleanGenerated(process.cwd(),directory);
await mkdir('src/assets',{recursive:true});await cp('node_modules/bedrock-agentcore/dist/src/tools/browser/live-view/nice-dcv-web-client-sdk/dcvjs-umd','src/assets/dcv',{recursive:true,filter:path=>!path.endsWith('README.md')});
await mkdir('dist',{recursive:true});await cp('src','dist',{recursive:true});const html=await readFile('dist/index.html','utf8');for(const match of html.matchAll(/(?:src|href)="(\/[^"#]+)"/g))await readFile('dist'+match[1]);console.log('Built standalone frontend; no AWS calls were made.');
await publicFiles('dist');
