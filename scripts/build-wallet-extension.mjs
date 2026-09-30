import {build} from 'esbuild';
import {mkdir,copyFile,readFile,writeFile} from 'node:fs/promises';
await mkdir('extension/dist',{recursive:true});
const icon='data:image/png;base64,'+(await readFile('web/static/favicon-32.png')).toString('base64');
for(const name of ['provider','content','worker','popup'])await build({entryPoints:[`extension/src/${name}.ts`],outfile:`extension/dist/${name}.js`,bundle:true,minify:false,format:name==='worker'||name==='popup'?'esm':'iife',target:'chrome120',define:{VAULT_ICON:JSON.stringify(icon)},legalComments:'none'});
for(const name of ['manifest.json','popup.html','popup.css'])await copyFile('extension/'+name,'extension/dist/'+name);
await copyFile('web/static/favicon-32.png','extension/dist/icon-32.png');await copyFile('web/static/icon-128.png','extension/dist/icon-128.png');
const manifest=JSON.parse(await readFile('extension/manifest.json','utf8'));const {createHash}=await import('node:crypto');const id=createHash('sha256').update(Buffer.from(manifest.key,'base64')).digest('hex').slice(0,32).replace(/[0-9a-f]/g,c=>String.fromCharCode(97+parseInt(c,16)));const source=await readFile('internal/browserwallet/native.go','utf8');if(!source.includes('"'+id+'"'))throw new Error('Native host and extension ID differ');
console.log('Built Chrome wallet',id);
