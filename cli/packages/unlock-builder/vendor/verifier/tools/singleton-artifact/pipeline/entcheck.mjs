import {readFileSync} from 'node:fs';
import zlib from 'node:zlib';
import {dissect} from './program.mjs';
const hex=readFileSync('optimized-full-5728.hex','utf8').trim();
const bytes=Uint8Array.from(Buffer.from(hex,'hex'));
const d=dissect(bytes);
let parts=[];
for(const id of d.order) parts.push(Buffer.from(d.bodies.get(id)));
const bodies=Buffer.concat(parts);
const gz=zlib.gzipSync(bodies,{level:9}).length;
const br=zlib.brotliCompressSync(bodies).length;
const f=new Array(256).fill(0); for(const b of bodies) f[b]++;
let H0=0; for(const c of f){ if(c){const p=c/bodies.length; H0-=p*Math.log2(p);} }
console.log('body bytes:',bodies.length,'gzip-9:',gz,'brotli:',br,'H0 b/byte:',H0.toFixed(3),'H0-floor B:',Math.round(H0*bodies.length/8));
