import { readFileSync } from 'node:fs';
import { parse } from './asm.mjs';
import { dissect } from './program.mjs';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const X=4965661367192848881n; // BN254 seed
const inv2=(P+1n)/2n;
const sixx2=6n*X*X;
const toLE=(x,n)=>{const o=Buffer.alloc(n);for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;}return o;};
const bytes=Uint8Array.from(Buffer.from(readFileSync('./optimized-twist-5782.hex','utf8').trim(),'hex'));
const d=dissect(bytes);
// tally all >=20B constants and their occurrence count + byte value
const tally=new Map();
const addOps=(ops,loc)=>{for(const o of ops){if(o.data&&o.data.length>=20){const h=Buffer.from(o.data).toString('hex');const e=tally.get(h)||{cnt:0,len:o.data.length,locs:[]};e.cnt++;e.locs.push(loc);tally.set(h,e);}}};
for(const id of d.order)addOps(parse(d.bodies.get(id)),'def#'+id);
addOps(d.mainOps,'MAIN');
const targets={inv2:toLE(inv2,32).toString('hex'),sixx2_le:null};
// sixx2 may be pushed as minimal-length LE. compute minimal bytes
function minLE(x){let bytes=[];let v=x;while(v>0n){bytes.push(Number(v&0xffn));v>>=8n;}if(bytes.length===0)bytes=[0];if(bytes[bytes.length-1]&0x80)bytes.push(0);return Buffer.from(bytes).toString('hex');}
console.log('inv2 value hex(LE32):',targets.inv2);
console.log('sixx2 =',sixx2.toString(),'minimal LE hex:',minLE(sixx2));
console.log('x =',X.toString(),'minimal LE hex:',minLE(X));
console.log('--- all >=20B constants, sorted by cnt*len ---');
const ents=[...tally.entries()].sort((a,b)=>(b[1].cnt*b[1].len)-(a[1].cnt*a[1].len));
for(const [h,e] of ents){
  let tag='';
  if(h===targets.inv2)tag=' <== inv2';
  const val=BigInt('0x'+Buffer.from(h,'hex').reverse().toString('hex'));
  if(val===P)tag=' <== p(should be gone!)';
  console.log('cnt',e.cnt,'len',e.len,'total',e.cnt*e.len,tag,'  '+h.slice(0,24)+'...');
}
// search for sixx2 and x as any-length pushes
console.log('--- scan for x / 6x^2 as any-length pushes ---');
const scan=new Map();
const addAll=(ops,loc)=>{for(const o of ops){if(o.data){const v=BigInt('0x'+(Buffer.from(o.data).reverse().toString('hex')||'0'));if(v===X||v===sixx2||v===inv2){const k=v===X?'x':v===sixx2?'6x^2':'inv2';scan.set(k,(scan.get(k)||0)+1);}}}};
for(const id of d.order)addAll(parse(d.bodies.get(id)),'def#'+id);
addAll(d.mainOps,'MAIN');
console.log([...scan.entries()]);
