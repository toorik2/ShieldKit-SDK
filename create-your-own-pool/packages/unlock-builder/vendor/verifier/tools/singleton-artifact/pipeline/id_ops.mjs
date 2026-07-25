import { readFileSync } from 'node:fs';
import { dissect, runSubroutine } from './program.mjs';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const bytes=Uint8Array.from(Buffer.from(readFileSync('./optimized-pooled-5892.hex','utf8').trim(),'hex'));
const d=dissect(bytes); const arity=JSON.parse(readFileSync('./arity.json','utf8'));
const a=987654321098765n%P, b=123456789012345n%P;
const ops={add:(a+b)%P, sub:((a-b)%P+P)%P, subrev:((b-a)%P+P)%P, mul:(a*b)%P};
for(const id of [1,2,3,4,5]){ const r=runSubroutine(d,id,arity[String(id)].in===2?[a,b]:[a]);
  if(r.error){console.log('def#'+id,'ERR',String(r.error).slice(0,60));continue;}
  const v=r.stack.length===1?r.stack[0]:r.stack.map(String).join(',');
  let name='?'; for(const[k,val]of Object.entries(ops))if(r.stack.length===1&&r.stack[0]===val)name=k;
  if(r.stack.length===1&&r.stack[0]===(a*a)%P)name='square(a)';
  console.log('def#'+id,'->',name,'raw',String(v).slice(0,50));
}
