import { readFileSync } from 'node:fs';
import { dissect, runSubroutine } from './program.mjs';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function inv(a,m){let[or,r]=[((a%m)+m)%m,m];let[os,s]=[1n,0n];while(r){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}return((os%m)+m)%m;}
const bytes=Uint8Array.from(Buffer.from(readFileSync('./optimized-pooled-5892.hex','utf8').trim(),'hex'));
const d=dissect(bytes); const arity=JSON.parse(readFileSync('./arity.json','utf8'));
const tests=[123456789012345678901234567890n%P, 98765432109876543210n%P, (P-2n), 7777777777777777777777n%P];
for(const id of d.order){ const a=arity[String(id)]; if(!a||a.in!==1||a.out!==1)continue;
  let ok=true,note='';
  for(const t of tests){ const r=runSubroutine(d,id,[t]); if(r.error){ok=false;note='ERR '+r.error;break;} if(r.stack.length!==1||r.stack[0]!==inv(t,P)){ok=false;note='on t: got '+r.stack.map(String)+' want inv='+inv(t,P);break;} }
  console.log('def#'+id, ok?'== inverseFp':('!= inverseFp; '+note.slice(0,80)));
}
