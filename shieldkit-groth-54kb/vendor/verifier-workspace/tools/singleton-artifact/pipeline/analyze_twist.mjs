import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect, runSubroutine } from './program.mjs';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function inv(a,m){let[or,r]=[((a%m)+m)%m,m];let[os,s]=[1n,0n];while(r){const q=or/r;[or,r]=[r,or-q*r];[os,s]=[s,os-q*s];}return((os%m)+m)%m;}
const toLE=(x,n)=>{const o=Buffer.alloc(n);for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;}return o;};
const i82=inv(82n,P);
const b2c0=(27n*i82)%P, b2c1=((P-3n)*i82)%P;
const b2c0LE=toLE(b2c0,32), b2c1LE=toLE(b2c1,32);
const eq=(a,b)=>Buffer.from(a).equals(Buffer.from(b));
const CANON='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/lever-stack-6167/optimized-pooled-5892.hex';
const bytes=Uint8Array.from(Buffer.from(readFileSync(CANON,'utf8').trim(),'hex'));
const d=dissect(bytes);
const arity=JSON.parse(readFileSync('./arity.json','utf8'));
// which bodies contain b2 pushes
for(const id of d.order){
  const ops=parse(d.bodies.get(id));
  let c0=0,c1=0;
  for(const o of ops){ if(o.data&&o.data.length===32){ if(eq(o.data,b2c0LE))c0++; if(eq(o.data,b2c1LE))c1++; } }
  if(c0||c1) console.log('def#'+id,'b2c0x'+c0,'b2c1x'+c1,'arity',JSON.stringify(arity[String(id)]),'bodyLen',d.bodies.get(id).length);
}
// main
{ const ops=parse(serialize(d.mainOps)); let c0=0,c1=0; for(const o of ops){if(o.data&&o.data.length===32){if(eq(o.data,b2c0LE))c0++;if(eq(o.data,b2c1LE))c1++;}} if(c0||c1)console.log('MAIN','b2c0x'+c0,'b2c1x'+c1);}
// identify inverseFp among 1->1 subroutines (and any)
console.log('--- searching inverseFp ---');
const tests=[2n,3n,7n,123456789n,P-2n];
for(const id of d.order){
  const a=arity[String(id)]; if(!a||a.in!==1||a.out!==1)continue;
  let ok=true;
  for(const t of tests){ const r=runSubroutine(d,id,[t]); if(r.error||r.stack.length!==1||r.stack[0]!==inv(t,P)){ok=false;break;} }
  if(ok) console.log('def#'+id,'IS inverseFp (1->1 modular inverse)');
  else {
    // report what it does on input 2
    const r=runSubroutine(d,id,[2n]);
    console.log('def#'+id,'(1->1) on 2 ->', r.error?('ERR '+r.error):r.stack.map(String).join(','));
  }
}
