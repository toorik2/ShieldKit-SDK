// Standalone gate on the FINAL v2 artifact (foldhunt-locking.hex, 5476 B): round-trip
// byte-exact + per-subroutine differential vs the 3-fold crown (5613) bodies.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { dissect, runSubroutine, decompileProgram, recompileProgram } from './program.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const arity = JSON.parse(readFileSync(join(here, 'arity.json'), 'utf8'));
const crown = Uint8Array.from(Buffer.from(readFileSync(join(here,'singleton-richpeep-locking.hex'),'utf8').trim(),'hex')); // 5613 3-fold
const v2 = Uint8Array.from(Buffer.from(readFileSync(join(here,'foldhunt-locking.hex'),'utf8').trim(),'hex'));           // 5476
const sha=(b)=>createHash('sha256').update(Buffer.from(b)).digest('hex');
console.log(`v2 artifact ${v2.length} B  sha ${sha(v2)}`);
const dC = dissect(crown), dV = dissect(v2);
// GATE1 round-trip on v2
let RT=false;
try{ const ir=decompileProgram(dV,arity,10); const rt=recompileProgram(dV,ir,arity);
  const full=Buffer.from(rt.bytes).equals(Buffer.from(v2)); const be=rt.perBody.filter(b=>b.exact).length;
  console.log(`GATE1 round-trip: bodies ${be}/${dV.order.length} main ${rt.mainExact} FULL ${full}`);
  RT = full && be===dV.order.length && rt.mainExact;
}catch(e){ console.log('GATE1 decompile THREW '+e.message); }
// GATE2 differential: v2 body vs crown body, random Fp. override map = v2 bodies.
const ov=new Map(); for(const id of dV.order) ov.set(id, dV.bodies.get(id));
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
function rng(s){let x=BigInt(s+7);return()=>{x=(x*6364136223846793005n+1442695040888963407n)%P;return x;};}
const eq=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const N=10; const fails=[]; let pass=0;
for(const id of dC.order){
  let clean=0,mism=0;
  for(let s=0;s<N;s++){ const r=rng(s*131+id*17); const inp=Array.from({length:arity[id].in},()=>r()%P);
    const ro=runSubroutine(dC,id,inp); const rs=runSubroutine(dC,id,inp,new Map([[id,ov.get(id)]]));
    if(ro.error) continue; clean++; if(!(!rs.error&&eq(ro.stack,rs.stack))) mism++; }
  if(mism>0){fails.push(id);console.log(`  def#${id} FAIL ${mism}/${clean}`);}else pass++;
}
console.log(`GATE2 differential: ${pass}/${dC.order.length} bodies bit-identical`+(fails.length?` FAIL ${fails}`:''));
console.log(`OVERALL ${RT&&fails.length===0?'PASS':'FAIL'}`);
