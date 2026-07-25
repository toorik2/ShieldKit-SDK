// STRUCTURAL LEVER (c): cross-body const-sharing of the BN254 prime p.
// Add a 0-in/1-out provider body at free id 13 (push p), rewrite every raw 32B p
// literal push (in bodies + main) to `<13> INVOKE` (OP_13 0x8a = 2B).
// Gates: FULL round-trip byte-exact (dissect->decompile->recompile==bytes, all bodies+main)
//        + per-body differential mod-vs-crown on random Fp (bit-identical outputs).
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dissect, probeArity, runSubroutine, decompileProgram, recompileProgram, rebuild } from './program.mjs';
import { serialize, parse } from './asm.mjs';

const H='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/';
const OUT='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/pipeline-sub6k/singleton-constshare.hex';
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const DEFINE=0x89, INVOKE=0x8a, PROVID=13;
const crownBytes=Uint8Array.from(Buffer.from(readFileSync(H+'singleton-5835-locking5476-foldcomplete.hex','utf8').trim(),'hex'));
const dc=dissect(crownBytes);

// canonical minimal p push data (VM-number / raw LE 32B, +sign pad if needed)
let b=[]; { let n=P; while(n>0n){b.push(Number(n&255n));n>>=8n;} if(b[b.length-1]&0x80)b.push(0); }
const pData=Uint8Array.from(b);
const pHex=Buffer.from(pData).toString('hex');
console.log(`p as ${pData.length}B LE push: ${pHex.slice(0,16)}...`);

// scan every body + main for pushes whose data === p
const eq=(u,v)=>u&&v&&u.length===v.length&&u.every((x,i)=>x===v[i]);
let siteBodies=[], siteMain=0;
for(const id of dc.order){ const n=parse(dc.bodies.get(id)).filter(o=>eq(o.data,pData)).length; if(n) siteBodies.push([id,n]); }
siteMain=parse(serialize(dc.mainOps)).filter(o=>eq(o.data,pData)).length;
const totalSites=siteBodies.reduce((a,[,n])=>a+n,0)+siteMain;
console.log('p-literal sites: bodies', siteBodies.map(([i,n])=>`def#${i}x${n}`).join(' '), '| main x'+siteMain, '| TOTAL', totalSites);

// rewrite helper: replace each p push with [OP_13, INVOKE]
const rewrite=(ops)=>{ const out=[]; for(const o of ops){ if(eq(o.data,pData)){ out.push({op:0x50+PROVID}); out.push({op:INVOKE}); } else out.push(o); } return out; };

// build modified program bytes
const provBody=serialize([{op:0,data:pData}]);           // push p  (the provider body)
const idp=(id)=> id>=1&&id<=16 ? [{op:0x50+id}] : [{op:0,data:Uint8Array.from([id])}];
let prog=[];
prog.push({op:0,data:provBody}, ...idp(PROVID), {op:DEFINE});   // provider def-record at id 13
for(const r of dc.defRecs){
  const body = serialize(rewrite(parse(dc.bodies.get(r.id))));
  prog.push({op:0,data:body}); prog.push(r.idRec); prog.push(r.defRec);
}
for(const o of rewrite(dc.mainOps)) prog.push(o);
const modBytes=serialize(prog);
console.log(`\ncrown ${crownBytes.length}B -> modified ${modBytes.length}B  (delta ${modBytes.length-crownBytes.length})`);

const dm=dissect(modBytes);
console.log(`modified bodies: ${dm.order.length} (has #13: ${dm.order.includes(PROVID)})`);

// ============ GATE 1: FULL ROUND-TRIP byte-exact ============
console.time('probeArity(mod)');
const arity=probeArity(dm);
console.timeEnd('probeArity(mod)');
console.log('arity #13:', JSON.stringify(arity[PROVID]));
const ir=decompileProgram(dm, arity, 10);
const rt=recompileProgram(dm, ir, arity);
const bodiesExact=rt.perBody.filter(x=>x.exact).length;
const fullExact=Buffer.from(rt.bytes).equals(Buffer.from(modBytes));
console.log(`\n== ROUND-TRIP == bodies ${bodiesExact}/${dm.order.length} exact | main ${rt.mainExact} | FULL ${fullExact}`);
if(!fullExact) console.log('  NON-EXACT:', rt.perBody.filter(x=>!x.exact).map(x=>`def#${x.id}(${x.origLen}->${x.recLen})`).join(', '), 'mainRec',rt.mainRecLen,'vs',rt.mainOrigLen);

// ============ GATE 2: per-body differential mod-vs-crown ============
const rng=(s)=>{ let x=BigInt(s)*6364136223846793005n+1442695040888963407n; return ()=>{ x=(x*6364136223846793005n+1442695040888963407n)&((1n<<64n)-1n); let z=x; z=(z^(z>>30n))*0xbf58476d1ce4e5b9n&((1n<<64n)-1n); z=(z^(z>>27n))*0x94d049bb133111ebn&((1n<<64n)-1n); return (z^(z>>31n))&((1n<<64n)-1n); }; };
const randFp=(r)=>{ let v=0n; for(let i=0;i<4;i++) v=(v<<64n)|r(); return v%P; };
const eqS=(a,b)=>a.length===b.length&&a.every((x,i)=>x===b[i]);
const NTRIAL=12;
let diffPass=0, diffFail=[], diffTotal=0;
for(const id of dc.order){   // every crown body
  diffTotal++;
  let clean=0, match=0, bad=0;
  for(let s=0;s<NTRIAL;s++){
    const r=rng(s*1009+id*7+1);
    const inputs=Array.from({length:arity[id]?arity[id].in:0},()=>randFp(r));
    const r0=runSubroutine(dc,id,inputs);      // crown
    const r1=runSubroutine(dm,id,inputs);      // modified
    if(r0.error){ if(r1.error) continue; else {bad++; continue;} }
    clean++;
    if(!r1.error && eqS(r0.stack,r1.stack)) match++; else bad++;
  }
  if(bad>0){ diffFail.push(id); }
  else diffPass++;
}
// provider #13 sanity: invoke with 0 args returns exactly p
const rp=runSubroutine(dm, PROVID, []);
const provOk = !rp.error && rp.stack.length===1 && rp.stack[0]===P;
console.log(`\n== DIFFERENTIAL == mod-vs-crown ${diffPass}/${diffTotal} bodies bit-identical` + (diffFail.length?` | FAIL def#${diffFail.join(', def#')}`:''));
console.log(`   provider #13 invoke(0)->p : ${provOk}  (got ${rp.stack.map(String).slice(0,1)})`);

const PASS = fullExact && bodiesExact===dm.order.length && rt.mainExact && diffFail.length===0 && provOk;
if(PASS){ writeFileSync(OUT, Buffer.from(modBytes).toString('hex')+'\n'); const sha=createHash('sha256').update(Buffer.from(modBytes)).digest('hex'); console.log(`\nARTIFACT ${OUT}\nSHA256 ${sha}\nlocking ${modBytes.length}B  score ${modBytes.length+359}`); }
console.log(`\nGATE: ${PASS?'PASS':'FAIL'}`);
process.exit(PASS?0:1);
