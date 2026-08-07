import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect, runSubroutine } from './program.mjs';
import { globalCse } from './global_cse.mjs';
import { twistDerive, B2C0, B2C1 } from './twist_derive.mjs';
import { tailDerive, INV2, SIXX2 } from './tail_derive.mjs';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin } from '@bitauth/libauth';
const CANON='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/expderiv-blob/optimized.hex';
const MP=vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json');
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const arity=JSON.parse(readFileSync('./arity.json','utf8'));
const log=(...a)=>console.error('[tail]',...a);

const orig=Uint8Array.from(Buffer.from(readFileSync(CANON,'utf8').trim(),'hex'));
const {bytes:pooled,dropped}=globalCse(orig,{poolId:13});
const {bytes:twist}=twistDerive(pooled,{deriveId:15});
const {bytes:tail,inv2Hits,sixHits}=tailDerive(twist,{poolId:13,doInv2:true,do6x2:true});
log('lens orig',orig.length,'pooled',pooled.length,'twist',twist.length,'tail',tail.length,
    'tailDelta',twist.length-tail.length,'inv2Hits',inv2Hits,'sixHits',sixHits);

const R={origLen:orig.length,pooledLen:pooled.length,twistLen:twist.length,tailLen:tail.length,
  tailDelta:twist.length-tail.length,inv2Hits,sixHits};

// GATE0 faithful reassembly: no-op tail == twist byte-identical
const noop=tailDerive(twist,{doInv2:false,do6x2:false}).bytes;
R.reassemblyFaithful=Buffer.from(noop).equals(Buffer.from(twist));
log('gate0 reassemblyFaithful',R.reassemblyFaithful);

// GATE1 round-trip + no residual inv2 / 6x^2 pushes
const dt=dissect(tail); let rtOK=true; const rtN=[];
if(!Buffer.from(serialize(parse(tail))).equals(Buffer.from(tail))){rtOK=false;rtN.push('reserialize');}
const dtw=dissect(twist);
if(dt.order.length!==dtw.order.length){rtOK=false;rtN.push('define count changed '+dtw.order.length+'->'+dt.order.length);}
const toLE=(x,n)=>{const o=Buffer.alloc(n);let v=x;for(let i=0;i<n;i++){o[i]=Number(v&0xffn);v>>=8n;}return o;};
const minLE=(x)=>{const b=[];let v=x;while(v>0n){b.push(Number(v&0xffn));v>>=8n;}if(b[b.length-1]&0x80)b.push(0);return Buffer.from(b);};
const th=Buffer.from(tail).toString('hex');
const remInv2=th.split(toLE(INV2,32).toString('hex')).length-1;
const rem6=th.split(minLE(SIXX2).toString('hex')).length-1;
if(remInv2!==0){rtOK=false;rtN.push('residual inv2 '+remInv2);}
if(rem6!==0){rtOK=false;rtN.push('residual 6x2 '+rem6);}
R.roundtrip={ok:rtOK,notes:rtN,tailDefines:dt.order.length,residualInv2:remInv2,residual6x2:rem6};
log('gate1',rtOK,'defines',dt.order.length,'residInv2',remInv2,'resid6x2',rem6);

// GATE2 per-subroutine differential orig vs tail (dedup redirect 15->14)
const rnd=(s)=>{let x=BigInt(s+7);for(let i=0;i<8;i++)x=(x*6364136223846793005n+1442695040888963407n)%P;return x;};
const dOrig=dissect(orig);
let pass=0,total=0; const fails=[];
for(const id of dOrig.order){ const a=arity[String(id)]; if(!a)continue;
  const tgt=dropped.includes(id)?14:id;
  for(let t=0;t<3;t++){ const ins=Array.from({length:a.in},(_,i)=>rnd(i*101+id*7+t*1000));
    const ro=runSubroutine(dOrig,id,ins), rp=runSubroutine(dt,tgt,ins); total++;
    const so=ro.stack.map(String).join(','), sp=rp.stack.map(String).join(',');
    if(!ro.error&&!rp.error&&so===sp)pass++; else if(fails.length<8)fails.push({id,tgt,e:[String(ro.error),String(rp.error)],so:so.slice(0,40),sp:sp.slice(0,40)});
  }
}
// directly confirm def#17 derives inv2 correctly (spot): run def#17 orig vs tail on random, already covered; also assert p-derive value
R.subDifferential={pass,total,ok:pass===total,fails};
log('gate2',pass+'/'+total,'ok',pass===total);

// GATE3 E2E multiproof: accept valid, reject invalid, differential vs orig
const HUGE=Number.MAX_SAFE_INTEGER;
const loose={...ConsensusBch2025,baseInstructionCost:100,maximumFunctionIdentifierLength:7,maximumMemorySlots:HUGE,maximumStandardLockingBytecodeLength:-1,maximumStandardUnlockingBytecodeLength:HUGE,maximumTokenCommitmentLength:128,operationCostBudgetPerByte:HUGE,maximumStackItemLength:HUGE,maximumVmNumberByteLength:HUGE,maximumStackDepth:HUGE,maximumControlStackDepth:HUGE,maximumBytecodeLength:HUGE,maximumOperationCount:HUGE};
const vm=createVirtualMachine(createInstructionSetBch2026(false,{consensus:loose,ripemd160,secp256k1,sha1,sha256}));
const runLock=(lock,unl)=>vm.verify(createTestAuthenticationProgramBch({lockingBytecode:lock,unlockingBytecode:hexToBin(unl),valueSatoshis:10000n}))===true;
const mp=JSON.parse(readFileSync(MP,'utf8')); const n=mp.proofs.length;
let ta=0,tr=0,diff=0,oa=0,or=0,i=0;
for(const p of mp.proofs){ const ov=runLock(orig,p.unlocking),oi=runLock(orig,p.invalidUnlocking);
  const tv=runLock(tail,p.unlocking),ti=runLock(tail,p.invalidUnlocking);
  if(ov)oa++; if(!oi)or++; if(tv)ta++; if(!ti)tr++; if(ov===tv&&oi===ti)diff++;
  log('proof',++i,'origAcc',ov,'origRej',!oi,'tailAcc',tv,'tailRej',!ti);
}
R.e2e={n,origAccept:oa,origReject:or,tailAccept:ta,tailReject:tr,differential:diff,ok:ta===n&&tr===n&&diff===n&&oa===n&&or===n};
R.GATE_PASS=R.reassemblyFaithful&&R.roundtrip.ok&&R.subDifferential.ok&&R.e2e.ok;
R.score={locking:tail.length,witness:272,txOvhd:87,total:tail.length+272+87};
console.log(JSON.stringify(R,null,2));
