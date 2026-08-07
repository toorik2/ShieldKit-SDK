import { repoPath as vcRepoPath } from '#repo-paths';
import { readFileSync } from 'node:fs';
import { parse, serialize } from './asm.mjs';
import { dissect, runSubroutine } from './program.mjs';
import { globalCse, P } from './global_cse.mjs';
import { twistDerive, B2C0, B2C1 } from './twist_derive.mjs';
import { createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin } from '@bitauth/libauth';
const CANON='/tmp/claude-1000/-home-toorik-Projects-verifier-cash/fa6e3d58-5aaa-4eaf-bef3-80ed05b22fa9/scratchpad/expderiv-blob/optimized.hex';
const MP=vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json');
const arity=JSON.parse(readFileSync('./arity.json','utf8'));
const log=(...a)=>console.error('[stage]',...a);
const orig=Uint8Array.from(Buffer.from(readFileSync(CANON,'utf8').trim(),'hex'));
const {bytes:pooled,dropped}=globalCse(orig,{poolId:13});
const {bytes:twist,deriveId,hits}=twistDerive(pooled,{deriveId:15});
log('orig',orig.length,'pooled',pooled.length,'twist',twist.length,'twistDelta',pooled.length-twist.length,'hits',hits);
const R={origLen:orig.length,pooledLen:pooled.length,twistLen:twist.length,twistDelta:pooled.length-twist.length,deriveId,hits};

// GATE1 round-trip
const dt=dissect(twist); let rtOK=true; const rtN=[];
{ const re=serialize(parse(twist)); if(!Buffer.from(re).equals(Buffer.from(twist))){rtOK=false;rtN.push('reserialize');} }
if(!dt.order.includes(deriveId)){rtOK=false;rtN.push('derive missing');}
// no remaining raw b2 pushes anywhere
const toLE=(x,n)=>{const o=Buffer.alloc(n);for(let i=0;i<n;i++){o[i]=Number(x&0xffn);x>>=8n;}return o;};
const b0=Buffer.from(toLE(B2C0,32)).toString('hex'), b1=Buffer.from(toLE(B2C1,32)).toString('hex');
const th=Buffer.from(twist).toString('hex');
const rem0=(th.split(b0).length-1), rem1=(th.split(b1).length-1);
if(rem0!==0||rem1!==0){rtOK=false;rtN.push('residual b2 pushes '+rem0+'/'+rem1);}
R.roundtrip={ok:rtOK,notes:rtN,twistDefines:dt.order.length,residualB2c0:rem0,residualB2c1:rem1};
log('gate1',rtOK,'defines',dt.order.length,'residual',rem0,rem1);

// GATE2 per-subroutine differential orig vs twist
const rnd=(s)=>{let x=BigInt(s+7);for(let i=0;i<8;i++)x=(x*6364136223846793005n+1442695040888963407n)%P;return x;};
const dOrig=dissect(orig);
let pass=0,total=0; const fails=[];
for(const id of dOrig.order){ const a=arity[String(id)]; if(!a)continue;
  const tgt = dropped.includes(id)?14:id;   // dedup redirect def#15->def#14
  for(let t=0;t<3;t++){ const ins=Array.from({length:a.in},(_,i)=>rnd(i*101+id*7+t*1000));
    const ro=runSubroutine(dOrig,id,ins), rp=runSubroutine(dt,tgt,ins); total++;
    const so=ro.stack.map(String).join(','), sp=rp.stack.map(String).join(',');
    if(!ro.error&&!rp.error&&so===sp)pass++; else if(fails.length<8)fails.push({id,tgt,e:[String(ro.error),String(rp.error)],so:so.slice(0,30),sp:sp.slice(0,30)});
  }
}
// derive define correctness
const rd=runSubroutine(dt,deriveId,[]);
const deriveOK=!rd.error&&rd.stack.length===2&&rd.stack[0]===B2C1&&rd.stack[1]===B2C0;
R.subDifferential={pass,total,deriveOK,ok:pass===total&&deriveOK,fails};
log('gate2',pass+'/'+total,'deriveOK',deriveOK);

// GATE3 E2E
const HUGE=Number.MAX_SAFE_INTEGER;
const loose={...ConsensusBch2025,baseInstructionCost:100,maximumFunctionIdentifierLength:7,maximumMemorySlots:HUGE,maximumStandardLockingBytecodeLength:-1,maximumStandardUnlockingBytecodeLength:HUGE,maximumTokenCommitmentLength:128,operationCostBudgetPerByte:HUGE,maximumStackItemLength:HUGE,maximumVmNumberByteLength:HUGE,maximumStackDepth:HUGE,maximumControlStackDepth:HUGE,maximumBytecodeLength:HUGE,maximumOperationCount:HUGE};
const vm=createVirtualMachine(createInstructionSetBch2026(false,{consensus:loose,ripemd160,secp256k1,sha1,sha256}));
const runLock=(lock,unl)=>vm.verify(createTestAuthenticationProgramBch({lockingBytecode:lock,unlockingBytecode:hexToBin(unl),valueSatoshis:10000n}))===true;
const mp=JSON.parse(readFileSync(MP,'utf8')); const n=mp.proofs.length;
let ta=0,tr=0,diff=0,oa=0,or=0,i=0;
for(const p of mp.proofs){ const ov=runLock(orig,p.unlocking),oi=runLock(orig,p.invalidUnlocking);
  const tv=runLock(twist,p.unlocking),ti=runLock(twist,p.invalidUnlocking);
  if(ov)oa++; if(!oi)or++; if(tv)ta++; if(!ti)tr++; if(ov===tv&&oi===ti)diff++;
  log('proof',++i,'origAcc',ov,'origRej',!oi,'twAcc',tv,'twRej',!ti);
}
R.e2e={n,origAccept:oa,origReject:or,twistAccept:ta,twistReject:tr,differential:diff,ok:ta===n&&tr===n&&diff===n&&oa===n&&or===n};
R.GATE_PASS=R.roundtrip.ok&&R.subDifferential.ok&&R.e2e.ok;
R.score={locking:twist.length,witness:272,txOvhd:87,total:twist.length+272+87};
console.log(JSON.stringify(R,null,2));
