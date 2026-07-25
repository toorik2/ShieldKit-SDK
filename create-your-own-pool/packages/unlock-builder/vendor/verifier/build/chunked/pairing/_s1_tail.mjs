// S1: Fiat-Shamir RLC of the residue-tail equality checks. Replaces the 12 (c*cInv==ONE) + 12
// (lhs==rhs) per-limb modP requires with two Sigma rho^i checks; rho = hash(committed fF,c,cInv,w).
// Soundness: if any limb differs, the degree<=11 poly in rho vanishes with prob <= 11/P (per group),
// and rho is the hash of the checked values (grinding a root needs ~P/11 hashes) -> negligible.
import { writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pairsFor, vec, singlePairMiller, decl, covIn, commitBin, CATEGORY, TARGET_UNLOCK, compileFileBytecode } from './_millermath.mjs';
import { millerBatchOpsAffine, millerFusedOpsAffine } from './_affmath.mjs';
import { residueWitness, fp12limbsOf, COSET27 } from './_residuemath.mjs';
import { encodeDataPush, bigIntToVmNumber, numberToBinUint16LE, createVirtualMachineBch2026, encodeLockingBytecodeP2sh32, hash256, binToHex } from '@bitauth/libauth';
const here = dirname(fileURLToPath(import.meta.url)); const GEN = join(here,'generated');
const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
const red=(x)=>((BigInt(x)%P)+P)%P;
const LIB='../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const inputs = vec.publicInputs.map(BigInt);
const pairs = pairsFor(inputs);
const { boundary: fRaw } = millerBatchOpsAffine(pairs);
const { c:cW, cInv:ciW, w:wW } = residueWitness(fRaw);
const fused = millerFusedOpsAffine(pairs, cW, ciW, singlePairMiller);
const tailState36 = [...fp12limbsOf(fused.boundary), ...fp12limbsOf(cW), ...fp12limbsOf(ciW)].map(red);
const wLimbs = fp12limbsOf(wW).map(red);
const ROOT27L = fp12limbsOf(COSET27[1]).map(String), ROOT27_2L=fp12limbsOf(COSET27[2]).map(String);
const ONE_L=['1','0','0','0','0','0','0','0','0','0','0','0'];
const matchVec=(names,lits)=>'('+names.map((n,i)=>`${n} == ${lits[i]}`).join(' && ')+')';
const fFn=Array.from({length:12},(_,i)=>`fF${i}`),cN=Array.from({length:12},(_,i)=>`c${i}`),ciN=Array.from({length:12},(_,i)=>`ci${i}`),wN=Array.from({length:12},(_,i)=>`w${i}`);
const COMMIT=[...fFn,...cN,...ciN];
// Horner RLC of (x_i - y_i): acc = ((...(d0*rho + d1)*rho + d2)...). Reduce every step to keep narrow.
function horner(diffs){ // diffs = array of cash int-exprs (may be negative reps)
  let e = diffs[0];
  for(let i=1;i<diffs.length;i++) e = `((${e}) * rho + (${diffs[i]}))`;
  return e;
}
function tailRLC(){
  const L=[];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${LIB}";`);
  L.push('contract ResidueTailRLC() {');
  L.push(`    function spend(${decl([...COMMIT,...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT));
  L.push(`        int P = ${Pstr};`);
  // canonical c (kept: range checks, not RLC-able)
  L.push('        '+cN.map(n=>`require(${n} < P);`).join(' '));
  // FS challenge rho: bind committed(fF,c,cInv) via the input nftCommitment + witness w. 32B hash -> int.
  L.push(`        int rho = int(hash256(tx.inputs[this.activeInputIndex].nftCommitment + ${wN.map(n=>`toPaddedBytes(${n},40)`).reduce((a,b)=>`${a} + ${b}`)})) % P;`);
  // c * cInv == ONE  (RLC over 12 limbs of p_i - ONE_i)
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`p${i}`))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  const dCC = Array.from({length:12},(_,i)=> ONE_L[i]==='0'?`p${i}`:`(p${i} - ${ONE_L[i]})`);
  L.push(`        require(${horner(dCC)} % P == 0);`);
  // w in coset (kept: 3-way membership, not an equality-vector RLC target)
  L.push(`        require(${matchVec(wN,ONE_L)} || ${matchVec(wN,ROOT27L)} || ${matchVec(wN,ROOT27_2L)});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`cq${i}`))}) = fp12Frob1(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`cqq${i}`))}) = fp12Frob2(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`cqqq${i}`))}) = fp12Frob3(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`t${i}`))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`lhs${i}`))}) = fp12Mul(${Array.from({length:12},(_,i)=>`t${i}`).join(',')}, ${Array.from({length:12},(_,i)=>`cqq${i}`).join(',')});`);
  L.push(`        (${decl(Array.from({length:12},(_,i)=>`rhs${i}`))}) = fp12Mul(${Array.from({length:12},(_,i)=>`cq${i}`).join(',')}, ${Array.from({length:12},(_,i)=>`cqqq${i}`).join(',')});`);
  // verdict lhs==rhs (RLC over 12 limbs of lhs_i - rhs_i)
  const dLR = Array.from({length:12},(_,i)=>`(lhs${i} - rhs${i})`);
  L.push(`        require(${horner(dLR)} % P == 0);`);
  L.push('    }');
  L.push('}');
  return L.join('\n')+'\n';
}
// measure with the deployed P2SH byte convention (copy of unified measureChunk for terminal)
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padBytes=(total)=>{const b=Math.max(2,total);const n=b<=76?b-1:b<=257?b-2:b-3;return encodeDataPush(new Uint8Array(n));};
const p2shSpk=(r)=>encodeLockingBytecodeP2sh32(hash256(r));
function measureTail(src){
  const probe=join(GEN,'_s1tail.cash'); writeFileSync(probe,src);
  let redeem; try{redeem=Uint8Array.from([...compileFileBytecode(probe)]);}catch(e){return{err:String(e?.message??e).slice(0,160)};}
  const rpush=encodeDataPush(redeem), locking=p2shSpk(redeem), tail=rpush.length;
  const inCommit=commitBin(tailState36.map(BigInt));
  const pushed=[...tailState36,...wLimbs];
  const argb=Uint8Array.from([...pushed].reverse().flatMap(c=>[...pushInt(c)]));
  const mk=(t)=>{const pad=padBytes(t-argb.length-tail);return Uint8Array.from([...pad,...argb,...rpush]);};
  const tok=(c)=>({amount:0n,category:CATEGORY,nft:{capability:'mutable',commitment:c}});
  const ev=(unlock)=>{const prog={inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(inCommit)}],
    transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlock}],outputs:[{lockingBytecode:Uint8Array.from([0x6a]),valueSatoshis:1000n}],locktime:0}};
    const st=realVm.evaluate(prog);const top=st.stack[st.stack.length-1];return{accepted:st.error===undefined&&st.stack.length===1&&top!==undefined&&top.length===1&&top[0]===1,op:st.metrics.operationCost,err:st.error};};
  // binary search minimal unlock
  let lo=argb.length+tail+2,hi=TARGET_UNLOCK;
  const hiR=ev(mk(hi)); if(!hiR.accepted) return {err:'hi reject: '+hiR.err, op:hiR.op};
  while(lo<hi){const mid=(lo+hi)>>1;if(ev(mk(mid)).accepted)hi=mid;else lo=mid+1;}
  const r=ev(mk(hi));
  return {lock:locking.length, unlock:mk(hi).length, op:r.op, accepted:r.accepted, total:locking.length+mk(hi).length};
}
const m=tailRLC();
const res=measureTail(m);
console.log('S1 RLC tail:', res.err||JSON.stringify(res));
console.log('baseline tail total = 4321 (lock 35 + unlock 4286)');
if(res.total) console.log('S1 net =', res.total-4321, 'B (negative=saving)');
