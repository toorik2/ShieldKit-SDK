// LeanBCH + libauth SECOND-ORACLE cross-check for the TRAJECTORY-FORGE lens.
// A P2SH32-wrapped contract runs ONE real affAdd (imported verbatim from _afflib.cash) with a
// WITNESSED slope lam, then REQUIRES the derived next point equals a committed target (tx,ty).
// scenario=honest : honest lam + honest target -> both VMs must ACCEPT.
// scenario=forge  : a STEERING lam' (lf^2 = target'.x + Rx + Qx) that DERIVES a chosen FALSE point,
//                   with the require-target set to that false point, so the ONLY gate that can
//                   reject is affAdd's internal slope check lam*(Rx-Qx)==Ry-Qy. Both VMs must REJECT.
// Emits wire tx+srcouts for xcheck.lean and prints libauth's verdict.
import { readFileSync, writeFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026, numberToBinUint16LE,
} from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const r=(x)=>((x%P)+P)%P;
const lib = readFileSync('variants/V3_millerres_lib.cash','utf8');
function extract(name){const s=lib.split('\n'),o=[];let p=false,d=0;for(const l of s){if(!p&&l.startsWith(`function ${name}(`))p=true;if(p){o.push(l);d+=(l.match(/\{/g)||[]).length-(l.match(/\}/g)||[]).length;if(d===0&&l.includes('}'))break;}}return o.join('\n');}
const need=['addFp','subFp','mulFp','fp2Add','fp2Sub','fp2Neg','fp2Mul','fp2Sqr','fp2Scale'];
const libtext=need.map(extract).join('\n')+'\n'+readFileSync('_afflib.cash','utf8');
const A=(x,y)=>Fp2.add(x,y),Sub=(x,y)=>Fp2.sub(x,y),M=(x,y)=>Fp2.mul(x,y),SQ=(x)=>Fp2.sqr(x);
const F2=(a,b)=>Fp2.fromBigTuple([r(a),r(b)]);
const scenario = process.env.SCENARIO ?? 'honest';

// R = 2Q, Q = pair0 twist point ; honest add R+Q
const Q=pairsFor(vec.publicInputs)[0].Q.toAffine();
const R2=pairsFor(vec.publicInputs)[0].Q.double().toAffine();
const t1=Sub(R2.x,Q.x),t0=Sub(R2.y,Q.y),lamHon=M(t0,Fp2.inv(t1));
const xnHon=Sub(Sub(SQ(lamHon),R2.x),Q.x), ynHon=Sub(M(lamHon,Sub(R2.x,Sub(Sub(SQ(lamHon),R2.x),Q.x))),R2.y);

let lam=lamHon, tx=xnHon, ty=ynHon, note='honest R+Q';
if (scenario==='forge'){
  // find a steerable FALSE target: scan dx until target.x+Rx+Qx is a QR
  let found=null;
  for(let dx=1n; dx<=8000n; dx++){
    const target=F2(r(xnHon.c0+dx),xnHon.c1);
    const need_l2=A(target,A(R2.x,Q.x));
    let lf; try{lf=Fp2.sqrt(need_l2);}catch(e){continue;}
    if(!(SQ(lf).c0===need_l2.c0&&SQ(lf).c1===need_l2.c1)) continue;
    const xnf=Sub(Sub(SQ(lf),R2.x),Q.x), ynf=Sub(M(lf,Sub(R2.x,xnf)),R2.y);
    if(xnf.c0===xnHon.c0&&xnf.c1===xnHon.c1) continue; // must be a genuinely false point
    found={lf,xnf,ynf,dx}; break;
  }
  if(!found){ console.log('no steerable false target found (all non-QR) — forge cannot even be attempted'); process.exit(0); }
  lam=found.lf; tx=found.xnf; ty=found.ynf; note=`STEERING lam' derives FALSE point (dx=${found.dx})`;
}

const consume='require(within(mulFp(c0a,0)+mulFp(c0b,0)+mulFp(c1a,0)+mulFp(c1b,0)+mulFp(c2a,0)+mulFp(c2b,0),0,2));';
const params=['Rxa','Rxb','Rya','Ryb','Qxa','Qxb','Qya','Qyb','la','lb'];
const body=`(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(Rxa,Rxb,Rya,Ryb,Qxa,Qxb,Qya,Qyb,la,lb);
 require(nxa==${tx.c0}); require(nxb==${tx.c1}); require(nya==${ty.c0}); require(nyb==${ty.c1});
 ${consume}`;
const srcCash=`pragma cashscript ^0.14.0;\ncontract T(){function spend(${params.map(n=>'int '+n).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
const redeem=Uint8Array.from(asmToBytecode(compileString(srcCash,{rescheduleStacks:true}).bytecode));
const rpush=encodeDataPush(redeem);
const locking=encodeLockingBytecodeP2sh32(hash256(redeem));

const argvals=[r(R2.x.c0),r(R2.x.c1),r(R2.y.c0),r(R2.y.c1),r(Q.x.c0),r(Q.x.c1),r(Q.y.c0),r(Q.y.c1),r(lam.c0),r(lam.c1)];
const pushInt=(n)=>encodeDataPush(bigIntToVmNumber(BigInt(n)));
const argb=Uint8Array.from([...argvals].reverse().flatMap(c=>[...pushInt(c)]));
const padPush=encodeDataPush(new Uint8Array(8));
const unlocking=Uint8Array.from([...padPush,...argb,...rpush]);

const program={inputIndex:0,
  sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n}],
  transaction:{version:2,
    inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlocking}],
    outputs:[{lockingBytecode:Uint8Array.from([0x6a]),valueSatoshis:1000n}], locktime:0}};
const st=realVm.evaluate(program);
const top=st.stack[st.stack.length-1];
const accepted=st.error===undefined&&st.stack.length===1&&top!==undefined&&top.length===1&&top[0]===1;
console.log(`[libauth] scenario=${scenario} (${note}) accepted=${accepted} opCost=${st.metrics.operationCost} err=${st.error??'none'}`);
writeFileSync('/tmp/xtraj_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xtraj_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
console.log('wrote /tmp/xtraj_tx.hex + /tmp/xtraj_srcouts.hex');
