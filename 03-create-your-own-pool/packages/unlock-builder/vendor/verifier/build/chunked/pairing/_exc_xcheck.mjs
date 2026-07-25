// EXCEPTIONAL-CASE second-oracle cross-check (libauth + LeanBCH). A P2SH32 contract runs ONE affAdd
// (imported verbatim from _afflib.cash) on an EXCEPTIONAL input and requires nothing false; the only
// gate is affAdd's guard/slope check. Scenarios:
//   negQ : R = -Q  (Rx=Qx, Ry=-Qy  => R+Q = O, point at infinity) -> guard require(Rx!=Qx) must REJECT
//   posQ : R = +Q  (Rx=Qx, Ry= Qy) -> same guard must REJECT
//   honest: R=2Q,Q honest add -> ACCEPT
// Emits /tmp/xtraj_tx.hex + /tmp/xtraj_srcouts.hex for xcheck.lean; prints libauth verdict.
import { readFileSync, writeFileSync } from 'node:fs';
import { compileString, utils } from 'cashc';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';
import { bn254, Fp2, pairsFor, vec } from './_millermath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const r = (x) => ((x % P) + P) % P;
const lib = readFileSync('variants/V3_millerres_lib.cash', 'utf8');
function extract(name) { const s = lib.split('\n'), o = []; let p = false, d = 0; for (const l of s) { if (!p && l.startsWith(`function ${name}(`)) p = true; if (p) { o.push(l); d += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length; if (d === 0 && l.includes('}')) break; } } return o.join('\n'); }
const need = ['addFp', 'subFp', 'mulFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2Scale'];
const libtext = need.map(extract).join('\n') + '\n' + readFileSync('_afflib.cash', 'utf8');
const Sub = (x, y) => Fp2.sub(x, y), M = (x, y) => Fp2.mul(x, y), SQ = (x) => Fp2.sqr(x);
const scenario = process.env.SCENARIO ?? 'negQ';
const Q = pairsFor(vec.publicInputs)[0].Q.toAffine();
const R2 = pairsFor(vec.publicInputs)[0].Q.double().toAffine();

let Rx, Ry, lam, tx, ty, note;
if (scenario === 'honest') {
  const t1 = Sub(R2.x, Q.x), t0 = Sub(R2.y, Q.y); lam = M(t0, Fp2.inv(t1));
  const xn = Sub(Sub(SQ(lam), R2.x), Q.x), yn = Sub(M(lam, Sub(R2.x, xn)), R2.y);
  Rx = R2.x; Ry = R2.y; tx = xn; ty = yn; note = 'honest 2Q+Q';
} else if (scenario === 'negQ') {
  Rx = Q.x; Ry = Fp2.neg(Q.y); lam = Fp2.fromBigTuple([7n, 11n]); tx = Fp2.fromBigTuple([0n, 0n]); ty = Fp2.fromBigTuple([0n, 0n]); note = 'R=-Q => O (guard must reject)';
} else if (scenario === 'posQ') {
  Rx = Q.x; Ry = Q.y; lam = Fp2.fromBigTuple([7n, 11n]); tx = Fp2.fromBigTuple([0n, 0n]); ty = Fp2.fromBigTuple([0n, 0n]); note = 'R=+Q (guard must reject)';
}
const consume = 'require(within(mulFp(c0a,0)+mulFp(c0b,0)+mulFp(c1a,0)+mulFp(c1b,0)+mulFp(c2a,0)+mulFp(c2b,0),0,2));';
const params = ['Rxa', 'Rxb', 'Rya', 'Ryb', 'Qxa', 'Qxb', 'Qya', 'Qyb', 'la', 'lb'];
const body = `(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affAdd(Rxa,Rxb,Rya,Ryb,Qxa,Qxb,Qya,Qyb,la,lb);
 require(nxa==${tx.c0}); require(nxb==${tx.c1}); require(nya==${ty.c0}); require(nyb==${ty.c1});
 ${consume}`;
const srcCash = `pragma cashscript ^0.14.0;\ncontract T(){function spend(${params.map((n) => 'int ' + n).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
const redeem = Uint8Array.from(asmToBytecode(compileString(srcCash, { rescheduleStacks: true }).bytecode));
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const argvals = [r(Rx.c0), r(Rx.c1), r(Ry.c0), r(Ry.c1), r(Q.x.c0), r(Q.x.c1), r(Q.y.c0), r(Q.y.c1), r(lam.c0), r(lam.c1)];
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const argb = Uint8Array.from([...argvals].reverse().flatMap((c) => [...pushInt(c)]));
const padPush = encodeDataPush(new Uint8Array(8));
const unlocking = Uint8Array.from([...padPush, ...argb, ...rpush]);
const program = { inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n }], transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }], locktime: 0 } };
const st = realVm.evaluate(program);
const top = st.stack[st.stack.length - 1];
const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
console.log(`[libauth] scenario=${scenario} (${note}) accepted=${accepted} err=${st.error ?? 'none'}`);
writeFileSync('/tmp/xtraj_tx.hex', binToHex(encodeTransaction(program.transaction)));
writeFileSync('/tmp/xtraj_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
