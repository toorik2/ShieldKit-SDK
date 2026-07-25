// Probe: compile the single-chunk ECIP vk_x verifier, run it through the covenant VM on the REAL
// instance, and report accept + op-cost + redeem/unlock bytes. Also runs a mini forge battery.
import { bn254, vec, proof, vkxPoint, commitBin, CATEGORY } from './_millermath.mjs';
import { compileString, utils } from 'cashc'; const { asmToBytecode } = utils;
import { foldRedeem } from './_foldredeem.mjs';
import { zkEcipHint, ecipVerify, emitCashVerifier, emitWitness, SEAM1, SEAM2 } from './gen_vkx_ecip.mjs';
import { encodeDataPush, hash256, encodeLockingBytecodeP2sh32, bigIntToVmNumber, binToHex, createVirtualMachineBch2026 } from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;
const G1 = bn254.G1.Point;

// ---- real instance ----
const g1 = (o) => G1.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const negA = proof.a.negate().toAffine(), Baf = proof.b.toAffine(), Caf = proof.c.toAffine();
const nAx = red(negA.x), nAy = red(negA.y);
const Bxa = red(Baf.x.c0), Bxb = red(Baf.x.c1), Bya = red(Baf.y.c0), Byb = red(Baf.y.c1);
const Cx = red(Caf.x), Cy = red(Caf.y);
const inputs = vec.publicInputs.map(BigInt);
const in0 = inputs[0], in1 = inputs[1];
const IC = vec.vk.ic.map(g1);
const scalars = [1n, in0, in1];
const h = zkEcipHint(IC, scalars);
const v = ecipVerify(IC, scalars, h);
const vkxAff = vkxPoint(inputs).toAffine();
console.log('ECIP Q == vkxPoint:', red(vkxAff.x) === h.Qx && red(vkxAff.y) === h.Qy, ' identity ok:', v.ok, ' nfail:', v.nfail);

const SEAM1vals = [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1];
const SEAM2vals = [nAx, nAy, Bxa, Bxb, Bya, Byb, h.Qx, h.Qy, Cx, Cy];
const PLAN_SPK = binToHex(Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]));

const src = emitCashVerifier(IC, PLAN_SPK);
import { writeFileSync } from 'node:fs';
writeFileSync('./generated/_ecip_probe.cash', src);
let redeem;
try { redeem = asmToBytecode(compileString(src, { rescheduleStacks: true }).bytecode); }
catch (e) { console.log('COMPILE ERROR:', String(e.message || e).slice(0, 400)); process.exit(1); }
redeem = foldRedeem(redeem);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const succSpk = Uint8Array.from(Buffer.from(PLAN_SPK, 'hex'));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));

function evalWith(seam1vals, witVals, seam2vals, succ) {
  const args = [...seam1vals, ...witVals];
  const argb = Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)]));
  const pad = encodeDataPush(new Uint8Array(Math.max(0, 9600 - argb.length - rpush.length)));
  const unlocking = Uint8Array.from([...pad, ...argb, ...rpush]);
  const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
  const st = realVm.evaluate({
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(seam1vals.map(BigInt))) }],
    transaction: { version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: succ, valueSatoshis: 1000n, token: tok(commitBin(seam2vals.map(BigInt))) }], locktime: 0 },
  });
  const top = st.stack[st.stack.length - 1];
  const acc = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { acc, op: st.metrics.operationCost, err: st.error ?? null, unlockBytes: unlocking.length };
}

const wit = emitWitness(IC, scalars, h, v);
const honest = evalWith(SEAM1vals, wit, SEAM2vals, locking); // pin self as successor (plan spk == self here? no, plan spk is fixed)
// use the fixed PLAN_SPK as successor (matches emitCashVerifier's pinned spk)
const honestPin = evalWith(SEAM1vals, wit, SEAM2vals, succSpk);
console.log(`\nredeemBytes=${redeem.length}  lockBytes=${locking.length}  unlockBytes=${honestPin.unlockBytes}`);
console.log(`HONEST: acc=${honestPin.acc} op=${honestPin.op} ${honestPin.err ? 'ERR:' + JSON.stringify(honestPin.err) : ''}`);

// ---- mini forge battery ----
const flip = (arr, i, d = 1n) => { const c = arr.slice(); c[i] = red(c[i] + d); return c; };
// forge A: fake divisor coeff (perturb a_num[0] -> WIT index 2). Recompute nothing (attacker just flips witness).
let idxAn0 = 2; // Qx,Qy then a_num0
const fAn = evalWith(SEAM1vals, flip(wit, idxAn0), SEAM2vals, succSpk);
console.log(`FORGE fake-divisor (a_num0+1): acc=${fAn.acc} (must be false)`);
// forge B: wrong vk_x in the SEAM2 output (Qx+1 in seam2) while witness Qx unchanged -> covOut mismatch OR identity
const fSeam = evalWith(SEAM1vals, wit, [nAx, nAy, Bxa, Bxb, Bya, Byb, red(h.Qx + 1n), h.Qy, Cx, Cy], succSpk);
console.log(`FORGE wrong-vkx-in-seam2 (Qx+1): acc=${fSeam.acc} (must be false)`);
// forge C: wrong witness Qx (and matching seam2) -> FS challenge changes, identity fails
const witQx = flip(wit, 0); // Qx is WIT[0]
const fQx = evalWith(SEAM1vals, witQx, [nAx, nAy, Bxa, Bxb, Bya, Byb, red(h.Qx + 1n), h.Qy, Cx, Cy], succSpk);
console.log(`FORGE wrong-vkx (witness Qx+1 & seam2): acc=${fQx.acc} (must be false)`);
// forge D: tamper a committed limb (in0) without updating covenant -> covIn mismatch
const fIn0 = evalWith([nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, red(in0 + 1n), in1], wit, SEAM2vals, succSpk);
console.log(`FORGE tamper committed in0: acc=${fIn0.acc} (must be false)`);
// WIT indices: yA0=24 nfail=25 mA0=34 iad0=37 t1p=43 ; retry gRoot0=26
const idx = { yA0: 24, nfail: 25, gr0: 26, mA0: 34, iad0: 37, t1p: 43 };
for (const [nm, i] of Object.entries(idx)) {
  const f = evalWith(SEAM1vals, flip(wit, i), SEAM2vals, succSpk);
  console.log(`FORGE tamper ${nm} (WIT[${i}]): acc=${f.acc} (must be false)`);
}
// forge: claim nfail=0 (skip retries) — real needs nfail=2, so accept-check on x_seed must fail
const witN0 = wit.slice(); witN0[25] = 0n;
console.log(`FORGE nfail:=0 (understate retries): acc=${evalWith(SEAM1vals, witN0, SEAM2vals, succSpk).acc} (must be false)`);
// forge: EIP-197 off-curve C (relocated input validation must reject)
const fOffC = evalWith([nAx, nAy, Bxa, Bxb, Bya, Byb, red(Cx + 1n), Cy, in0, in1], wit,
  [nAx, nAy, Bxa, Bxb, Bya, Byb, h.Qx, h.Qy, red(Cx + 1n), Cy], succSpk);
console.log(`FORGE off-curve C (x+1): acc=${fOffC.acc} (must be false)`);
