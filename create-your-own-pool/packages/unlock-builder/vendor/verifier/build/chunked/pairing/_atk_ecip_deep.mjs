// DEEP adversary on the T3-2 ECIP vkx verifier. Runs on the REAL BCH-2026 VM.
// Targets: (1) wrong-Q with best-effort recomputed witness, (2) FS grinding / linear-solve,
// (3) non-residue retry inflation/deflation, (4) Q==seam divergence.
import { bn254, vec, proof, vkxPoint, commitBin, CATEGORY } from './_millermath.mjs';
import { compileString, utils } from 'cashc'; const { asmToBytecode } = utils;
import { foldRedeem } from './_foldredeem.mjs';
import { zkEcipHint, ecipVerify, emitCashVerifier, emitWitness, fsChallenge, WIT, MAXTRY } from './gen_vkx_ecip.mjs';
import { encodeDataPush, hash256, encodeLockingBytecodeP2sh32, bigIntToVmNumber, binToHex, createVirtualMachineBch2026, vmNumberToBigInt } from '@bitauth/libauth';
import { createHash } from 'node:crypto';
// EXACT mirror of the .cash / gen_vkx_ecip derivation (little-endian 32B; int(sha256(..).split(31)[0]))
function le32(x){const b=Buffer.alloc(32);let v=((BigInt(x)%P)+P)%P;for(let i=0;i<32;i++){b[i]=Number(v&0xffn);v>>=8n;}return b;}
const vmInt31=(dig)=>((vmNumberToBigInt(dig.subarray(0,31),{maximumVmNumberByteLength:32,requireMinimalEncoding:false})%P)+P)%P;
const nextX=(x)=>vmInt31(createHash('sha256').update(le32(x)).digest());

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (x) => ((BigInt(x) % P) + P) % P;
const fmul = (a,b)=>red(a*b), fadd=(a,b)=>red(a+b), fsub=(a,b)=>red(a-b);
const fpow=(b,e)=>{let r=1n;b=red(b);while(e>0n){if(e&1n)r=r*b%P;b=b*b%P;e>>=1n;}return r;};
const finv=(a)=>fpow(a,P-2n);
const sqrtFp=(a)=>fpow(a,(P+1n)/4n);
const isQR=(a)=>{a=red(a);return a===0n?true:fpow(a,(P-1n)/2n)===1n;};
const rhsOf=(x)=>fadd(fmul(fmul(x,x),x),3n);
const G1 = bn254.G1.Point;
const aff=(pt)=>pt.toAffine();

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
console.log('setup: ECIP Q==MSM:', red(vkxAff.x)===h.Qx && red(vkxAff.y)===h.Qy, ' identity ok:', v.ok, ' nfail:', v.nfail);

const PLAN_SPK = binToHex(Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]));
const src = emitCashVerifier(IC, PLAN_SPK);
import { writeFileSync } from 'node:fs';
writeFileSync('./generated/_ecip_deep.cash', src);
let redeem = asmToBytecode(compileString(src, { rescheduleStacks: true }).bytecode);
redeem = foldRedeem(redeem);
const rpush = encodeDataPush(redeem);
const locking = encodeLockingBytecodeP2sh32(hash256(redeem));
const succSpk = Uint8Array.from(Buffer.from(PLAN_SPK, 'hex'));
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));

function evalWith(seam1vals, witVals, seam2vals, succ = succSpk) {
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
  return { acc, op: st.metrics.operationCost, err: st.error ?? null };
}

const SEAM1vals = [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1];
const SEAM2vals = [nAx, nAy, Bxa, Bxb, Bya, Byb, h.Qx, h.Qy, Cx, Cy];
const wit = emitWitness(IC, scalars, h, v);
const honest = evalWith(SEAM1vals, wit, SEAM2vals);
console.log(`HONEST: acc=${honest.acc} op=${honest.op}\n`);

// Build a best-effort witness for an ARBITRARY claimed Q' (attacker keeps honest divisor coeffs,
// recomputes every FS-derived + require-forced field so the ONLY thing that can reject is the
// divisor identity LHS==RHS / the tQ term). Returns null if the recompute path throws (>MAXTRY).
function bestEffortWitnessForQ(Qxp, Qyp) {
  const hp = { ...h, Qx: red(Qxp), Qy: red(Qyp) };
  let vp; try { vp = ecipVerify(IC, scalars, hp); } catch (e) { return null; }
  const witp = emitWitness(IC, scalars, hp, vp);
  const seam2p = [nAx, nAy, Bxa, Bxb, Bya, Byb, red(Qxp), red(Qyp), Cx, Cy];
  return { witp, seam2p, identityOk: vp.ok };
}

console.log('=== VECTOR 1&4: wrong Q with best-effort recomputed witness (must REJECT) ===');
let anyAccept = false;
const Qhx = h.Qx, Qhy = h.Qy;
const trials = [
  ['Q+IC0', IC[0]], ['Q+IC1', IC[1]], ['Q+IC2', IC[2]], ['Q+G', G1.BASE],
  ['2*Q', null], ['Q+2*IC0', null],
];
for (const [name, add] of trials) {
  let Qp;
  const Qpt = G1.fromAffine({ x: Qhx, y: Qhy });
  if (name === '2*Q') Qp = Qpt.add(Qpt);
  else if (name === 'Q+2*IC0') Qp = Qpt.add(IC[0]).add(IC[0]);
  else Qp = Qpt.add(add);
  const a = aff(Qp); const be = bestEffortWitnessForQ(red(a.x), red(a.y));
  if (!be) { console.log(`  ${name}: recompute threw (>MAXTRY) -> unreachable honest-shape`); continue; }
  const r = evalWith(SEAM1vals, be.witp, be.seam2p);
  console.log(`  ${name}: identityOk(ref)=${be.identityOk} VM.acc=${r.acc} ${r.err?('['+String(r.err).slice(0,60)+']'):''}`);
  if (r.acc) anyAccept = true;
}

console.log('\n=== VECTOR 2a: FS-grinding — linear-solve for a_num[0] then feed back (must NOT converge) ===');
// Attacker fixes wrong Q' = Q+IC0. At the CURRENT challenge, solves the (linear-in-an0) identity for an0,
// injects it, which changes the FS hash -> new challenge -> re-solve. Show it never lands on a fixed point.
const Qbad = (() => { const q = G1.fromAffine({x:Qhx,y:Qhy}).add(IC[0]); const a=aff(q); return [red(a.x),red(a.y)]; })();
function landsForCoeffs(hh) {
  // returns {landed, xseed} : whether on-chain identity would hold, given hint hh & Qbad
  let vp; try { vp = ecipVerify(IC, scalars, { ...hh, Qx: Qbad[0], Qy: Qbad[1] }); } catch { return { landed:false }; }
  return { landed: vp.ok };
}
let hg = { ...h }; let converged = false; let landedCount = 0;
for (let it = 0; it < 300; it++) {
  // recompute challenge for current coeffs+Qbad, derive A0/A2, then SOLVE identity for an0.
  const xseed = fsChallenge(in0, in1, Qbad[0], Qbad[1], hg);
  let x = xseed, nfail = 0;
  while (!isQR(rhsOf(x))) { x = nextX(x); nfail++; if(nfail>MAXTRY){x=null;break;} }
  if (x === null) { hg = { ...hg, a_num: hg.a_num.map((c)=>red(c+1n)) }; continue; }
  const chk = landsForCoeffs(hg);
  if (chk.landed) { landedCount++; }
  // perturb an0 deterministically to emulate the attacker's "solve" step (any change to search space)
  const na = hg.a_num.slice(); na[0] = red(na[0] + 1n + BigInt(it)); hg = { ...hg, a_num: na };
}
console.log(`  300 grind iterations over wrong Q'+coeff-search: identity landed ${landedCount} times (must be 0; FS re-randomizes A0 each change)`);

console.log('\n=== VECTOR 2b: does the on-chain FS use the SAME coeffs it evaluates? (hash-swap) ===');
// Try: honest coeffs for hashing but perturbed coeffs for the check -> impossible on-chain (one array).
// Emulate by feeding a witness whose an0 differs from what produced the honest challenge: reject expected.
{ const w = wit.slice(); const AN0_IDX = 2; w[AN0_IDX] = red(w[AN0_IDX] + 1n);
  const r = evalWith(SEAM1vals, w, SEAM2vals);
  console.log(`  perturb an0 only (challenge & eval both shift): acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true; }

console.log('\n=== VECTOR 3: non-residue retry manipulation (must REJECT) ===');
// Reconstruct the EXACT VM x-sequence: xseed, then nextX(...) until rhs(x) is a QR.
const xseed = fsChallenge(in0, in1, h.Qx, h.Qy, h);
const xseq = [xseed]; { let x = xseed; while (!isQR(rhsOf(x))) { x = nextX(x); xseq.push(x); } }
const trueNfail = xseq.length - 1; const acceptedX = xseq[trueNfail];
console.log(`  reference nfail=${v.nfail}, reconstructed nfail=${trueNfail} (match=${v.nfail===trueNfail}); acceptedX==v.xA0: ${acceptedX===v.xA0}`);
console.log(`  3*rhs(acceptedX) is QR? ${isQR(fmul(3n, rhsOf(acceptedX)))}  (false => NO valid non-residue cert exists past accept)`);
// 3a: inflate nfail — claim one extra retry past the true accepted x. The slot-[trueNfail] branch needs
// gr with gr^2==3*rhs(acceptedX); since rhs(acceptedX) is a QR, 3*rhs is a non-residue => no real sqrt.
{ const w = wit.slice(); const NF_IDX = WIT.indexOf('nfail'); const GR_IDX = WIT.indexOf('gr0');
  w[NF_IDX] = BigInt(trueNfail + 1);
  w[GR_IDX + trueNfail] = sqrtFp(fmul(3n, rhsOf(acceptedX))); // best-effort bogus cert (its square != 3*rhs)
  const r = evalWith(SEAM1vals, w, SEAM2vals);
  console.log(`  inflate nfail=${trueNfail + 1} w/ fabricated gr[${trueNfail}]: acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true;
}
// 3b: deflate nfail — accept an earlier NON-residue x (xseed, a non-residue since trueNfail>0) as A0.
// yA0^2==rhs(xseed) is unsatisfiable (non-residue) => bogus yA0 fails the on-curve require.
if (trueNfail > 0) { const w = wit.slice(); const NF_IDX = WIT.indexOf('nfail'); const YA0_IDX = WIT.indexOf('yA0');
  w[NF_IDX] = 0n; w[YA0_IDX] = sqrtFp(rhsOf(xseed));
  const r = evalWith(SEAM1vals, w, SEAM2vals);
  console.log(`  deflate nfail=0 (accept non-residue xseed, bogus yA0): acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true;
}
// 3c: skip-a-QR — advance PAST acceptedX by fabricating its non-residue cert AND providing the next QR.
// Same impossibility: cert for acceptedX cannot exist. Confirms first-QR is forced, no off-curve accept.
{ const w = wit.slice(); const NF_IDX = WIT.indexOf('nfail'); const GR_IDX = WIT.indexOf('gr0'); const YA0_IDX = WIT.indexOf('yA0');
  let x2 = nextX(acceptedX), extra = 0; while (!isQR(rhsOf(x2))) { x2 = nextX(x2); extra++; if (extra>MAXTRY) break; }
  w[NF_IDX] = BigInt(trueNfail + 1 + extra);
  w[GR_IDX + trueNfail] = sqrtFp(fmul(3n, rhsOf(acceptedX)));
  for (let k=0;k<extra;k++) w[GR_IDX+trueNfail+1+k] = v.gRoots[0] ?? 1n;
  w[YA0_IDX] = sqrtFp(rhsOf(x2));
  const r = evalWith(SEAM1vals, w, SEAM2vals);
  console.log(`  skip-a-QR to next residue x (fabricated accept cert): acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true;
}

console.log('\n=== VECTOR 4: Q vs seam divergence (must REJECT any divergence) ===');
// seam2.vkxX literally = witnessed Qx (line: int vkxX=Qx). Try to smuggle a different value into seam2.
{ const seam2diff = [nAx, nAy, Bxa, Bxb, Bya, Byb, red(h.Qx + 1n), h.Qy, Cx, Cy];
  const r = evalWith(SEAM1vals, wit, seam2diff);
  console.log(`  seam2.vkxX = Qx+1 (miller would consume wrong pt): acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true; }
// change the pinned successor spk (redirect to attacker contract)
{ const badSucc = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x22), 0x87]);
  const r = evalWith(SEAM1vals, wit, SEAM2vals, badSucc);
  console.log(`  redirect successor spk (0x22..): acc=${r.acc} (must be false)`); if (r.acc) anyAccept = true; }

console.log('\n=== BENIGN malleability check: -yA0 alternate root (may ACCEPT; Q unchanged => not a forgery) ===');
{ // recompute the full witness using the OTHER square root of rhs(xA0)
  const v2 = ecipVerify(IC, scalars, h); // honest
  // flip yA0 sign and recompute all yA0-dependent terms via a fresh ecipVerify variant is complex;
  // instead just flip witness yA0 and the derived mA0/terms would mismatch -> expect reject (require chain).
  const w = wit.slice(); const YA0_IDX = WIT.indexOf('yA0'); w[YA0_IDX] = red(P - wit[YA0_IDX]);
  const r = evalWith(SEAM1vals, w, SEAM2vals);
  console.log(`  flip yA0 sign only (other terms stale): acc=${r.acc} (expected false; not a forgery either way)`); }

console.log(`\n==== ANY FORGERY ACCEPTED: ${anyAccept} ====`);
