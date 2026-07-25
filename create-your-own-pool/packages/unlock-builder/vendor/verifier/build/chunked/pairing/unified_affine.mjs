import { repoPath as vcRepoPath } from '#repo-paths';
// UNIFIED single-scheme 28-chunk BN254 Groth16 verifier — freshly generate + MEASURE every
// chunk under the deployed buildCovStep byte convention (P2SH redeem-in-scriptSig + state-arg
// pushes + tuned zero pad, RESCHEDULED cashc compile). ALL 28 chunks use ONE generic hash256
// covenant chain (covIn/covOut = commitBin = sha256d over 40-byte LE mod-p limbs), threaded
// cross-stage: g2check(4) -> vkx(8) -> miller(15..) -> tail(1), with relocation-genesis seam
// chunks at each stage boundary. Verifies covOut[i]==covIn[i+1] for EVERY boundary + all accept.
//   node unified_fullverifier.mjs
import { writeFileSync, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  bn254, vec, proof, vkxPoint, commitBin, CATEGORY, TARGET_UNLOCK, decl, covIn, covOut,
  compileFileBytecode, pairsFor, singlePairMiller, proofFromLimbs,
} from './_millermath.mjs';
// T5-1: the g2check stage is DELETED (subgroup check folded into the final miller window; its
// on-twist(B)/on-G1(A,C)/input-canonicality validators relocated to the vkx genesis below).
import {
  genChunk as millerGenChunk, ops as millerOps, inState as millerInState,
  outState as millerOutState, states as millerStates, chunkLambdas as millerLambdas,
} from './gen_miller_affine.mjs';
import { millerBatchOpsAffine, millerFusedOpsAffine, affDoubleJS, affAddJS } from './_affmath.mjs';
import { foldRedeem } from './_foldredeem.mjs';
// ---- T4-KP: miller k*P specialization. subFp(x,y,k)=x-y+k*P multiplies k*P at RUNTIME on every
// exec (~18k execs/proof). Bake each distinct k*P as a 34-B literal in k-indexed subFp_k<K> (and the
// whole bias-forwarding fp2/fp6 wrapper chain) so the runtime k-plumbing is deleted. Semantics-null:
// each baked k*P is the exact same integer the runtime would compute (verified byte-identical below).
// specializeLib() reads the real Bn254LazyAff.cash and returns the specialized lib source; the lib is
// regenerated on every build (never stale). rewriteChunk() rewrites each emitted miller window's own
// literal-k calls (e.g. fp2Neg(...,64) -> fp2Neg_k64), whose variants live in the specialized lib.
const T4KP = process.env.T4KP !== '0';
import { specializeLib as t4kpSpecializeLib, rewriteChunk as t4kpRewriteChunk } from '../../../intel/validation/T4-KP/t4kp_specialize.mjs';
const T4KP_ORIG_IMPORT = 'import "../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash";';
const T4KP_KSPEC_IMPORT = 'import "../../../singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash";';
const T4KP_KSPEC_PATH = fileURLToPath(new URL('../../singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash', import.meta.url));
// Regenerate + write the specialized lib (fresh from the real lib) once at startup.
if (T4KP) {
  const { libText, needed } = t4kpSpecializeLib();
  writeFileSync(T4KP_KSPEC_PATH, libText);
  console.error(`T4-KP: specialized lib written (${needed.length} k-variants, ${libText.length} B) -> ${T4KP_KSPEC_PATH}`);
}
// Redirect a miller chunk's import to the k-spec lib and rewrite its literal-k calls. Applied to
// EVERY miller window (both the plan-measure re-chunk pass and the reverse-thread build).
const t4kpMiller = (src) => T4KP ? t4kpRewriteChunk(src.replace(T4KP_ORIG_IMPORT, T4KP_KSPEC_IMPORT)) : src;
// OP_2SWAP/2DUP/2OVER/2ROT-type window merges via the LeanBCH VERIFIED FoldTable (0-sorry proven
// stack identities), applied to each compiled redeem before P2SH-wrap. Sound codegen: introspection
// ops (0xc0-0xd3) are opaque fold barriers, so covenant/pin logic is byte-identical; reverse-thread
// then pins each folded successor hash. Default ON (set PEEPHOLE=0 to A/B the un-peepholed build).
const PEEPHOLE = process.env.PEEPHOLE !== '0';
import { residueWitness, fp12limbsOf, COSET27 } from './_residuemath.mjs';
// T3-2: single-chunk Eagen ECIP vk_x certificate (replaces the 8-chunk jacobian MSM).
import { zkEcipHint, ecipVerify, emitCashVerifier, emitWitness } from './gen_vkx_ecip.mjs';
import {
  binToHex, bigIntToVmNumber, encodeDataPush, hash256,
  encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
  hexToBin, vmNumberToBigInt,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const Pstr = P.toString();
const red = (x) => ((BigInt(x) % P) + P) % P;
const OP_TARGET = Number(process.env.OP_COST_TARGET ?? 7_700_000);

// ---- T2-A: InvokeCSE (LeanBCH cse.mjs, machine-checked Stackcert.InvokeCSE) bytecode-level common-
// subexpression factoring of the code-bound tail + final-miller redeems. Applied AFTER foldRedeem,
// BEFORE the P2SH32 commit (the redeem push header stays PUSHDATA2 so a redeem cut == an unlock cut
// 1:1). Each cse output is BLESSED by undomint_equiv.mjs — undo exactly the minted [push id;INVOKE]
// factorings and byte-compare to the original; byte-exact undo ⟹ semantics-preserving (a stronger,
// decompiler-free substitute for the pass's own --gate, which cannot model OP_CAT/NUM2BIN/BIN2NUM).
const T2A_CSE = process.env.T2A_CSE !== '0';
const LEANBCH_ROOT = process.env.LEANBCH_ROOT || '/home/toorik/Projects/LeanBCH';
const CSE_MJS = join(LEANBCH_ROOT, 'optimizer/passes/cse.mjs');
const UNDOMINT_MJS = join(here, '../../../intel/validation/T2-A/undomint_equiv.mjs');
function cseRedeem(redeem, name) {
  const origHex = join(GEN, `_cse_${name}.orig.hex`);
  const cseHex = join(GEN, `_cse_${name}.cse.hex`);
  writeFileSync(origHex, binToHex(redeem));
  execFileSync('node', [CSE_MJS, origHex, cseHex], { stdio: ['ignore', 'ignore', 'inherit'] });
  // undomint EQUIVALENCE PROOF: byte-exact undo of the minted invoke-factorings ⟹ semantics-preserving
  // (Stackcert.InvokeCSE). If it CANNOT be proven byte-exact — e.g. the T5-1 fold merges the final
  // miller window into a larger chunk the pass factors in a way the undo model can't reverse — we DO
  // NOT deploy an unproven optimization: fall back to the (independently sound) foldRedeem-only redeem.
  // The gate is deterministic, so verify_chain_binding.mjs makes the identical per-chunk decision.
  const undo = cseUndomint(origHex, cseHex);
  if (!undo.byteExactUndo) { console.error(`T2-A cse ${name}: byteExactUndo=false — NOT deploying CSE on this chunk (foldRedeem-only, still sound)`); return redeem; }
  return Uint8Array.from(Buffer.from(readFileSync(cseHex, 'utf8').trim(), 'hex'));
}
// Run the undomint equivalence proof; return its JSON verdict. undomint exits non-zero on divergence
// (throws), in which case its {..,"byteExactUndo":false} verdict is still on stdout — parse it back.
function cseUndomint(origHex, cseHex) {
  try { return JSON.parse(execFileSync('node', [UNDOMINT_MJS, origHex, cseHex], { encoding: 'utf8' }).trim()); }
  catch (e) { const s = String(e.stdout ?? '').trim().split('\n')[0]; try { return JSON.parse(s); } catch { return { byteExactUndo: false }; } }
}

// ---- buildCovStep P2SH byte-counter (byte-identical to v3_fullverifier.mjs) --------------------
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
function evalCov(locking, unlocking, inCommit, outCommit, outLocking) {
  const outHasTok = outCommit !== null;
  // output[0].lockingBytecode = the SUCCESSOR chunk's P2SH32 spk (what the covOut successor-pin now
  // enforces). Falls back to self-locking for the terminal tail (which has no successor pin).
  const outLock = outLocking ?? locking;
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, ...(outHasTok ? { token: tok(outCommit) } : {}) }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}
// compile src (RESCHED, deployed convention), P2SH-wrap, binary-search minimal accepting unlock.
// committedIn/outLimbs = decl-order limbs; pushedArgs = full push list (committedIn + witnesses).
// outLimbs=null => terminal (output[0] carries no token).
function measureChunk(name, src, committedIn, pushedArgs, outLimbs, succSpk = null, applyCse = false) {
  const probe = join(GEN, `_u_${name}.cash`);
  writeFileSync(probe, src);
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecode(probe)]); }
  catch (e) { return { fits: false, accepted: false, error: String(e?.message ?? e) }; }
  if (PEEPHOLE) redeem = foldRedeem(redeem); // sound OP_2SWAP/2DUP/... window merges (verified FoldTable)
  if (applyCse && T2A_CSE) redeem = cseRedeem(redeem, name); // T2-A: InvokeCSE factor (undomint-blessed)
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const outLock = succSpk ?? locking; // honest successor for output[0].lockingBytecode (self for terminal)
  const tail = rpush.length;
  const inCommit = commitBin(committedIn.map(BigInt));
  const outCommit = outLimbs === null ? null : commitBin(outLimbs.map(BigInt));
  const argb = Uint8Array.from([...pushedArgs].reverse().flatMap((c) => [...pushInt(c)]));
  const mkUnlock = (target) => { const pad = padBytes(target - argb.length - tail); return Uint8Array.from([...pad, ...argb, ...rpush]); };
  const minU = argb.length + tail + 2;
  const hiUnlock = mkUnlock(TARGET_UNLOCK);
  const topProbe = evalCov(locking, hiUnlock, inCommit, outCommit, outLock);
  let target, real;
  if (!topProbe.accepted || hiUnlock.length > TARGET_UNLOCK) { target = TARGET_UNLOCK; real = topProbe; }
  else {
    let loU = minU, hiU = TARGET_UNLOCK;
    while (loU < hiU) { const mid = (loU + hiU) >> 1; const r = evalCov(locking, mkUnlock(mid), inCommit, outCommit, outLock); if (r.accepted) hiU = mid; else loU = mid + 1; }
    target = hiU; real = evalCov(locking, mkUnlock(target), inCommit, outCommit, outLock);
  }
  const unlocking = mkUnlock(target);
  if (process.env.DIFF === '1') {
    // A1 peephole differential: honest must ACCEPT and a fixed forgery battery must all REJECT.
    // Signature is compared between the unfolded and folded builds; any divergence = behavior change.
    const flip = (arr, i) => { const c = arr.map(BigInt); c[i] = ((c[i] % P) + P) % P ^ 1n; return c; };
    const argbOf = (args) => Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)]));
    const mkU = (args) => { const t = argbOf(args); const pad = padBytes(target - t.length - tail); return Uint8Array.from([...pad, ...t, ...rpush]); };
    const flipByte = (bin, i) => { const c = Uint8Array.from(bin); c[i % c.length] ^= 0x01; return c; };
    const sig = [real.accepted ? 1 : 0]; // [0] honest = ACCEPT expected
    const idxs = [...new Set([0, pushedArgs.length >> 1, pushedArgs.length - 1])].filter((i) => i >= 0);
    for (const i of idxs) sig.push(evalCov(locking, mkU(flip(pushedArgs, i)), inCommit, outCommit, outLock).accepted ? 1 : 0); // wrong witness/state -> REJECT
    sig.push(evalCov(locking, unlocking, flipByte(inCommit, 3), outCommit, outLock).accepted ? 1 : 0);                       // wrong covIn -> REJECT
    if (outCommit) sig.push(evalCov(locking, unlocking, inCommit, flipByte(outCommit, 3), outLock).accepted ? 1 : 0);       // wrong covOut -> REJECT
    sig.push(evalCov(locking, unlocking, inCommit, outCommit, flipByte(outLock, 5)).accepted ? 1 : 0);                      // wrong successor pin -> REJECT
    console.log(`DIFFSIG ${name} ${sig.join('')}`);
  }
  return {
    fits: real.accepted && unlocking.length <= TARGET_UNLOCK && real.operationCost <= OP_TARGET,
    lockingBytes: locking.length, unlockingBytes: unlocking.length,
    operationCost: real.operationCost, accepted: real.accepted,
    inCommit: binToHex(inCommit), outCommit: outCommit ? binToHex(outCommit) : null,
    locking, // this chunk's own 35-byte P2SH32 spk — the PREDECESSOR pins it as its covenant successor
    error: real.error,
    // artifact-dump fields (used only when SAVE_DIR is set; no effect on measurement)
    redeemHex: binToHex(redeem), lockingHex: binToHex(locking), unlockingHex: binToHex(unlocking), src,
  };
}

// ======================================================================================
// instance reference values
// ======================================================================================
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
// ---- ELIGIBILITY (runtimeGeneral) instance selector — DEFAULT-INERT. Unset => committed proof #0
// (crown build byte-identical). Set ELIG_INSTANCE=proof1|worstcase to replay a DISTINCT proof / the
// dense near-r worst-case through the SAME (proof-agnostic, empty-constructor) chunk lockings. The VK
// is fixed; only proof+publicInputs (witness + token commitments) change, so the P2SH32 lockings are
// invariant. This exercises the EXACT deployed code path with a different instance.
function eligInstance() {
  const sel = process.env.ELIG_INSTANCE;
  if (!sel) return { proof, inputs: vec.publicInputs.map(BigInt) };
  const mp = JSON.parse(readFileSync(vcRepoPath('harness/src/bch/groth16-singleton-multiproof-vectors.json'), 'utf8'));
  const parse = (hex) => { const b = hexToBin(hex), v = []; let i = 0; while (i < b.length) { const op = b[i++]; if (op === 0x00) v.push(0n); else if (op === 0x4f) v.push(-1n); else if (op >= 0x51 && op <= 0x60) v.push(BigInt(op - 0x50)); else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); v.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; } } const d = v.reverse(); return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] }; };
  const src = sel === 'worstcase' ? mp.worstCaseProof : mp.proofs[Number(process.env.ELIG_IDX ?? 1)];
  const p = parse(src.unlocking);
  return { proof: proofFromLimbs(p.Ax, p.Ay, p.Bxa, p.Bxb, p.Bya, p.Byb, p.Cx, p.Cy), inputs: [p.in0, p.in1] };
}
const activeInst = eligInstance();
const activeProof = activeInst.proof;
const negA = activeProof.a.negate().toAffine(), Baf = activeProof.b.toAffine(), Caf = activeProof.c.toAffine();
const nAx = red(negA.x), nAy = red(negA.y);
const Bxa = red(Baf.x.c0), Bxb = red(Baf.x.c1), Bya = red(Baf.y.c0), Byb = red(Baf.y.c1);
const Cx = red(Caf.x), Cy = red(Caf.y);
const inputs = activeInst.inputs;
const in0 = inputs[0], in1 = inputs[1];
const vkxAff = vkxPoint(inputs).toAffine();
const vkxX = red(vkxAff.x), vkxY = red(vkxAff.y);
const BforG2 = [[Bxa, Bxb], [Bya, Byb]];

// ======================================================================================
// STAGE 1: g2check (4 chunks) — validate negA,C on G1, B on G2, subgroup([x0]B endo)
//   state (16): R(6) B(4) nAx nAy Cx Cy in0 in1 ; genesis pins R=(0,1,0); final emits SEAM1(10)
// ======================================================================================
const BN_X = 4965661367192848881n, NBITS = 63;
const g2bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n;
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n];
// S3 AFFINE g2check: [x0]B ladder rides AFFINE (R=4 limbs) starting at R=B (bit-0 of |x0| is 1),
// each g2Double/g2AddAffine replaced by witnessed-slope g2AffDbl/g2AffAdd (point-only; no line fold);
// slope verified so the derived next point = 2R / R+Q is uniquely forced and pinned forward. The endo
// subgroup relation ([x0+1]B + psi([x0]B) + psi^2([x0]B) == psi^3([2x0]B)) is checked in AFFINE (no
// witnessed zinv / Z-normalisation / cross-multiply needed). Reject on wrong-slope, R=+-Q, y=0, and
// on any non-subgroup B (verified vs noble). R never = O (starts at B, stays [k]B in the odd subgroup).
const G2LIBA = '../../../singleton/bn254/lib/Miller_aff.cash';
const BNM = ['Bxa', 'Bxb', 'Bya', 'Byb'];
const RN4 = ['RXa', 'RXb', 'RYa', 'RYb'];
const PASS = ['nAx', 'nAy', 'Cx', 'Cy', 'input0', 'input1'];
const G2STA = [...RN4, ...BNM, ...PASS];           // 14 interior state names (affine R)
const SEAM1 = ['nAx', 'nAy', ...BNM, 'Cx', 'Cy', 'input0', 'input1']; // 10 (negA,B,C,in0,in1)
// ---- affine ladder trace (JS): Rafter[k] = affine R after processing bit k; lamDbl/lamAdd + endo lams
const Fp2A = bn254.fields.Fp2;
const conjFp2 = (x) => Fp2A.fromBigTuple([x.c0, (bn254.fields.Fp.ORDER - x.c1) % bn254.fields.Fp.ORDER]);
const PSI_Xg = Fp2A.pow(Fp2A.NONRESIDUE, (bn254.fields.Fp.ORDER - 1n) / 3n);
const PSI_Yg = Fp2A.pow(Fp2A.NONRESIDUE, (bn254.fields.Fp.ORDER - 1n) / 2n);
const psiJS = (x, y) => [Fp2A.mul(conjFp2(x), PSI_Xg), Fp2A.mul(conjFp2(y), PSI_Yg)];
const Baff = { x: Fp2A.fromBigTuple([Bxa, Bxb]), y: Fp2A.fromBigTuple([Bya, Byb]) };
const g2Trace = (() => {
  const Rafter = new Array(NBITS), lamDbl = {}, lamAdd = {};
  let R = { x: Baff.x, y: Baff.y }; Rafter[0] = { x: Baff.x, y: Baff.y };
  for (let k = 1; k < NBITS; k++) {
    const d = affDoubleJS(R.x, R.y); lamDbl[k] = d.lam; R = d.R;
    if (g2bit(k)) { const a = affAddJS(R.x, R.y, Baff.x, Baff.y); lamAdd[k] = a.lam; R = a.R; }
    Rafter[k] = { x: R.x, y: R.y };
  }
  const a0 = Rafter[NBITS - 1];                     // [x0]B affine
  const b = psiJS(a0.x, a0.y), c = psiJS(b[0], b[1]), d = psiJS(c[0], c[1]);
  const l1 = affAddJS(a0.x, a0.y, Baff.x, Baff.y);
  const l2 = affAddJS(l1.R.x, l1.R.y, b[0], b[1]);
  const l3 = affAddJS(l2.R.x, l2.R.y, c[0], c[1]);
  const rr = affDoubleJS(d[0], d[1]);
  return { Rafter, lamDbl, lamAdd, endoLams: [l1.lam, l2.lam, l3.lam, rr.lam], x0B: a0 };
})();
const r4 = (R) => [red(R.x.c0), red(R.x.c1), red(R.y.c0), red(R.y.c1)];
// committed g2 state at window-start lo: R = B (genesis) or Rafter[lo-1]; + B(4) + PASS(6) = 14
const g2StateA = (lo) => [...(lo === 0 ? [Bxa, Bxb, Bya, Byb] : r4(g2Trace.Rafter[lo - 1])), Bxa, Bxb, Bya, Byb, nAx, nAy, Cx, Cy, in0, in1];
// witnessed slopes for window [lo,hi): ladder bits [max(lo,1),hi) then (if last) the 4 endo slopes
function g2LambdasA(lo, hi, isLast) {
  const out = [];
  for (let k = Math.max(lo, 1); k < hi; k++) { const d = g2Trace.lamDbl[k]; out.push(red(d.c0), red(d.c1)); if (g2bit(k)) { const a = g2Trace.lamAdd[k]; out.push(red(a.c0), red(a.c1)); } }
  if (isLast) for (const lm of g2Trace.endoLams) out.push(red(lm.c0), red(lm.c1));
  return out;
}

function g2Chunk(lo, hi, isFirst, isLast, succSpk = null) {
  // lam param names for this window (declaration order == g2LambdasA order)
  const lamP = [];
  for (let k = Math.max(lo, 1); k < hi; k++) { lamP.push(`ld${k}a`, `ld${k}b`); if (g2bit(k)) lamP.push(`la${k}a`, `la${k}b`); }
  if (isLast) lamP.push('le1a', 'le1b', 'le2a', 'le2b', 'le3a', 'le3b', 'lera', 'lerb');
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${G2LIBA}";`);
  L.push('contract G2CheckAff() {');
  L.push(`    function spend(${decl([...G2STA, ...lamP])}, bytes unused zeroPadding) {`);
  L.push(covIn(G2STA));                    // 14-limb state binds spent token
  if (isFirst) {
    // genesis: pin R = B (affine); bit-0 of |x0| == 1 so [x0]B ladder starts at B.
    L.push('        require(RXa == Bxa); require(RXb == Bxb); require(RYa == Bya); require(RYb == Byb);');
    L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));'); // negA on G1
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');     // C on G1
    L.push('        (int oxa,int oxb) = fp2Sqr(Bxa, Bxb);');                              // B on G2
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`);
    L.push('        (int oba,int obb) = fp2Sqr(Bya, Byb);');
    L.push('        require(oba == ora); require(obb == orb);');
  }
  let r = RN4.slice(), uid = 0;
  const fresh = () => Array.from({ length: 4 }, () => `v${uid++}`);
  for (let k = Math.max(lo, 1); k < hi; k++) {
    const d = fresh(); L.push(`        (${decl(d)}) = g2AffDbl(${r.join(',')}, ld${k}a, ld${k}b);`); r = d;
    if (g2bit(k)) { const a = fresh(); L.push(`        (${decl(a)}) = g2AffAdd(${r.join(',')}, ${BNM.join(',')}, la${k}a, la${k}b);`); r = a; }
  }
  if (isLast) {
    const [Rxa, Rxb, Rya, Ryb] = r;                 // R = [x0]B affine
    L.push(`        (int bxa,int bxb,int bya,int byb) = psi(${Rxa}, ${Rxb}, ${Rya}, ${Ryb});`);
    L.push('        (int cxa,int cxb,int cya,int cyb) = psi(bxa, bxb, bya, byb);');
    L.push('        (int dxa,int dxb,int dya,int dyb) = psi(cxa, cxb, cya, cyb);');
    L.push(`        (int l1xa,int l1xb,int l1ya,int l1yb) = g2AffAdd(${Rxa}, ${Rxb}, ${Rya}, ${Ryb}, Bxa, Bxb, Bya, Byb, le1a, le1b);`);
    L.push('        (int l2xa,int l2xb,int l2ya,int l2yb) = g2AffAdd(l1xa, l1xb, l1ya, l1yb, bxa, bxb, bya, byb, le2a, le2b);');
    L.push('        (int l3xa,int l3xb,int l3ya,int l3yb) = g2AffAdd(l2xa, l2xb, l2ya, l2yb, cxa, cxb, cya, cyb, le3a, le3b);');
    L.push('        (int rxa,int rxb,int rya,int ryb) = g2AffDbl(dxa, dxb, dya, dyb, lera, lerb);');
    L.push('        require(l3xa == rxa); require(l3xb == rxb); require(l3ya == rya); require(l3yb == ryb);');
    L.push(covOut(SEAM1, succSpk));         // 10-limb seam -> vkx-genesis (pins vkx-genesis spk)
  } else {
    L.push(covOut([...r, ...BNM, ...PASS], succSpk)); // 14-limb interior (pins next g2 spk)
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ======================================================================================
// STAGE 2: vkx (8 chunks, worst-case-sized windows) — MSM vk_x = IC0 + in0*IC1 + in1*IC2
//   interior state (13): rX rY rZ in0 in1 nAx nAy B(4) Cx Cy ; genesis reads SEAM1(10),
//   pins R=inf; final emits SEAM2(10) = [negA,B,vkx,C] (ptParams order)
// ======================================================================================
const IC = vec.vk.ic.map(g1);
const ic0 = IC[0].toAffine(), ic1 = IC[1].toAffine(), ic2 = IC[2].toAffine(), Ta = IC[1].add(IC[2]).toAffine();
const IC0 = [ic0.x, ic0.y], IC1 = [ic1.x, ic1.y], IC2 = [ic2.x, ic2.y], T = [Ta.x, Ta.y];
const aF = (x, y) => (x + y) % P, sF = (x, y) => (x - y + P) % P, mF = (x, y) => (x * y) % P, qF = (x) => (x * x) % P;
function jDbl(X, Y, Z) { const a = qF(X), b = qF(Y), c = qF(b); const d = mF(2n, sF(sF(qF(aF(X, b)), a), c)); const e = mF(3n, a), f = qF(e); const nx = sF(f, mF(2n, d)); return [nx, sF(mF(e, sF(d, nx)), mF(8n, c)), mF(2n, mF(Y, Z))]; }
function jAdd(aX, aY, aZ, bX, bY, bZ) { if (aZ === 0n) return [bX, bY, bZ]; const z1 = qF(aZ), z2 = qF(bZ); const u1 = mF(aX, z2), u2 = mF(bX, z1); const s1 = mF(mF(aY, bZ), z2), s2 = mF(mF(bY, aZ), z1); if (u1 === u2 && s1 === s2) return jDbl(aX, aY, aZ); const h = sF(u2, u1), i2 = qF(mF(2n, h)), j = mF(h, i2), rr = mF(2n, sF(s2, s1)), v = mF(u1, i2); const nx = sF(sF(qF(rr), j), mF(2n, v)); return [nx, sF(mF(rr, sF(v, nx)), mF(2n, mF(s1, j))), mF(sF(sF(qF(aF(aZ, bZ)), z1), z2), h)]; }
const addedPt = (i) => { const b0 = (in0 >> BigInt(i)) & 1n, b1 = (in1 >> BigInt(i)) & 1n; if (b0 && b1) return T; if (b0) return IC1; if (b1) return IC2; return null; };
function vkxWindow(lo, hi, rX, rY, rZ) { for (let j = lo; j < hi; j++) { const i = 253 - j; if (rZ !== 0n)[rX, rY, rZ] = jDbl(rX, rY, rZ); const ap = addedPt(i); if (ap)[rX, rY, rZ] = jAdd(rX, rY, rZ, ap[0], ap[1], 1n); } return [rX, rY, rZ]; }
const modpow = (b, e, m) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
const vkxPrologue = `function addFp(int x,int y) returns(int){return (x+y)%${Pstr};}
function subFp(int x,int y) returns(int){return (x-y+${Pstr})%${Pstr};}
function mulFp(int x,int y) returns(int){return (x*y)%${Pstr};}
function sqrFp(int x) returns(int){return (x*x)%${Pstr};}
function jacDouble(int x,int y,int z) returns(int,int,int){int a=sqrFp(x);int b=sqrFp(y);int c=sqrFp(b);int d=mulFp(2,subFp(subFp(sqrFp(addFp(x,b)),a),c));int e=mulFp(3,a);int f=sqrFp(e);int nx=subFp(f,mulFp(2,d));int ny=subFp(mulFp(e,subFp(d,nx)),mulFp(8,c));int nz=mulFp(2,mulFp(y,z));return nx,ny,nz;}
function jacAdd(int aX,int aY,int aZ,int bX,int bY,int bZ) returns(int,int,int){int rx=bX;int ry=bY;int rz=bZ;if(aZ!=0){int z1=sqrFp(aZ);int z2=sqrFp(bZ);int u1=mulFp(aX,z2);int u2=mulFp(bX,z1);int s1=mulFp(mulFp(aY,bZ),z2);int s2=mulFp(mulFp(bY,aZ),z1);if(u1==u2&&s1==s2){int da=sqrFp(aX);int db=sqrFp(aY);int dc=sqrFp(db);int dd=mulFp(2,subFp(subFp(sqrFp(addFp(aX,db)),da),dc));int de=mulFp(3,da);int df=sqrFp(de);int dnx=subFp(df,mulFp(2,dd));int dny=subFp(mulFp(de,subFp(dd,dnx)),mulFp(8,dc));int dnz=mulFp(2,mulFp(aY,aZ));rx=dnx;ry=dny;rz=dnz;}else{int h=subFp(u2,u1);int i2=sqrFp(mulFp(2,h));int jj=mulFp(h,i2);int rr=mulFp(2,subFp(s2,s1));int vv=mulFp(u1,i2);int anx=subFp(subFp(sqrFp(rr),jj),mulFp(2,vv));int any=subFp(mulFp(rr,subFp(vv,anx)),mulFp(2,mulFp(s1,jj)));int anz=mulFp(subFp(subFp(sqrFp(addFp(aZ,bZ)),z1),z2),h);rx=anx;ry=any;rz=anz;}}return rx,ry,rz;}
function selectPoint(int b0,int b1) returns(int,int,int){int aX=0;int aY=0;int doAdd=0;if(b0==1&&b1==1){aX=${T[0]};aY=${T[1]};doAdd=1;}else{if(b0==1){aX=${IC1[0]};aY=${IC1[1]};doAdd=1;}else{if(b1==1){aX=${IC2[0]};aY=${IC2[1]};doAdd=1;}}}return aX,aY,doAdd;}`;
// T5-1 RELOCATION: reducing Fp2 helpers, appended ONLY to the vkx GENESIS prologue (the new
// covenant root after g2check's deletion), so the relocated B-on-twist membership check runs there.
// subFp/addFp/mulFp in vkxPrologue reduce (`%P`), so fp2Mul/fp2Add outputs are canonical (< P) and
// the on-twist equality can compare directly. Only the genesis chunk emits these (interior/final
// vkx chunks never reference them), so no other window pays for them.
const vkxGenesisFp2 = `function fp2Add(int a0,int a1,int b0,int b1) returns(int,int){return addFp(a0,b0),addFp(a1,b1);}
function fp2Mul(int a0,int a1,int b0,int b1) returns(int,int){int v0=mulFp(a0,b0);int v1=mulFp(a1,b1);return subFp(v0,v1),subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1));}`;
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // BN254 scalar field order r
const VKST = ['rX', 'rY', 'rZ', 'input0', 'input1', 'nAx', 'nAy', ...BNM, 'Cx', 'Cy']; // 13
const SEAM2 = ['nAx', 'nAy', ...BNM, 'vkxX', 'vkxY', 'Cx', 'Cy'];                       // 10 (ptParams order)
function vkxChunk(lo, hi, isGenesis, isFinal, succSpk = null) {
  const count = hi - lo, hiBit = 253 - lo;
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(vkxPrologue);
  if (isGenesis) L.push(vkxGenesisFp2);  // T5-1: fp2 helpers for the relocated B-on-twist check
  L.push('contract VkxU() {');
  L.push(`    function spend(${decl(VKST)}${isFinal ? ', int zInv' : ''}, bytes unused zeroPadding) {`);
  if (isGenesis) {
    L.push(covIn(SEAM1));                 // reads 10-limb SEAM1 (negA,B,C,in0,in1) — the covenant ROOT (T5-1)
    L.push('        require(rX == 0); require(rY == 1); require(rZ == 0);'); // pin accumulator = infinity
    // ---- T5-1 RELOCATED input-validation prologue (was the deleted g2check genesis). These MUST run
    // before any ladder consumes their subjects; B is covenant-bound through vkx -> miller unchanged.
    // in0/in1 canonicality: public inputs are canonical scalars (< r) [EIP-197 rigor; MSM well-defined].
    L.push(`        require(input0 < ${FR}); require(input1 < ${FR});`);
    // negA, C on G1: y^2 == x^3 + 3.
    L.push('        require(mulFp(nAy, nAy) == addFp(mulFp(mulFp(nAx, nAx), nAx), 3));');
    L.push('        require(mulFp(Cy, Cy) == addFp(mulFp(mulFp(Cx, Cx), Cx), 3));');
    // B on the twist E'(Fp2): y^2 == x^3 + b2 (SCOPES the folded miller subgroup check to on-twist B,
    // where ker(phi) ∩ E'(Fp2) == G2 was proven). fp2Mul/fp2Add reduce, so compare directly.
    L.push('        (int oxa,int oxb) = fp2Mul(Bxa, Bxb, Bxa, Bxb);');            // x^2
    L.push('        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);');           // x^3
    L.push(`        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});`); // x^3 + b2
    L.push('        (int oba,int obb) = fp2Mul(Bya, Byb, Bya, Byb);');           // y^2
    L.push('        require(oba == ora); require(obb == orb);');
  } else {
    L.push(covIn(VKST));                  // 13-limb interior state
  }
  L.push(`        for (int k = 0; k < ${count}; k = k + 1) {`);
  L.push(`            int i = ${hiBit} - k;`);
  L.push('            if (rZ != 0) { (int dx,int dy,int dz) = jacDouble(rX,rY,rZ); rX=dx; rY=dy; rZ=dz; }');
  L.push('            int b0 = (input0 >> i) % 2; int b1 = (input1 >> i) % 2;');
  L.push('            (int aX,int aY,int doAdd) = selectPoint(b0,b1);');
  L.push('            if (doAdd == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,aX,aY,1); rX=ax; rY=ay; rZ=az; }');
  L.push('        }');
  if (isFinal) {
    L.push(`        (int icx,int icy,int icz) = jacAdd(rX,rY,rZ,${IC0[0]},${IC0[1]},1);`);
    L.push('        require(mulFp(icz, zInv) == 1);');
    L.push('        int zInv2 = sqrFp(zInv); int zInv3 = mulFp(zInv2, zInv);');
    L.push('        int vkxX = mulFp(icx, zInv2);');
    L.push('        int vkxY = mulFp(icy, zInv3);');
    L.push(covOut(SEAM2, succSpk));         // 10-limb SEAM2 -> miller reloc genesis (pins its spk)
  } else {
    L.push(covOut(VKST, succSpk));          // 13-limb interior (pins next vkx spk)
  }
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
const vkxStateAt = (accX, accY, accZ) => [red(accX), red(accY), red(accZ), in0, in1, nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy];

// ======================================================================================
// DRIVER
// ======================================================================================
const chain = []; // {name, stage, lock, unlock, op, inCommit, outCommit, committedIn}
function record(name, stage, m) {
  if (!m.accepted) { console.error(`FAIL ${name}: acc=${m.accepted} op=${m.operationCost} err=${m.error ?? ''}`); throw new Error(`chunk ${name} did not accept`); }
  chain.push({ name, stage, lock: m.lockingBytes, unlock: m.unlockingBytes, op: m.operationCost, inCommit: m.inCommit, outCommit: m.outCommit });
  console.log(`${stage.padEnd(8)} ${name.padEnd(18)} lock=${String(m.lock ?? m.lockingBytes).padStart(3)} unlock=${String(m.unlockingBytes).padStart(5)} op=${String(m.operationCost).padStart(9)} acc=Y`);
}

// ---- COVENANT SUCCESSOR THREADING ---------------------------------------------------------------
// Each NON-terminal chunk's covOut now pins output[0].lockingBytecode == the SUCCESSOR chunk's
// 35-byte P2SH32 spk (+ tx.outputs.length == 1). So the chain must be built TAIL-FIRST: compile the
// successor redeem -> hash256 -> P2SH32 spk -> embed in the predecessor. We do it in two passes:
//   (1) PLAN pass — collect chain-ordered descriptors; measure each with a fixed 35-byte plan-spk
//       (below). The pin's SIZE + op-cost are INVARIANT to the spk's 32-byte hash VALUE, so plan-spk
//       measurement gives EXACT window boundaries (the greedy miller re-chunker included).
//   (2) REVERSE-THREAD pass — walk the plan tail->head, feeding each chunk the REAL successor spk,
//       re-measuring; the spk value changes only the predecessor's pinned bytes, never any metric.
const PLAN_SPK_BIN = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32).fill(0x11), 0x87]); // 35B P2SH32-shaped
const PLAN_SPK = binToHex(PLAN_SPK_BIN);          // OP_HASH256 <32B> OP_EQUAL; VALUE irrelevant to size/op-cost
const plan = []; // chain-ordered: { name, fname, stage, build:(succSpkHexOrNull)=>src, committedIn, pushedArgs, outLimbs }

// ---- STAGE 1 (g2check) DELETED by T5-1. The G2-subgroup check is folded into the final miller
// window (gen_miller_affine.mjs pp op: R_end == -psi^3(B)); the on-twist(B)/on-G1(negA,C)/input-
// canonicality validators are relocated into the vkx GENESIS chunk (vkxChunk isGenesis, above).
// The vkx genesis is now the covenant ROOT: its covIn(SEAM1) commitment is the chain genesis. ----

// ---- STAGE 2: vkx (T3-2) — ONE-CHUNK Eagen principal-divisor certificate ----
// Replaces the 8-chunk jacobian double-and-add MSM with a single Liam-Eagen / Weil-reciprocity
// divisor check (garaga-audited hint, ported + validated coeff-for-coeff). The 22-coeff SumDlogDiv
// FunctionFelt binds vk_x = IC0 + in0*IC1 + in1*IC2 via a Fiat–Shamir random-point identity:
//   A0 = try-and-increment(sha256(in0,in1,Q,hint)) ; LHS = coeff0*f(A0) - coeff2*f(A2) == RHS.
// The chunk is the covenant ROOT: it carries SEAM1 (covIn) and the T5-1 relocated input validation,
// and emits SEAM2 (vkxX/vkxY = Q) to the miller genesis. See gen_vkx_ecip.mjs.
const ecipScal = [1n, in0, in1];
const ecipHint = zkEcipHint(IC, ecipScal);
const ecipV = ecipVerify(IC, ecipScal, ecipHint);
if (!ecipV.ok) throw new Error('T3-2: ECIP identity LHS!=RHS on real instance');
if (ecipHint.Qx !== vkxX || ecipHint.Qy !== vkxY) throw new Error('T3-2: ECIP Q != vkxPoint(inputs)');
const ecipWit = emitWitness(IC, ecipScal, ecipHint, ecipV);
const ecipSEAM1 = [nAx, nAy, Bxa, Bxb, Bya, Byb, Cx, Cy, in0, in1];
const ecipSEAM2 = [nAx, nAy, Bxa, Bxb, Bya, Byb, ecipHint.Qx, ecipHint.Qy, Cx, Cy];
plan.push({
  name: 'vkx_ecip[cert]', fname: 'vkx_ecip', stage: 'vkx',
  build: (spk) => emitCashVerifier(IC, spk),
  committedIn: ecipSEAM1.map(red), pushedArgs: [...ecipSEAM1, ...ecipWit].map(BigInt), outLimbs: ecipSEAM2.map(red),
});

// ---- STAGE 3: miller (reloc genesis + greedy re-chunk under buildCovStep) ----
// Plan-measured WITH the plan-spk successor pin present (via millerGenChunk's succSpk arg), so the
// greedy boundaries already account for the pin's ~39 bytes + op-cost. Real successor spks (each
// miller chunk pins the NEXT one; the final miller chunk pins the residue tail) are threaded below.
function measureMiller(lo, hi, relocGenesis) {
  const isFinal = hi === millerOps.length;
  const src = t4kpMiller(millerGenChunk(lo, hi, isFinal, relocGenesis, PLAN_SPK));
  const inFull = millerInState(lo).map(BigInt);
  const committedIn = relocGenesis ? inFull.slice(16, 26).map(red) : inFull.map(red);
  const outLimbs = millerOutState(hi).map(red);
  const pushed = [...inFull, ...millerLambdas(lo, hi).map(BigInt)]; // append witnessed slopes (uncommitted)
  return measureChunk(`ml_${lo}_${hi}`, src, committedIn, pushed, outLimbs, PLAN_SPK_BIN);
}
let lo = 0, mIdx = 0, prevWidth = null;
while (lo < millerOps.length) {
  const relocGenesis = lo === 0;
  const guess = Math.min(millerOps.length, prevWidth ? lo + prevWidth : lo + (relocGenesis ? 14 : 27));
  let last = null;
  const gm = measureMiller(lo, guess, relocGenesis);
  if (gm.fits) {
    last = { hi: guess, m: gm };
    for (let hi = guess + 1; hi <= millerOps.length; hi++) { const mm = measureMiller(lo, hi, relocGenesis); if (mm.fits) last = { hi, m: mm }; else break; }
  } else {
    for (let hi = guess - 1; hi > lo; hi--) { const mm = measureMiller(lo, hi, relocGenesis); if (mm.fits) { last = { hi, m: mm }; break; } }
  }
  if (!last) throw new Error(`miller op ${lo} infeasible`);
  const hi = last.hi, isFinal = hi === millerOps.length, reloc = relocGenesis;
  const inFull = millerInState(lo).map(BigInt);
  const committedIn = relocGenesis ? inFull.slice(16, 26).map(red) : inFull.map(red);
  const outLimbs = millerOutState(hi).map(red);
  const lo0 = lo;
  const pushed = [...inFull, ...millerLambdas(lo, hi).map(BigInt)];
  plan.push({
    name: `ml_${mIdx}[${lo},${hi})${relocGenesis ? 'G' : ''}`, fname: `ml_${lo}_${hi}`, stage: 'miller',
    build: (spk) => t4kpMiller(millerGenChunk(lo0, hi, isFinal, reloc, spk)), committedIn, pushedArgs: pushed, outLimbs,
  });
  prevWidth = hi - lo; lo = hi; mIdx++;
}
// T2-A cse targets: the code-bound final-miller chunk (last miller push) + the tail (pushed below).
// vkx/g2 slices are EXCLUDED here — Path A supersedes them with T3-2 (whole-vkx) / T5-1 (delete g2),
// so cse'ing them now would be bytes that vanish under those levers (double-count ledger, Pool 1/2).
const CSE_FNAMES = new Set([plan[plan.length - 1].fname, 'tail']);

// ---- STAGE 4: residue tail (terminal, generic covIn = [fF,c,cInv]) ----
const TAIL_LIB = '../../../singleton/bn254/lib/lazy/Bn254Lazy.cash';
const pairs = pairsFor(inputs, activeProof);
const { boundary: fRaw } = millerBatchOpsAffine(pairs);
const { c: cWit, cInv: ciWit, w: wWit } = residueWitness(fRaw);
const fused = millerFusedOpsAffine(pairs, cWit, ciWit, singlePairMiller);
const tailState36 = [...fp12limbsOf(fused.boundary), ...fp12limbsOf(cWit), ...fp12limbsOf(ciWit)].map(red);
const wLimbs = fp12limbsOf(wWit).map(red);
const ROOT27L = fp12limbsOf(COSET27[1]).map(String);
const ROOT27_2L = fp12limbsOf(COSET27[2]).map(String);
const ONE_L = ['1', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'];
const matchVec = (names, lits) => '(' + names.map((n, i) => `${n} == ${lits[i]}`).join(' && ') + ')';
function tailSrc() {
  const fFn = Array.from({ length: 12 }, (_, i) => `fF${i}`), cN = Array.from({ length: 12 }, (_, i) => `c${i}`);
  const ciN = Array.from({ length: 12 }, (_, i) => `ci${i}`), wN = Array.from({ length: 12 }, (_, i) => `w${i}`);
  const COMMIT = [...fFn, ...cN, ...ciN];
  const L = [];
  L.push('pragma cashscript ^0.14.0;');
  L.push(`import "${TAIL_LIB}";`);
  L.push('contract ResidueTailU() {');
  L.push(`    function spend(${decl([...COMMIT, ...wN])}, bytes unused zeroPadding) {`);
  L.push(covIn(COMMIT));
  L.push(`        int P = ${Pstr};`);
  L.push('        ' + cN.map((n) => `require(${n} < P);`).join(' '));
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `p${i}`))}) = fp12Mul(${cN.join(',')}, ${ciN.join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(p${i} % P == ${ONE_L[i]});`).join(' '));
  L.push(`        require(${matchVec(wN, ONE_L)} || ${matchVec(wN, ROOT27L)} || ${matchVec(wN, ROOT27_2L)});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cq${i}`))}) = fp12Frob1(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqq${i}`))}) = fp12Frob2(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `cqqq${i}`))}) = fp12Frob3(${cN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `t${i}`))}) = fp12Mul(${fFn.join(',')}, ${wN.join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `lhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `t${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqq${i}`).join(',')});`);
  L.push(`        (${decl(Array.from({ length: 12 }, (_, i) => `rhs${i}`))}) = fp12Mul(${Array.from({ length: 12 }, (_, i) => `cq${i}`).join(',')}, ${Array.from({ length: 12 }, (_, i) => `cqqq${i}`).join(',')});`);
  L.push('        ' + Array.from({ length: 12 }, (_, i) => `require(lhs${i} % P == rhs${i} % P);`).join(' '));
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}
// residue tail is the ONLY terminal chunk: output[0] carries no token (outLimbs=null) and covOut
// has NO successor pin. It is built last in chain order, first in the reverse-thread pass.
plan.push({
  name: 'tail', fname: 'tail', stage: 'tail',
  build: () => tailSrc(), committedIn: tailState36, pushedArgs: [...tailState36, ...wLimbs], outLimbs: null,
});

// ======================================================================================
// REVERSE-THREAD PASS: tail-first. Feed each chunk the REAL successor P2SH32 spk, re-measure,
// then take THIS chunk's own P2SH32 spk (measureChunk.locking) as the successor its PREDECESSOR pins.
// ======================================================================================
const measured = new Array(plan.length);
let succSpkBin = null; // Uint8Array: successor chunk's 35-byte P2SH32 spk (null for the terminal tail)
for (let i = plan.length - 1; i >= 0; i--) {
  const d = plan[i];
  const src = d.build(succSpkBin ? binToHex(succSpkBin) : null); // embed successor spk in covOut pin
  const m = measureChunk(d.fname, src, d.committedIn, d.pushedArgs, d.outLimbs, succSpkBin, CSE_FNAMES.has(d.fname)); // honest out.lock=successor; T2-A cse on tail+final-miller
  if (!m.accepted) { console.error(`FAIL ${d.name}: acc=${m.accepted} op=${m.operationCost ?? '?'} err=${m.error ?? ''}`); throw new Error(`chunk ${d.name} did not accept`); }
  measured[i] = m;
  succSpkBin = m.locking; // predecessor pins THIS chunk's 35-byte P2SH32 spk
}
for (let i = 0; i < plan.length; i++) record(plan[i].name, plan[i].stage, measured[i]);

// ---- OPTIONAL ARTIFACT DUMP (SAVE_DIR=<dir>): persist the reverse-threaded crown chunks --------
// Writes per-chunk {source, redeem hex, locking spk hex, minimal accepting unlock hex, commits, op}
// exactly as measured. Inert unless SAVE_DIR is set; measurement path is untouched.
if (process.env.SAVE_DIR) {
  const { mkdirSync } = await import('node:fs');
  const dir = process.env.SAVE_DIR;
  mkdirSync(dir, { recursive: true });
  const dump = plan.map((d, i) => {
    const m = measured[i];
    writeFileSync(join(dir, `${d.fname}.cash`), m.src);
    return {
      index: i, name: d.name, fname: d.fname, stage: d.stage,
      lockingBytes: m.lockingBytes, unlockingBytes: m.unlockingBytes, operationCost: m.operationCost,
      inCommit: m.inCommit, outCommit: m.outCommit,
      lockingHex: m.lockingHex, redeemHex: m.redeemHex, unlockingHex: m.unlockingHex,
    };
  });
  writeFileSync(join(dir, 'chunks.json'), JSON.stringify(dump, null, 1));
  console.log(`SAVE_DIR: wrote ${dump.length} chunk artifacts + chunks.json to ${dir}`);
}

// ======================================================================================
// CHAIN VERIFICATION + TOTALS
// ======================================================================================
let internalChainOk = true;
const breaks = [];
for (let i = 1; i < chain.length; i++) {
  if (chain[i - 1].outCommit !== chain[i].inCommit) { internalChainOk = false; breaks.push(`${chain[i - 1].name} -> ${chain[i].name}`); }
}
const startSeam = chain[0].stage === 'vkx'; // T3-2/T5-1: the vkx ECIP cert is the covenant root
const endSeam = chain[chain.length - 1].name === 'tail' && chain[chain.length - 1].outCommit === null;
const total = chain.reduce((s, c) => s + c.lock + c.unlock, 0);
const byStage = {};
for (const c of chain) { byStage[c.stage] = (byStage[c.stage] || 0) + c.lock + c.unlock; }
console.log('');
console.log(`chunk count: ${chain.length}`);
console.log('per-stage bytes:', JSON.stringify(byStage));
console.log(`internalChainOk=${internalChainOk} ${breaks.length ? 'BREAKS: ' + breaks.join(', ') : ''}`);
console.log(`UNIFIED end-to-end TOTAL = ${total} B  deltaVs274607=${total - 274607}  crownCrossed(<241518)=${total < 241518}  margin=${241518 - total}`);
console.log('JSON ' + JSON.stringify({
  chunkCount: chain.length, total, deltaVs274607: total - 274607, crownCrossed: total < 241518, margin: 241518 - total,
  internalChainOk, startSeam, endSeam, byStage,
  chunks: chain.map((c) => ({ name: c.name, stage: c.stage, lock: c.lock, unlock: c.unlock, op: c.op })),
}));
