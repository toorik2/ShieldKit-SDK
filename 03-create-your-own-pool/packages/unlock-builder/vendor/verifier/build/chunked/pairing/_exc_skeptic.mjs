// EXCEPTIONAL-CASES SKEPTIC harness for the S3 affine offload.
// Attacks: R=O / point-at-infinity, R=+-Q, 2-torsion (y=0), denominator-zero (2y=0 / Rx-Qx=0),
// and the (0,0)-origin escape, on the REAL libauth BCH-2026 VM. Tests both the primitive level
// AND reachability (whether the covenant thread can be made to feed an exceptional R mid-chain).
import { readFileSync, writeFileSync } from 'node:fs';
import { compileString, compileFile, utils } from 'cashc';
import { createTestAuthenticationProgramBch, encodeDataPush, bigIntToVmNumber, createVirtualMachineBch2026, numberToBinUint16LE } from '@bitauth/libauth';
import { bn254, Fp2, proof, pairsFor, vec } from './_millermath.mjs';
import { affDoubleJS, affAddJS } from './_affmath.mjs';
import { genChunk, inState, outState, chunkLambdas, ops } from './gen_miller_affine.mjs';
import { compileFileBytecodeRaw, CATEGORY, commitBin, TARGET_UNLOCK } from './_millermath.mjs';
const { asmToBytecode } = utils; const { Fp } = bn254.fields;
const vm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n, r = (x) => ((x % P) + P) % P;
const OP_PUSHDATA2 = 0x4d;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const padPush = (al, t) => { const N = t - al - 3; return Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };
const results = {};
const rec = (k, v) => { results[k] = v; console.log((v ? 'PASS ' : 'FAIL '), k, '=>', v); };

// ---------- reducing-tower g2 primitive (import Miller_aff) ----------
function runLib(nargs, body, args) {
  const src = `pragma cashscript ^0.14.0;\nimport "../../../singleton/bn254/lib/Miller_aff.cash";\ncontract T(){function f(${Array.from({ length: nargs }, (_, i) => `int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n`;
  writeFileSync('generated/_exc_g2.cash', src);
  let raw; try { raw = asmToBytecode(compileFile('generated/_exc_g2.cash').bytecode); } catch (e) { return { err: String(e?.message ?? e).slice(0, 90) }; }
  const locking = Uint8Array.from(raw);
  const pad = Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(9000), ...new Uint8Array(9000)]);
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: Uint8Array.from([...pad, ...Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)]))]), valueSatoshis: 1000n }));
  return { accepted: st.error === undefined && st.stack.length === 1 && st.stack[0].length === 1 && st.stack[0][0] === 1, err: st.error ? String(st.error).slice(0, 90) : undefined };
}
// ---------- lazy-tower miller primitive (extract fp2 from V3 lib + _afflib) ----------
const lib = readFileSync('variants/V3_millerres_lib.cash', 'utf8');
function extract(name) { const s = lib.split('\n'), o = []; let p = false, d = 0; for (const l of s) { if (!p && l.startsWith(`function ${name}(`)) p = true; if (p) { o.push(l); d += (l.match(/\{/g) || []).length - (l.match(/\}/g) || []).length; if (d === 0 && l.includes('}')) break; } } return o.join('\n'); }
const need = ['addFp', 'subFp', 'mulFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2Scale'];
const libtext = need.map(extract).join('\n') + '\n' + readFileSync('_afflib.cash', 'utf8');
function runLazy(nargs, body, args) {
  const src = `pragma cashscript ^0.14.0;\ncontract T(){function f(${Array.from({ length: nargs }, (_, i) => `int a${i}`).join(',')}, bytes unused pad){\n${body}\n}}\n${libtext}`;
  let raw; try { raw = asmToBytecode(compileString(src, { rescheduleStacks: true }).bytecode); } catch (e) { return { err: String(e?.message ?? e).slice(0, 90) }; }
  const locking = Uint8Array.from(raw);
  const pad = Uint8Array.from([OP_PUSHDATA2, ...numberToBinUint16LE(9000), ...new Uint8Array(9000)]);
  const st = vm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: locking, unlockingBytecode: Uint8Array.from([...pad, ...Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)]))]), valueSatoshis: 1000n }));
  return { accepted: st.error === undefined && st.stack.length === 1 && st.stack[0].length === 1 && st.stack[0][0] === 1, err: st.error ? String(st.error).slice(0, 90) : undefined };
}
const consume10 = `require(within(mulFp(c0a,0)+mulFp(c0b,0)+mulFp(c1a,0)+mulFp(c1b,0)+mulFp(c2a,0)+mulFp(c2b,0)+mulFp(nxa,0)+mulFp(nxb,0)+mulFp(nya,0)+mulFp(nyb,0), 0, 2));`;
const consume4 = `require(within(mulFp(nxa,0)+mulFp(nxb,0)+mulFp(nya,0)+mulFp(nyb,0), 0, 2));`;

console.log('\n===== PART 1: primitive-level (0,0)-origin escape (documents the latent hazard) =====');
// lazy-tower affDbl on (0,0): slope check 0==3*0^2 -> 0==0 passes for ANY lambda.
{
  const bodyD = `(int c0a,int c0b,int c1a,int c1b,int c2a,int c2b,int nxa,int nxb,int nya,int nyb)=affDbl(a0,a1,a2,a3,a4,a5);\n ${consume10}`;
  const acc = runLazy(6, bodyD, [0n, 0n, 0n, 0n, 999n, 12345n]).accepted;
  rec('LAZY affDbl(0,0, arbitrary-lam) ACCEPTS at primitive level (latent escape confirmed)', acc === true);
}
// reducing-tower g2AffDbl on (0,0)
{
  const bodyD = `(int nxa,int nxb,int nya,int nyb)=g2AffDbl(a0,a1,a2,a3,a4,a5);\n ${consume4}`;
  const acc = runLib(6, bodyD, [0n, 0n, 0n, 0n, 999n, 12345n]).accepted;
  rec('REDUCING g2AffDbl(0,0, arbitrary-lam) ACCEPTS at primitive level (latent escape confirmed)', acc === true);
}
// on-curve 2-torsion is IMPOSSIBLE on BN254 (odd order), but the SLOPE check must still reject a
// genuine y=0, x!=0 input (2-torsion-like). Use x=B.x, y=0:
{
  const B = proof.b.toAffine();
  const bodyD = `(int nxa,int nxb,int nya,int nyb)=g2AffDbl(a0,a1,a2,a3,a4,a5);\n ${consume4}`;
  const acc = runLib(6, bodyD, [B.x.c0, B.x.c1, 0n, 0n, 999n, 12345n]).accepted;
  rec('REDUCING g2AffDbl(x!=0, y=0) REJECTS (2-torsion / denom-zero)', acc === false);
}

console.log('\n===== PART 2: R=-Q => O (point at infinity) and R=+Q on the ADD, both towers =====');
{
  const B = proof.b.toAffine(), nBy = Fp2.neg(B.y);
  const twoB = proof.b.double().toAffine();
  const a = affAddJS(twoB.x, twoB.y, B.x, B.y);
  const bodyA = `(int nxa,int nxb,int nya,int nyb)=g2AffAdd(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9);\n ${consume4}`;
  // honest 2B + B
  rec('REDUCING g2AffAdd honest ACCEPTS', runLib(10, bodyA, [twoB.x.c0, twoB.x.c1, twoB.y.c0, twoB.y.c1, B.x.c0, B.x.c1, B.y.c0, B.y.c1, a.lam.c0, a.lam.c1]).accepted === true);
  // R=+Q
  rec('REDUCING g2AffAdd R=+Q REJECTS', runLib(10, bodyA, [B.x.c0, B.x.c1, B.y.c0, B.y.c1, B.x.c0, B.x.c1, B.y.c0, B.y.c1, 5n, 6n]).accepted === false);
  // R=-Q  (Rx=Qx, Ry=-Qy => R+Q=O)
  rec('REDUCING g2AffAdd R=-Q(=>O) REJECTS', runLib(10, bodyA, [B.x.c0, B.x.c1, nBy.c0, nBy.c1, B.x.c0, B.x.c1, B.y.c0, B.y.c1, 5n, 6n]).accepted === false);
}

console.log('\n===== PART 3: 2-torsion / low-order / non-subgroup B fed to the REAL g2 endo chunk =====');
// (delegated to _g2_forge for the full endo chunk; here we sanity-run more B via the JS+VM primitive
//  by checking that a y=0 B rejects at the FIRST ladder doubling.)
// Build the twist b' and construct exceptional B candidates.
const b2 = Fp2.fromBigTuple([19485874751759354771024239261021720505790618469301721065564631296452457478373n, 266929791119991161246907387137283842545076965332900288569378510910307636690n]);
const eq = (a, b) => a.c0 === b.c0 && a.c1 === b.c1;
function onCurve(seed) { for (let s = seed; ; s++) { const x = Fp2.fromBigTuple([BigInt(s), 3n]); const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2); try { const y = Fp2.sqrt(rhs); if (eq(Fp2.sqr(y), rhs)) return { x, y }; } catch (e) {} } }
// verify none of these non-subgroup points is accidentally subgroup, and each rejects at endo via the FIRST ladder step primitive:
// (the definitive endo-chunk VM reject is in _g2_forge; here we confirm the ladder never grants a free step)
let allNonsubForced = true;
for (const seed of [1, 7, 13, 21, 33, 42, 55, 99, 123, 200]) {
  const B = onCurve(seed);
  // walk the JS ladder and assert every doubling has y!=0 and every add has Rx!=Qx (no exceptional escape)
  const BN_X = 4965661367192848881n, NBITS = 63, bit = (k) => (BN_X >> BigInt(NBITS - 1 - k)) & 1n;
  let R = { x: B.x, y: B.y }, ok = true;
  try {
    for (let k = 1; k < NBITS; k++) {
      if (eq(R.y, Fp2.ZERO)) { ok = false; break; }              // would be denom-zero in dbl
      const d = affDoubleJS(R.x, R.y); R = d.R;
      if (bit(k)) { if (eq(R.x, B.x)) { ok = false; break; } const a = affAddJS(R.x, R.y, B.x, B.y); R = a.R; }
    }
  } catch (e) { ok = false; }
  // 'ok' true means the ladder ran with NO exceptional case for this non-subgroup B (endo check then fails -> reject, tested in _g2_forge)
  if (!ok) allNonsubForced = false;
}
rec('non-subgroup B ladders complete WITHOUT hitting an exceptional escape (endo then rejects them)', allNonsubForced);

console.log('\n===== PART 4: reachability — can the covenant be fed an exceptional/off-trajectory R? =====');
// Build a REAL interior miller chunk WITH successor pin. Confirm: honest ACCEPTS; and feeding a
// substituted committed stateIn (e.g. R replaced by (0,0)) while the spent-token commitment stays
// the HONEST predecessor-output hash makes covIn REJECT (hash mismatch) -> (0,0) uninjectable.
const succSpk = '00'.repeat(35); // any 35-byte P2SH32 (pin target); irrelevant to covIn test
function buildChunk(lo, hi) {
  const src = genChunk(lo, hi, false, false, succSpk);
  writeFileSync('generated/_exc_chunk.cash', src);
  const raw = compileFileBytecodeRaw('generated/_exc_chunk.cash');
  return Uint8Array.from([...raw]);
}
// choose a window whose first pair0 op is a doubling so R is consumed by affDbl first
function firstPair0IsDbl(lo, hi) { for (let i = lo; i < hi; i++) { if (ops[i].j === 0 && (ops[i].t === 'dl' || ops[i].t === 'al' || ops[i].t === 'pp')) return ops[i].t === 'dl'; } return false; }
let win = null;
for (let lo = 2; lo < 300; lo += 3) { const hi = lo + 6; if (firstPair0IsDbl(lo, hi)) { win = [lo, hi]; break; } }
const [lo, hi] = win;
const locking = buildChunk(lo, hi);
const honestIn = inState(lo).map(r);
const honestOut = outState(hi).map(r);
const honestLams = chunkLambdas(lo, hi).map(r);
// The successor pin requires outputs.length==1 and output spk == succSpk. To satisfy covIn+covOut we
// must ALSO route the output to succSpk (P2SH32). Use a token output whose locking = succSpk bytes.
function evalWith(spentCommit, pushedIn, lams, outLimbs) {
  const outLock = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32), 0x87]); // OP_HASH256 <32> OP_EQUAL = 35B P2SH32
  const succ = outLock; // and set succSpk to match below
  const pushed = [...pushedIn, ...lams];
  const argBytes = Uint8Array.from([...pushed].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(spentCommit) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: [{ lockingBytecode: succ, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 },
  };
  const st = vm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, err: st.error ? String(st.error).slice(0, 80) : undefined };
}
// Need succSpk in the compiled chunk to equal outLock. Rebuild chunk with real succSpk = outLock hex.
const outLockHex = Buffer.from([0xaa, 0x20, ...new Uint8Array(32), 0x87]).toString('hex');
function buildChunkSucc(lo, hi, spkHex) { const src = genChunk(lo, hi, false, false, spkHex); writeFileSync('generated/_exc_chunk.cash', src); return Uint8Array.from([...compileFileBytecodeRaw('generated/_exc_chunk.cash')]); }
const locking2 = buildChunkSucc(lo, hi, outLockHex);
// recompute locking-dependent closure
function evalWith2(spentCommit, pushedIn, lams, outLimbs) {
  const outLock = Uint8Array.from([0xaa, 0x20, ...new Uint8Array(32), 0x87]);
  const pushed = [...pushedIn, ...lams];
  const argBytes = Uint8Array.from([...pushed].reverse().flatMap((c) => [...pushInt(c)]));
  const unlocking = Uint8Array.from([...padPush(argBytes.length, TARGET_UNLOCK), ...argBytes]);
  const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
  const program = { inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking2, valueSatoshis: 1000n, token: tok(spentCommit) }], transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: [{ lockingBytecode: outLock, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) }], locktime: 0 } };
  const st = vm.evaluate(program); const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, err: st.error ? String(st.error).slice(0, 80) : undefined };
}
const honestCommit = commitBin(honestIn);
rec(`REAL pinned miller chunk [${lo},${hi}) honest ACCEPTS`, evalWith2(honestCommit, honestIn, honestLams, honestOut).accepted === true);
// forge: corrupt first lambda -> reject
{ const f = honestLams.slice(); f[0] = r(f[0] + 1n); rec('REAL pinned chunk forged-lambda REJECTS', evalWith2(honestCommit, honestIn, f, honestOut).accepted === false); }
// INJECT R=(0,0): replace the 4 R limbs (indices 16..19 of inState: [f0..15, R0x a b, R0y a b, ...])
// find R0 offset: inState = [...12 f, ...ptL(pts), ...] -- actually withPts inserts ptL after first 16.
// stateLimbs = [12 f, 4 R, 12 c, 12 cInv]; withPts(limbs) = [fr(16=12f+? )]. Re-derive from gen: withPts takes first16.
// From gen_miller_affine: stateLimbs(s)=[...f12(16?)]. f12limbs=12. r4limbs=4 => first 16 = 12f+4R. withPts slices first16 as 'fr', inserts ptL, then rest. So R limbs are indices 12..15 of the FINAL inState.
const R_OFF = 12;
{
  const inj = honestIn.slice(); inj[R_OFF] = 0n; inj[R_OFF + 1] = 0n; inj[R_OFF + 2] = 0n; inj[R_OFF + 3] = 0n;
  // (a) ISOLATED attacker who also controls the spent commitment (sets it to hash(inj)):
  //     the chunk would compute affDbl((0,0),lam)-free-accept; output pinned. Show it 'accepts' in isolation.
  const injCommit = commitBin(inj);
  // recompute the honest output for this injected input is NOT known; use a free lambda and let covOut pin whatever.
  // We must supply outLimbs = the chunk's actual computed output. Since we can't easily recompute, we instead
  // test the DECISIVE chain constraint (b) below. For (a), just check covIn passes with matching commit:
  //   push inj, spent=hash(inj). If covIn passes, VM proceeds (may fail later on unknown out); we only care covIn.
  // (b) CHAIN constraint: spent commitment stays the HONEST predecessor-output hash, attacker pushes inj.
  const chainRej = evalWith2(honestCommit, inj, honestLams, honestOut).accepted === false;
  rec('CHAIN: injecting R=(0,0) while spent-commit is honest -> covIn REJECTS (uninjectable mid-chain)', chainRej);
  // Also: any substituted R (not just origin) with honest spent-commit -> reject
  const inj2 = honestIn.slice(); inj2[R_OFF] = r(inj2[R_OFF] + 1n);
  rec('CHAIN: substituting R (off-trajectory) while spent-commit is honest -> covIn REJECTS', evalWith2(honestCommit, inj2, honestLams, honestOut).accepted === false);
}

console.log('\n===== SUMMARY =====');
const allPass = Object.values(results).every(Boolean);
console.log(JSON.stringify({ allPass, results }, null, 0));
