// ADVERSARIAL forge battery for T5-1 (g2check delete + fold-into-miller + genesis relocation).
// T5-1 replaced the standalone g2check subgroup ladder with:
//   (A) a RELOCATED B-on-twist(E'(Fp2)) membership check in the vkx GENESIS chunk, and
//   (B) a FOLDED G2-subgroup check in the final miller window:  R_end == -psi^3(B)
//       where R_end = [6x+2]B + psi(B) - psi^2(B) (the pair0 ladder result).
// Soundness rests on ker(phi) ∩ E'(Fp2) == G2 EXACTLY (proven in intel/validation/T5-1/), which is
// scoped to ON-TWIST points — hence (A) must gate (B). This harness attacks BOTH surfaces on the
// REAL libauth BCH-2026 VM, compiling the EXACT deployed check source against the SAME libraries:
//   1. honest B (proof.b, in G2)          -> on-twist ACCEPT   + fold ACCEPT
//   2. NOT-on-twist B (perturbed y)       -> on-twist REJECT   (surface A)
//   3. wrong-subgroup cofactor B ([r]*P0, order | h2, not r, on twist) -> fold REJECT (surface B)
//   4. small-subgroup B (order-10069, on twist)                        -> fold REJECT (surface B)
// R_end / psi^2(B) are computed by REAL point arithmetic (same psi the circuit uses); the attacker
// cannot fake R_end at deploy time (the pinned affine ladder forces it), so feeding the TRUE R_end
// for each adversarial B is the decisive discrimination test of the fold.
//   node _atk_cofactor.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bn254, CATEGORY, decl, compileFileBytecode, proof } from './_millermath.mjs';
import {
  bigIntToVmNumber, encodeDataPush, hash256, encodeLockingBytecodeP2sh32, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const red = (v) => ((BigInt(v) % P) + P) % P;

// ---- BN254 twist point arithmetic (noble G2.Point) + the EXACT circuit psi (from _millermath) ----
const { Fp, Fp2 } = bn254.fields;
const Pt = bn254.G2.Point, ZERO = Pt.ZERO;
const r = Pt.Fn.ORDER;                        // scalar field order (G2 subgroup order)
const x = 4965661367192848881n;               // BN_X
const SIX_X2 = 6n * x + 2n;
const h2 = 2n * P - r;                         // twist cofactor (E'(Fp2) has order r*h2, cyclic)
const n2 = r * h2;
const Fp2B = Fp2.fromBigTuple([
  19485874751759354771024239261021720505790618469301721065564631296452457478373n,
  266929791119991161246907387137283842545076965332900288569378510910307636690n]);
const PSI_X = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 3n);
const PSI_Y = Fp2.pow(Fp2.NONRESIDUE, (Fp.ORDER - 1n) / 2n);
const psiAff = (X, Y) => [Fp2.mul(Fp2.frobeniusMap(X, 1), PSI_X), Fp2.mul(Fp2.frobeniusMap(Y, 1), PSI_Y)];
const isO = (Q) => Q.is0();
function mul(Q, k) { let neg = k < 0n; let e = neg ? -k : k; let acc = ZERO, base = Q; while (e > 0n) { if (e & 1n) acc = acc.add(base); base = base.double(); e >>= 1n; } return neg ? acc.negate() : acc; }
function psiPoint(Q) { if (isO(Q)) return ZERO; const a = Q.toAffine(); const [nx, ny] = psiAff(a.x, a.y); return Pt.fromAffine({ x: nx, y: ny }); }
const REND = (Q) => mul(Q, SIX_X2).add(psiPoint(Q)).subtract(psiPoint(psiPoint(Q))); // [6x+2]Q+psi(Q)-psi^2(Q)
const Q2 = (Q) => psiPoint(psiPoint(Q));                                              // psi^2(Q)
const affOf = (Q) => { const a = Q.toAffine(); return { xa: red(a.x.c0), xb: red(a.x.c1), ya: red(a.y.c0), yb: red(a.y.c1) }; };
// random on-twist point of full order (via noble's own sampler on the twist)
function randTwistPoint() { for (let i = 0; i < 64; i++) { const k = (BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(40))].map(v => v.toString(16).padStart(2, '0')).join('')) % n2) + 1n; const Q = mul(Pt.BASE, k % r).add(mul(cofGen(), k)); if (!isO(Q)) return Q; } throw new Error('sampler'); }
let _cof = null;
function cofGen() { // a fixed generator of a nontrivial twist-cofactor part (order | h2, not r)
  if (_cof) return _cof;
  for (let i = 1; ; i++) { const cand = mul(hashToTwist(i), r); if (!isO(cand)) { _cof = cand; return cand; } }
}
function hashToTwist(seed) { // deterministic on-twist point (any order)
  for (let s = seed; ; s++) { const xx = Fp2.fromBigTuple([BigInt(s) * 1000003n % Fp.ORDER, BigInt(s) * 7919n % Fp.ORDER]); const rhs = Fp2.add(Fp2.mul(Fp2.sqr(xx), xx), Fp2B); let y; try { y = Fp2.sqrt(rhs); } catch { continue; } if (y && Fp2.eql(Fp2.sqr(y), rhs)) return Pt.fromAffine({ x: xx, y }); }
}
import { webcrypto as crypto } from 'node:crypto';

// ======================================================================================
// CONTRACT (A): the RELOCATED vkx-genesis B-on-twist check (exact deployed source + helpers)
// ======================================================================================
const Pstr = P.toString();
const B2 = [19485874751759354771024239261021720505790618469301721065564631296452457478373n,
            266929791119991161246907387137283842545076965332900288569378510910307636690n];
const onTwistSrc = `pragma cashscript ^0.14.0;
function addFp(int a,int b) returns(int){return (a+b)%${Pstr};}
function subFp(int a,int b) returns(int){return (a-b+${Pstr})%${Pstr};}
function mulFp(int a,int b) returns(int){return (a*b)%${Pstr};}
function fp2Add(int a0,int a1,int b0,int b1) returns(int,int){return addFp(a0,b0),addFp(a1,b1);}
function fp2Mul(int a0,int a1,int b0,int b1) returns(int,int){int v0=mulFp(a0,b0);int v1=mulFp(a1,b1);return subFp(v0,v1),subFp(mulFp(addFp(a0,a1),addFp(b0,b1)),addFp(v0,v1));}
contract OnTwist(){
    function spend(int Bxa,int Bxb,int Bya,int Byb, bytes unused zeroPadding){
        (int oxa,int oxb) = fp2Mul(Bxa, Bxb, Bxa, Bxb);
        (int oya,int oyb) = fp2Mul(oxa, oxb, Bxa, Bxb);
        (int ora,int orb) = fp2Add(oya, oyb, ${B2[0]}, ${B2[1]});
        (int oba,int obb) = fp2Mul(Bya, Byb, Bya, Byb);
        require(oba == ora); require(obb == orb);
    }
}
`;

// ======================================================================================
// CONTRACT (B): the FOLDED subgroup check (exact deployed source; lazy-lib psi/fp2Neg)
//   require(R_end == (psi^3(B).x, -psi^3(B).y)) with q3 = psi(q2), q2 = psi^2(B) witnessed.
// ======================================================================================
const foldSrc = `pragma cashscript ^0.14.0;
import "../../../singleton/bn254/lib/lazy/Bn254LazyAff.cash";
contract Fold(){
    function spend(int crxa,int crxb,int crya,int cryb, int q2xa,int q2xb,int q2ya,int q2yb, bytes unused zeroPadding){
        (int q3xa,int q3xb,int q3ya,int q3yb) = psi(q2xa,q2xb,q2ya,q2yb);
        (int nq3ya,int nq3yb) = fp2Neg(q3ya, q3yb, 64);
        require(crxa == q3xa % ${Pstr}); require(crxb == q3xb % ${Pstr});
        require(crya == nq3ya % ${Pstr}); require(cryb == nq3yb % ${Pstr});
    }
}
`;

// ---- P2SH eval on the real VM (byte convention from unified_affine) ----
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh32(hash256(redeem));
const padBytes = (total) => { const b = Math.max(2, total); const n = b <= 76 ? b - 1 : b <= 257 ? b - 2 : b - 3; return encodeDataPush(new Uint8Array(n)); };
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const tok = (commitment) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment } });
const TARGET_UNLOCK = 10000;
function runContract(name, src, args) {
  const probe = join(GEN, `_atk_cof_${name}.cash`);
  writeFileSync(probe, src);
  let redeem;
  try { redeem = Uint8Array.from([...compileFileBytecode(probe)]); }
  catch (e) { return { accepted: false, error: 'compile:' + String(e?.message ?? e) }; }
  const rpush = encodeDataPush(redeem);
  const locking = p2shSpk(redeem);
  const argb = Uint8Array.from([...args].reverse().flatMap((c) => [...pushInt(c)]));
  const pad = padBytes(TARGET_UNLOCK - argb.length - rpush.length);
  const unlocking = Uint8Array.from([...pad, ...argb, ...rpush]);
  const commit = new Uint8Array(32); // no covIn in these contracts -> commitment unused
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs: [{ lockingBytecode: locking, valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  return { accepted, error: st.error ?? null };
}
const onTwist = (Baff) => runContract('ontwist', onTwistSrc, [Baff.xa, Baff.xb, Baff.ya, Baff.yb]).accepted;
const fold = (Q) => { const R = affOf(REND(Q)), q = affOf(Q2(Q)); return runContract('fold', foldSrc, [R.xa, R.xb, R.ya, R.yb, q.xa, q.xb, q.ya, q.yb]).accepted; };

// ======================================================================================
// BUILD THE ADVERSARIAL POINTS + RUN
// ======================================================================================
const results = [];
const record = (label, surface, got, expect) => { const ok = got === expect; results.push({ label, surface, accepted: got, expect, ok }); console.log(`  [${surface}] ${label}: accepted=${got} expect=${expect} ${ok ? 'OK' : '*** MISMATCH — A1 FAILURE ***'}`); };

// 1) honest B = proof.b (real instance twist point, in G2)
const Bhonest = proof.b;
console.log('\n=== honest B (proof.b) ===  in G2 ([r]B==O)?', isO(mul(Bhonest, r)), ' on twist?', true);
const BhAff = affOf(Bhonest);
record('honest_B', 'on-twist', onTwist(BhAff), true);   // on twist -> ACCEPT
record('honest_B', 'fold', fold(Bhonest), true);        // in G2   -> fold ACCEPT

// 2) NOT-on-twist B: perturb honest B.y by +1 so y^2 != x^3 + b2
const BnotAff = { ...BhAff, ya: red(BhAff.ya + 1n) };
const notOnTwist = Fp2.eql(Fp2.sqr(Fp2.fromBigTuple([BnotAff.ya, BnotAff.yb])), Fp2.add(Fp2.mul(Fp2.sqr(Fp2.fromBigTuple([BnotAff.xa, BnotAff.xb])), Fp2.fromBigTuple([BnotAff.xa, BnotAff.xb])), Fp2B));
console.log('\n=== not-on-twist B (honest.y + 1) ===  actually off twist?', !notOnTwist);
record('not_on_twist_B', 'on-twist', onTwist(BnotAff), false); // off twist -> REJECT

// 3) wrong-subgroup cofactor B: [r]*P0 (order divides h2, not r) — ON the twist, OFF G2
const P0 = randTwistPoint();
const Bcof = mul(P0, r);
console.log('\n=== cofactor B ([r]*P0) ===  nonzero?', !isO(Bcof), ' [r]B==O (in G2)?', isO(mul(Bcof, r)), ' on twist?', true);
if (isO(Bcof)) throw new Error('cofactor sample degenerate (P0 happened to be in G2)');
record('cofactor_B', 'on-twist', onTwist(affOf(Bcof)), true);  // still ON twist -> on-twist ACCEPTS
record('cofactor_B', 'fold', fold(Bcof), false);               // off G2 -> fold REJECT

// 4) small-subgroup B: order-10069 point ([n2/10069]*P0) — ON twist, OFF G2
const q0 = 10069n;
let Bsmall = mul(randTwistPoint(), n2 / q0);
for (let i = 0; i < 40 && isO(Bsmall); i++) Bsmall = mul(randTwistPoint(), n2 / q0);
console.log('\n=== small-subgroup B (order-10069) ===  nonzero?', !isO(Bsmall), ' [10069]B==O?', isO(mul(Bsmall, q0)), ' [r]B==O (in G2)?', isO(mul(Bsmall, r)));
if (isO(Bsmall)) throw new Error('small-subgroup sample degenerate');
record('small_subgroup_B', 'on-twist', onTwist(affOf(Bsmall)), true); // ON twist -> ACCEPT
record('small_subgroup_B', 'fold', fold(Bsmall), false);              // off G2 -> fold REJECT

// ======================================================================================
// VERDICT
// ======================================================================================
const allOk = results.every((r) => r.ok);
const honestOk = results.filter((r) => r.label === 'honest_B').every((r) => r.accepted === true);
const forgeryRejected = results.filter((r) => r.expect === false).every((r) => r.accepted === false);
console.log('\n================= _atk_cofactor VERDICT =================');
console.log('honest B accepts (on-twist + fold)      :', honestOk);
console.log('every forgery rejects (not-twist/cofactor/small):', forgeryRejected);
console.log('all expectations met                    :', allOk);
console.log(JSON.stringify({ allOk, honestOk, forgeryRejected, results }, null, 2));
if (!allOk) process.exit(1);
