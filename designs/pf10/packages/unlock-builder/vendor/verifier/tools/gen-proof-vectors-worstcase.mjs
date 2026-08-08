import { repoPath as vcRepoPath } from '#repo-paths';
// Manufacture a VALID WORST-CASE BN254 Groth16 instance against OUR EXACT VK.
// Identical VK scalars to tools/gen-proof-vectors.mjs (deterministic sha256 toxic
// waste), so the VK points are byte-identical — only the public inputs and the
// re-solved proof C differ. Public inputs = 2^253-1 (dense near-r), the worst case
// flagged in zk-verifier-bench issues/2.
//   verification: e(-A,B)·e(alpha,beta)·e(vkx,gamma)·e(C,delta) == 1
//   c = (a·b - α·β - X·γ)·δ⁻¹ (mod r),  X = ic0 + s1·ic1 + s2·ic2
// Writes out/checkpoints/pairing-vectors-worstcase.json (same shape as the default).
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { bn254 } from '../node_modules/@noble/curves/esm/bn254.js';

const { Fr, Fp12 } = bn254.fields;
const G1 = bn254.G1.Point.BASE;
const G2 = bn254.G2.Point.BASE;

const scalar = (label) => Fr.create(BigInt('0x' + createHash('sha256').update(label).digest('hex')));

const alpha = scalar('alpha'), beta = scalar('beta'), gamma = scalar('gamma'), delta = scalar('delta');
const ic0 = scalar('ic0'), ic1 = scalar('ic1'), ic2 = scalar('ic2');
const a = scalar('proofA'), b = scalar('proofB');

// WORST CASE: dense near-r public inputs. 2^253-1 = all of bits 0..252 set, < r.
const WORST = (1n << 253n) - 1n;
const s1 = WORST, s2 = WORST;

const X = Fr.add(Fr.add(ic0, Fr.mul(ic1, Fr.create(s1))), Fr.mul(ic2, Fr.create(s2)));
const c = Fr.mul(Fr.sub(Fr.sub(Fr.mul(a, b), Fr.mul(alpha, beta)), Fr.mul(X, gamma)), Fr.inv(delta));

const alphaP = G1.multiply(alpha), betaP = G2.multiply(beta);
const gammaP = G2.multiply(gamma), deltaP = G2.multiply(delta);
const ic = [G1.multiply(ic0), G1.multiply(ic1), G1.multiply(ic2)];
const A = G1.multiply(a), B = G2.multiply(b), C = G1.multiply(c);

const vkxPoint = (i0, i1) => ic[0].add(ic[1].multiply(i0)).add(ic[2].multiply(i1));
const pairsFor = (i0, i1) => [
  { g1: A.negate(), g2: B },
  { g1: alphaP, g2: betaP },
  { g1: vkxPoint(i0, i1), g2: gammaP },
  { g1: C, g2: deltaP },
];

// SINGLETON/NOBLE REFERENCE: full pairing product must equal Fp12.ONE.
const verifies = (pairs) => Fp12.eql(bn254.pairingBatch(pairs, true), Fp12.ONE);
const validVerified = verifies(pairsFor(s1, s2));
const invalidVerified = verifies(pairsFor(s1, s2 + 1n)); // tamper: in1+1
if (!validVerified) throw new Error('worst-case instance does NOT verify on noble — algebra bug');
if (invalidVerified) throw new Error('worst-case tamper verifies — should not');

// CONFIRM VK IDENTITY to the default fixture (must be byte-identical so baked chunks apply).
const def = JSON.parse(readFileSync(vcRepoPath('out/checkpoints/pairing-vectors.json'), 'utf8'));
const j1 = (P) => { const p = P.toAffine(); return { x: p.x.toString(), y: p.y.toString() }; };
const j2 = (P) => { const p = P.toAffine(); return { x: { c0: p.x.c0.toString(), c1: p.x.c1.toString() }, y: { c0: p.y.c0.toString(), c1: p.y.c1.toString() } }; };
const vk = { alpha: j1(alphaP), beta: j2(betaP), gamma: j2(gammaP), delta: j2(deltaP), ic: ic.map(j1) };
const vkMatch = JSON.stringify(vk) === JSON.stringify(def.vk);
if (!vkMatch) throw new Error('worst-case VK != default fixture VK — baked chunks would be invalid');

// golden 4-pair Miller (NO final exp)
const miller = bn254.pairingBatch(pairsFor(s1, s2), false);
const limbs = (f) => [
  f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1,
  f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
];
const millerHex = limbs(miller).map((n) => n.toString(16).padStart(64, '0')).join('');

const out = {
  _note: 'WORST-CASE fixture (dense public inputs 2^253-1) against the SAME toxic-waste VK as pairing-vectors.json. For completeness-bug investigation (zk-verifier-bench issues/2). VK byte-identical to default ⇒ baked chunks apply unchanged.',
  curve: 'bn254',
  vk,
  proof: { a: j1(A), b: j2(B), c: j1(C) },
  publicInputs: [s1.toString(), s2.toString()],
  invalid: { publicInputs: [s1.toString(), (s2 + 1n).toString()] },
  golden: { millerHex, verified: validVerified, invalidVerified },
};
mkdirSync(vcRepoPath('out/checkpoints'), { recursive: true });
writeFileSync(vcRepoPath('out/checkpoints/pairing-vectors-worstcase.json'), JSON.stringify(out, null, 2));
console.log(`WORST-CASE valid verifies=${validVerified}  invalid verifies=${invalidVerified}`);
console.log(`vk byte-identical to default fixture: ${vkMatch}`);
console.log(`public inputs: s1=s2=2^253-1 = ${s1}`);
console.log(`bit length of s1: ${s1.toString(2).length}`);
console.log('wrote out/checkpoints/pairing-vectors-worstcase.json');
