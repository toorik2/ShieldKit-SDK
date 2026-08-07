import { repoPath as vcRepoPath } from '#repo-paths';
// Manufacture a self-consistent BN254 Groth16 instance (VK + proof + public
// inputs + golden checkpoints) with noble — NO proving key, NO external data.
// We choose the VK scalars (toxic waste), so a *valid* proof is just algebra:
//   verification: e(-A,B)·e(alpha,beta)·e(vkx,gamma)·e(C,delta) == 1
//   in exponents (all points = scalar·generator):  -a·b + α·β + X·γ + c·δ ≡ 0 (mod r)
//   => c = (a·b - α·β - X·γ)·δ⁻¹ (mod r),  X = ic0 + s1·ic1 + s2·ic2
// Writes out/checkpoints/pairing-vectors.json in the exact shape the graders read.
import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { bn254 } from '../node_modules/@noble/curves/esm/bn254.js';

const { Fr, Fp12 } = bn254.fields;
const G1 = bn254.G1.Point.BASE;
const G2 = bn254.G2.Point.BASE;

// deterministic scalars from a label (reproducible)
const scalar = (label) => Fr.create(BigInt('0x' + createHash('sha256').update(label).digest('hex')));

const alpha = scalar('alpha'), beta = scalar('beta'), gamma = scalar('gamma'), delta = scalar('delta');
const ic0 = scalar('ic0'), ic1 = scalar('ic1'), ic2 = scalar('ic2');
const a = scalar('proofA'), b = scalar('proofB');
const s1 = 123456789n, s2 = 987654321n; // public inputs

// X = ic0 + s1*ic1 + s2*ic2 (mod r); c balances the verification equation.
const X = Fr.add(Fr.add(ic0, Fr.mul(ic1, Fr.create(s1))), Fr.mul(ic2, Fr.create(s2)));
const c = Fr.mul(Fr.sub(Fr.sub(Fr.mul(a, b), Fr.mul(alpha, beta)), Fr.mul(X, gamma)), Fr.inv(delta));

// points
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

// sanity: valid instance verifies, invalid (s2+1) does not
const verifies = (pairs) => Fp12.eql(bn254.pairingBatch(pairs, true), Fp12.ONE);
const validVerified = verifies(pairsFor(s1, s2));
const invalidVerified = verifies(pairsFor(s1, s2 + 1n));
if (!validVerified) throw new Error('manufactured instance does NOT verify — algebra bug');
if (invalidVerified) throw new Error('tampered instance verifies — should not');

// golden 4-pair Miller (NO final exp), 12 limbs x 32-byte BE hex
const miller = bn254.pairingBatch(pairsFor(s1, s2), false);
const limbs = (f) => [
  f.c0.c0.c0, f.c0.c0.c1, f.c0.c1.c0, f.c0.c1.c1, f.c0.c2.c0, f.c0.c2.c1,
  f.c1.c0.c0, f.c1.c0.c1, f.c1.c1.c0, f.c1.c1.c1, f.c1.c2.c0, f.c1.c2.c1,
];
const millerHex = limbs(miller).map((n) => n.toString(16).padStart(64, '0')).join('');

// serialize to the graders' JSON shape (decimal strings)
const j1 = (P) => { const p = P.toAffine(); return { x: p.x.toString(), y: p.y.toString() }; };
const j2 = (P) => { const p = P.toAffine(); return { x: { c0: p.x.c0.toString(), c1: p.x.c1.toString() }, y: { c0: p.y.c0.toString(), c1: p.y.c1.toString() } }; };

const out = {
  _note: 'LOCALLY MANUFACTURED fixture (own toxic-waste VK) for harness/optimization. NOT the official fixed statement — re-bake the official VK before any leaderboard submission.',
  curve: 'bn254',
  vk: { alpha: j1(alphaP), beta: j2(betaP), gamma: j2(gammaP), delta: j2(deltaP), ic: ic.map(j1) },
  proof: { a: j1(A), b: j2(B), c: j1(C) },
  publicInputs: [s1.toString(), s2.toString()],
  invalid: { publicInputs: [s1.toString(), (s2 + 1n).toString()] },
  golden: { millerHex, verified: validVerified, invalidVerified },
};
mkdirSync(vcRepoPath('out/checkpoints'), { recursive: true });
writeFileSync(vcRepoPath('out/checkpoints/pairing-vectors.json'), JSON.stringify(out, null, 2));
console.log(`valid verifies=${validVerified}  invalid verifies=${invalidVerified}  millerHex=${millerHex.length / 2}B`);
console.log('wrote out/checkpoints/pairing-vectors.json');
