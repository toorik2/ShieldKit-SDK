#!/usr/bin/env node
// Scenario N sumcheck/MLE floor probe.
//
// This models the tempting "replace the 103-coeff bigQ Horner by a logarithmic
// sumcheck" idea over the real Scenario-N bigQ. It demonstrates the exact place
// the coefficient mass reappears: the verifier still needs a bound opening of
// the coefficient multilinear extension C~(r). If C~(r) is free, a cheating
// prover forges any target q(z).
//
// Usage:
//   SCENARIO_N_PAIRING_DIR=/path/to/build/chunked/pairing \
//     SZ_ALLAFF=1 L17SEL=1 node tools/scenario-n-sumcheck-mle-floor.mjs
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const pairingDir = process.env.SCENARIO_N_PAIRING_DIR;
if (!pairingDir) {
  throw new Error('set SCENARIO_N_PAIRING_DIR to the build/chunked/pairing directory');
}
const szPath = join(pairingDir, '_szmath.mjs');
const genPath = join(pairingDir, 'gen_miller_sz.mjs');
if (!existsSync(szPath)) throw new Error(`missing ${szPath}`);
if (!existsSync(genPath)) throw new Error(`missing ${genPath}`);

const moduleUrl = (name) => pathToFileURL(join(pairingDir, name)).href;
const [sz, szGen] = await Promise.all([
  import(moduleUrl('_szmath.mjs')),
  import(moduleUrl('gen_miller_sz.mjs')),
]);

const mod = sz.mod;
const mmul = sz.mmul;
const madd = sz.madd;
const msub = sz.msub;
const minv = sz.minv;
const be4 = sz.be4;
const be32 = sz.be32;
const hash256 = sz.hash256;
const inv2 = minv(2n);
const SUMCHECK_TAG = 'BN254-SZN-SUMCHECK/v0';
const json = (x) => JSON.stringify(x, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
const short = (x) => `${BigInt(x).toString().slice(0, 24)}...`;

function ceilPow2(n) {
  let p = 1;
  let bits = 0;
  while (p < n) {
    p <<= 1;
    bits++;
  }
  return { p, bits };
}

function fieldFromHash(parts) {
  return mod(BigInt(`0x${hash256(Buffer.concat(parts)).toString('hex')}`));
}

function challenge(label, round, values, previous) {
  return fieldFromHash([
    Buffer.from(label, 'ascii'),
    be4(round),
    ...previous.map(be32),
    ...values.map(be32),
  ]);
}

function qeval012(y0, y1, y2, x) {
  // Quadratic interpolation from values at x=0,1,2.
  const l0 = mmul(mmul(msub(x, 1n), msub(x, 2n)), inv2);
  const l1 = mod(-mmul(x, msub(x, 2n)));
  const l2 = mmul(mmul(x, msub(x, 1n)), inv2);
  return madd(madd(mmul(y0, l0), mmul(y1, l1)), mmul(y2, l2));
}

function bitAt(i, bit) {
  return (i >> bit) & 1;
}

function mleEval(values, point) {
  let acc = 0n;
  for (let i = 0; i < values.length; i++) {
    if (values[i] === 0n) continue;
    let weight = 1n;
    for (let bit = 0; bit < point.length; bit++) {
      weight = mmul(weight, bitAt(i, bit) ? point[bit] : msub(1n, point[bit]));
    }
    acc = madd(acc, mmul(values[i], weight));
  }
  return acc;
}

function zMle(point, z) {
  let acc = 1n;
  let zPow = z;
  for (const r of point) {
    acc = mmul(acc, madd(msub(1n, r), mmul(r, zPow)));
    zPow = mmul(zPow, zPow);
  }
  return acc;
}

function splitEval(coeffs, point, z) {
  return mmul(mleEval(coeffs, point), zMle(point, z));
}

function sumOverSuffix(coeffs, prefix, rounds, z) {
  const rem = rounds - prefix.length;
  let total = 0n;
  for (let mask = 0; mask < (1 << rem); mask++) {
    const point = [...prefix];
    for (let j = 0; j < rem; j++) point.push(BigInt((mask >> j) & 1));
    total = madd(total, splitEval(coeffs, point, z));
  }
  return total;
}

function honestSumcheck(coeffs, rounds, z) {
  const transcript = [];
  const challenges = [];
  let claim = sumOverSuffix(coeffs, [], rounds, z);
  const initialClaim = claim;
  for (let round = 0; round < rounds; round++) {
    const y0 = sumOverSuffix(coeffs, [...challenges, 0n], rounds, z);
    const y1 = sumOverSuffix(coeffs, [...challenges, 1n], rounds, z);
    const y2 = sumOverSuffix(coeffs, [...challenges, 2n], rounds, z);
    if (madd(y0, y1) !== claim) throw new Error(`honest sumcheck consistency failed at round ${round}`);
    const r = challenge(SUMCHECK_TAG, round, [y0, y1, y2], challenges);
    claim = qeval012(y0, y1, y2, r);
    transcript.push([y0, y1, y2]);
    challenges.push(r);
  }
  const cMle = mleEval(coeffs, challenges);
  const zOpen = zMle(challenges, z);
  return {
    transcript,
    challenges,
    initialClaim,
    finalClaim: claim,
    cMle,
    zOpen,
    finalCheck: claim === mmul(cMle, zOpen),
  };
}

function forgedFreeOpeningSumcheck(target, rounds, z) {
  const transcript = [];
  const challenges = [];
  let claim = target;
  for (let round = 0; round < rounds; round++) {
    // Any degree-2 polynomial satisfying g(0)+g(1)=claim passes the
    // sumcheck round check. The final free C~ opening repairs the rest.
    const y0 = 0n;
    const y1 = claim;
    const y2 = 0n;
    const r = challenge(SUMCHECK_TAG, round, [y0, y1, y2], challenges);
    claim = qeval012(y0, y1, y2, r);
    transcript.push([y0, y1, y2]);
    challenges.push(r);
  }
  const zOpen = zMle(challenges, z);
  if (zOpen === 0n) throw new Error('unexpected zero z-ML extension in forged transcript');
  const freeCMle = mmul(claim, minv(zOpen));
  return {
    transcript,
    challenges,
    finalClaim: claim,
    freeCMle,
    zOpen,
    finalCheckWithFreeCMle: claim === mmul(freeCMle, zOpen),
  };
}

const t = sz.trajectory();
const bigQ = szGen.closePushedArgsC().slice(4).map(BigInt);
const { p: domainSize, bits: rounds } = ceilPow2(bigQ.length);
const coeffs = Array.from({ length: domainSize }, (_, i) => mod(bigQ[i] ?? 0n));
const honestQz = sz.peval(bigQ, t.z);
const honest = honestSumcheck(coeffs, rounds, t.z);
if (honest.initialClaim !== honestQz) {
  throw new Error(`honest sumcheck initial claim mismatch: ${honest.initialClaim} != ${honestQz}`);
}

const forgedTargetQz = madd(honestQz, 1n);
const forged = forgedFreeOpeningSumcheck(forgedTargetQz, rounds, t.z);

const roundPolyValues = rounds * 3;
const constrainedRoundValues = rounds * 2;
const result = {
  pairingDir,
  env: {
    SZ_ALLAFF: process.env.SZ_ALLAFF ?? '',
    L17SEL: process.env.L17SEL ?? '',
  },
  realBigQ: {
    coeffs: bigQ.length,
    domainSize,
    rounds,
    zPrefix: short(t.z),
    honestQzPrefix: short(honestQz),
    paddedZeroCoeffs: domainSize - bigQ.length,
  },
  honestSumcheck: {
    roundPolyValues,
    finalCheck: honest.finalCheck,
    initialClaimMatchesBigQz: honest.initialClaim === honestQz,
    cMlePrefix: short(honest.cMle),
    zOpenPrefix: short(honest.zOpen),
  },
  forgedFreeOpening: {
    targetQzPrefix: short(forgedTargetQz),
    differsFromHonestQz: forgedTargetQz !== honestQz,
    finalCheckWithFreeCMle: forged.finalCheckWithFreeCMle,
    freeCMlePrefix: short(forged.freeCMle),
    verdict: 'UNSOUND if C~(r) is supplied as a free scalar opening; the prover can satisfy every round and repair the final check.',
  },
  byteFloor: {
    currentBigQBlobBytes: bigQ.length * 32,
    paddedCoeffBlobBytes: domainSize * 32,
    sumcheckRoundPolysFullBytes: roundPolyValues * 32,
    sumcheckRoundPolysConstrainedBytes: constrainedRoundValues * 32,
    finalCMleOpeningBytes: 32,
    fullCoeffPlusFullRoundPolysBytes: bigQ.length * 32 + roundPolyValues * 32,
    fullCoeffPlusConstrainedRoundPolysBytes: bigQ.length * 32 + constrainedRoundValues * 32,
    freeOpeningTranscriptBytesFull: roundPolyValues * 32 + 32,
    freeOpeningTranscriptBytesConstrained: constrainedRoundValues * 32 + 32,
    verdict: 'A plain sumcheck only saves bytes in the free-opening model, which forges. If the verifier recomputes/binds C~(r) from the coefficients, the 103 coefficient field elements remain and the sumcheck transcript is extra overhead.',
  },
};

console.log(json(result));
