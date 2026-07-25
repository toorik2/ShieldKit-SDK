#!/usr/bin/env node
// Cheating-prover probes for Scenario N close-compression orderings.
//
// This is an algebra/protocol harness over the real Scenario-N SZ trajectory and
// the real fused close+tail bytecode. It does not claim a verifier win.
//
// Usage:
//   SCENARIO_N_PAIRING_DIR=/path/to/build/chunked/pairing \
//     SZ_ALLAFF=1 L17SEL=1 node tools/scenario-n-logclose-cheat.mjs
//
// Optional:
//   SCENARIO_N_SCALAR_TRIALS=4096
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  bigIntToVmNumber,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256 as libauthHash256,
} from '@bitauth/libauth';

const pairingDir = process.env.SCENARIO_N_PAIRING_DIR;
if (!pairingDir) {
  throw new Error('set SCENARIO_N_PAIRING_DIR to the build/chunked/pairing directory');
}

const generatedCash = join(pairingDir, 'generated', 'fused_close_tail.cash');
if (!existsSync(generatedCash)) {
  throw new Error(`missing ${generatedCash}; run "node _fuse_close_tail.mjs" in SCENARIO_N_PAIRING_DIR first`);
}

const moduleUrl = (name) => pathToFileURL(join(pairingDir, name)).href;
const [
  sz,
  szGen,
  residue,
  lib,
] = await Promise.all([
  import(moduleUrl('_szmath.mjs')),
  import(moduleUrl('gen_miller_sz.mjs')),
  import(moduleUrl('_residuemath.mjs')),
  import(moduleUrl('_millermath.mjs')),
]);

const trials = Number(process.env.SCENARIO_N_SCALAR_TRIALS ?? 4096);
if (!Number.isSafeInteger(trials) || trials < 0) {
  throw new Error('SCENARIO_N_SCALAR_TRIALS must be a non-negative safe integer');
}

const P = sz.P;
const mod = sz.mod;
const be4 = sz.be4;
const be32 = sz.be32;
const hash256 = sz.hash256;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const hex = (buf, len = 12) => Buffer.from(buf).toString('hex').slice(0, len);
const short = (x) => `${BigInt(x).toString().slice(0, 24)}...`;
const json = (x) => JSON.stringify(x, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);

function fieldFromHash(payload) {
  return mod(BigInt(`0x${hash256(payload).toString('hex')}`));
}

function hashToField(label, ...parts) {
  return fieldFromHash(Buffer.concat([Buffer.from(label, 'ascii'), ...parts]));
}

function zFromGammaOnly(gamma) {
  return hashToField('BN254-SZN-GAMMA-ONLY/v0', be32(gamma));
}

function scalarCommit(qz, nonce) {
  return hash256(Buffer.concat([
    Buffer.from('BN254-SZN-QZ-COMMIT/v0', 'ascii'),
    be32(qz),
    be4(nonce),
  ]));
}

function zFromScalarCommit(gamma, qz, nonce) {
  return hashToField('BN254-SZN-SCALAR-Z/v0', be32(gamma), scalarCommit(qz, nonce));
}

function p12At(z) {
  return sz.peval(sz.P12, z);
}

function qzForAccD(accD, z) {
  return sz.mmul(accD, sz.minv(p12At(z)));
}

function peval(poly, z) {
  return sz.peval(poly.map(BigInt), z);
}

const redeem = Uint8Array.from([...lib.compileFileBytecode(generatedCash)]);
const honestSeam = szGen.closeStateC().map(BigInt);
const honestBigQ = szGen.closePushedArgsC().slice(4).map(BigInt);
const t = sz.trajectory();

const pairs = lib.pairsFor(lib.vec.publicInputs.map(BigInt));
const { boundary: fRaw } = lib.millerBatchOps(pairs);
const { w } = residue.residueWitness(fRaw);
const wLimbs = residue.fp12limbsOf(w).map((x) => mod(BigInt(x)));
const tailInts = [...szGen.closeOutLimbs().map(BigInt), ...wLimbs];

function runClose({ seam = honestSeam, bigQ = honestBigQ } = {}) {
  const bqBlob = Uint8Array.from(bigQ.flatMap((c) => [...be32(c)]));
  const declPushes = [];
  for (const v of seam) declPushes.push(pushInt(v));
  declPushes.push(encodeDataPush(bqBlob));
  for (const v of tailInts) declPushes.push(pushInt(v));
  const argBytes = Uint8Array.from(declPushes.reverse().flatMap((push) => [...push]));
  const unlocking = Uint8Array.from([...argBytes, ...encodeDataPush(redeem)]);
  const locking = encodeLockingBytecodeP2sh32(libauthHash256(redeem));
  const token = {
    amount: 0n,
    category: lib.CATEGORY,
    nft: { capability: 'mutable', commitment: lib.commitBin(seam) },
  };
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token }],
    transaction: {
      version: 2,
      inputs: [{
        outpointTransactionHash: new Uint8Array(32),
        outpointIndex: 0,
        sequenceNumber: 0,
        unlockingBytecode: unlocking,
      }],
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  };

  const state = createVirtualMachineBch2026(false).evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined &&
    state.stack.length === 1 &&
    top !== undefined &&
    top.length === 1 &&
    top[0] === 1;
  return {
    accepted,
    error: state.error ? String(state.error) : undefined,
    opCost: state.metrics?.operationCost ?? 0,
    lockBytes: redeem.length,
    unlockBytes: unlocking.length,
    bytes: redeem.length + unlocking.length,
  };
}

const honestZ = t.z;
const honestP12z = p12At(honestZ);
if (honestP12z === 0n) throw new Error('unexpected P12(z)=0 on honest challenge');
const honestQz = peval(honestBigQ, honestZ);
const honestAccD = sz.mmul(honestQz, honestP12z);
if (mod(honestSeam[0]) !== honestAccD) {
  throw new Error(`closeStateC accD mismatch: seam=${honestSeam[0]} computed=${honestAccD}`);
}

const forgedAccD = sz.madd(honestAccD, 1n);
const forgedSeam = [...honestSeam];
forgedSeam[0] = forgedAccD;

const currentHonest = runClose();
const currentAccDTamper = runClose({ seam: forgedSeam });
const lateScalarQz = qzForAccD(forgedAccD, honestZ);

const gammaOnlyZ = zFromGammaOnly(t.gamma);
const gammaOnlyHonestQz = qzForAccD(honestAccD, gammaOnlyZ);
const gammaOnlyForgedQz = qzForAccD(forgedAccD, gammaOnlyZ);
const gammaOnlyHonestBigQz = peval(honestBigQ, gammaOnlyZ);

let scalarPrecommitHonestHits = 0;
let scalarPrecommitForgedHits = 0;
const scalarPrecommitSamples = [];
for (let i = 0; i < trials; i++) {
  const seed = hashToField('BN254-SZN-QZ-TRIAL/v0', be4(i));
  const zh = zFromScalarCommit(t.gamma, seed, i);
  const honestExpected = peval(honestBigQ, zh);
  const forgedExpected = qzForAccD(forgedAccD, zh);
  const honestHit = seed === honestExpected;
  const forgedHit = seed === forgedExpected;
  if (honestHit) scalarPrecommitHonestHits++;
  if (forgedHit) scalarPrecommitForgedHits++;
  if (i < 3) {
    scalarPrecommitSamples.push({
      trial: i,
      qzPrefix: short(seed),
      zPrefix: short(zh),
      honestExpectedPrefix: short(honestExpected),
      forgedExpectedPrefix: short(forgedExpected),
      honestFixedPoint: honestHit,
      forgedFixedPoint: forgedHit,
    });
  }
}

const currentBigQBlobBytes = honestBigQ.length * 32;
const scalarOpeningBytes = 32;
const scalarCommitmentBytes = 32;

const report = {
  pairingDir,
  generatedCash,
  env: {
    SZ_ALLAFF: process.env.SZ_ALLAFF ?? '',
    L17SEL: process.env.L17SEL ?? '',
  },
  realCloseAnchor: {
    steps: t.steps.length,
    chainPoints: t.chain.length,
    bigQCoeffs: honestBigQ.length,
    gammaPrefix: short(t.gamma),
    zPrefix: short(honestZ),
    p12zNonzero: honestP12z !== 0n,
    accDMatchesCommittedBigQ: honestAccD === mod(honestSeam[0]),
    currentHonest,
    currentAccDTamperWithMatchingSeamCommitment: currentAccDTamper,
    currentCloseRejectsAccDTamper: !currentAccDTamper.accepted,
  },
  protocolProbes: [
    {
      name: 'late-scalar-opening-after-z',
      model: 'Verifier derives z from the existing committed bigQ transcript but accepts a free scalar q(z) supplied after z.',
      honestAccepts: honestAccD === sz.mmul(honestQz, honestP12z),
      forgedAccepts: forgedAccD === sz.mmul(lateScalarQz, honestP12z),
      fullCommittedBigQWouldRejectSameForge: !currentAccDTamper.accepted,
      forgedQzPrefix: short(lateScalarQz),
      verdict: 'UNSOUND: after z is known, qz = accD / P12(z) repairs any scalar accD defect.',
    },
    {
      name: 'z-from-gamma-only-with-free-qz',
      model: 'Verifier sets z = H(gamma) and accepts a free scalar q(z), with no quotient commitment in the challenge.',
      zPrefix: short(gammaOnlyZ),
      honestFreeQzPrefix: short(gammaOnlyHonestQz),
      forgedFreeQzPrefix: short(gammaOnlyForgedQz),
      honestBigQAtGammaOnlyZPrefix: short(gammaOnlyHonestBigQz),
      honestFreeQzEqualsHonestBigQAtZ: gammaOnlyHonestQz === gammaOnlyHonestBigQz,
      forgedAccepts: forgedAccD === sz.mmul(gammaOnlyForgedQz, p12At(gammaOnlyZ)),
      verdict: 'UNSOUND: moving z to H(gamma) does not help if qz is still an unconstrained post-challenge witness.',
    },
    {
      name: 'z-from-gamma-only-no-quotient',
      model: 'Verifier sets z = H(gamma) and removes the quotient/opening check entirely, or replaces it with accD == 0.',
      noCheckHonestAccepts: true,
      noCheckForgedAccepts: true,
      zeroCheckHonestAccepts: honestAccD === 0n,
      zeroCheckForgedAccepts: forgedAccD === 0n,
      verdict: 'NO-CHECK IS UNSOUND; ZERO-CHECK IS INCOMPLETE for the honest current close.',
    },
    {
      name: 'precommit-scalar-qz-before-z',
      model: 'Prover commits only to a scalar qz, then z = H(gamma, commit(qz)); verifier checks accD == qz*P12(z).',
      trials,
      scalarPrecommitHonestHits,
      scalarPrecommitForgedHits,
      sampleTrials: scalarPrecommitSamples,
      expectedRandomHitProbabilityUpperBound: `${trials}/P`,
      verdict: 'INCOMPLETE/NOT-A-QUOTIENT-PROOF: honest proving also becomes a fixed-point search qz = Q(H(commit(qz))). No sampled fixed points; even a hit would bind only one scalar, not the quotient polynomial.',
    },
  ],
  byteContext: {
    currentBigQBlobBytes,
    currentBigQPushBytes: encodeDataPush(new Uint8Array(currentBigQBlobBytes)).length,
    scalarOpeningBytes,
    scalarCommitmentBytes,
    naiveScalarTranscriptSavingBeforeCode: currentBigQBlobBytes - scalarOpeningBytes,
    note: 'The large apparent scalar saving is exactly the unsound/incomplete surface above. A real logarithmic close must bind proof material before z and still prove divisibility/transition residuals, not only one scalar value.',
  },
  obligationsForAnySurvivingLogClose: [
    'Commit all quotient/proof material before z is derived.',
    'Derive z from the committed material, not from gamma alone.',
    'Do not allow q(z), residual openings, or repaired accumulator values to be chosen after z.',
    'Bind the full transition residual relation, not only accD at one point.',
    'Preserve the ccff/residue tail and canonicality checks measured by the current fused close.',
  ],
};

console.log(json(report));
