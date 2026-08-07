#!/usr/bin/env node
// Measure the current Scenario-N SZ fused close+tail object and emit LeanBCH xcheck inputs.
//
// Usage:
//   SCENARIO_N_PAIRING_DIR=/path/to/build/chunked/pairing \
//     node tools/scenario-n-close-baseline.mjs
//
// The pairing dir must already have generated/fused_close_tail.cash, e.g. after:
//   (cd "$SCENARIO_N_PAIRING_DIR" && node _fuse_close_tail.mjs)
import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  bigIntToVmNumber,
  binToHex,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  encodeTransaction,
  encodeTransactionOutputs,
  hash256 as libauthHash256,
} from '@bitauth/libauth';
import { classifyBound, decompose } from '../harness/src/harness/cost.mjs';

const pairingDir = process.env.SCENARIO_N_PAIRING_DIR;
if (!pairingDir) {
  throw new Error('set SCENARIO_N_PAIRING_DIR to the build/chunked/pairing directory');
}

const moduleUrl = (name) => pathToFileURL(join(pairingDir, name)).href;
const generatedCash = join(pairingDir, 'generated', 'fused_close_tail.cash');
if (!existsSync(generatedCash)) {
  throw new Error(`missing ${generatedCash}; run "node _fuse_close_tail.mjs" in SCENARIO_N_PAIRING_DIR first`);
}

const [
  sz,
  math,
  residue,
  lib,
] = await Promise.all([
  import(moduleUrl('gen_miller_sz.mjs')),
  import(moduleUrl('_szmath.mjs')),
  import(moduleUrl('_residuemath.mjs')),
  import(moduleUrl('_millermath.mjs')),
]);

const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const mod = (x) => ((x % P) + P) % P;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));

const redeem = Uint8Array.from([...lib.compileFileBytecode(generatedCash)]);
const seamC = sz.closeStateC().map(BigInt);
const bigQ = sz.closePushedArgsC().slice(4).map(BigInt);
const bqBlob = Uint8Array.from(bigQ.flatMap((c) => [...math.be32(c)]));
const fccinv = sz.closeOutLimbs().map(BigInt);
const pairs = lib.pairsFor(lib.vec.publicInputs.map(BigInt));
const { boundary: fRaw } = lib.millerBatchOps(pairs);
const { w } = residue.residueWitness(fRaw);
const wLimbs = residue.fp12limbsOf(w).map((x) => mod(BigInt(x)));
const tailInts = [...fccinv, ...wLimbs];

const declPushes = [];
for (const v of seamC) declPushes.push(pushInt(v));
const bqPush = encodeDataPush(bqBlob);
declPushes.push(bqPush);
for (const v of tailInts) declPushes.push(pushInt(v));

const argBytes = Uint8Array.from(declPushes.reverse().flatMap((push) => [...push]));
const redeemPush = encodeDataPush(redeem);
const unlocking = Uint8Array.from([...argBytes, ...redeemPush]);
const locking = encodeLockingBytecodeP2sh32(libauthHash256(redeem));
const token = (commitment) => ({
  amount: 0n,
  category: lib.CATEGORY,
  nft: { capability: 'mutable', commitment },
});
const inCommit = lib.commitBin(seamC);
const program = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: token(inCommit) }],
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

const vm = createVirtualMachineBch2026(false);
const state = vm.evaluate(program);
const top = state.stack[state.stack.length - 1];
const accepted = state.error === undefined &&
  state.stack.length === 1 &&
  top !== undefined &&
  top.length === 1 &&
  top[0] === 1;
const metrics = state.metrics ?? {};
const instr = metrics.evaluatedInstructionCount ?? 0;
const run = {
  ok: accepted,
  error: state.error ? String(state.error) : undefined,
  opCost: metrics.operationCost ?? 0,
  arith: metrics.arithmeticCost ?? 0,
  base: instr * 100,
  push: metrics.stackPushedBytes ?? 0,
  hashIters: metrics.hashDigestIterations ?? 0,
  sigChecks: metrics.signatureCheckCount ?? 0,
  instr,
  lockBytes: redeem.length,
  unlockBytes: unlocking.length,
  bytes: redeem.length + unlocking.length,
};

const prefix = process.env.SCENARIO_N_XCHECK_PREFIX ?? '/tmp/scenarioN_close';
writeFileSync(`${prefix}_tx.hex`, binToHex(encodeTransaction(program.transaction)));
writeFileSync(`${prefix}_srcouts.hex`, binToHex(encodeTransactionOutputs(program.sourceOutputs)));

const byteAnatomy = {
  seamPushBytes: seamC.map(pushInt).reduce((sum, push) => sum + push.length, 0),
  bqBlobBytes: bqBlob.length,
  bqPushBytes: bqPush.length,
  tailPushBytes: tailInts.map(pushInt).reduce((sum, push) => sum + push.length, 0),
  redeemPushBytes: redeemPush.length,
  argBytes: argBytes.length,
  unlockBytes: unlocking.length,
};

console.log(JSON.stringify({
  pairingDir,
  generatedCash,
  env: {
    SZ_ALLAFF: process.env.SZ_ALLAFF ?? '',
    L17SEL: process.env.L17SEL ?? '',
  },
  accepted,
  bigQCoeffs: bigQ.length,
  run,
  decompose: decompose(run),
  classify: classifyBound(run.unlockBytes, run.opCost),
  byteAnatomy,
  candidateTranscriptBytes: [448, 512, 640, 768].map((transcriptBytes) => ({
    transcriptBytes,
    projectedUnlockBytes: unlocking.length - bqPush.length + encodeDataPush(new Uint8Array(transcriptBytes)).length,
  })),
  xcheck: {
    prefix,
    command: `(cd /home/toorik/Projects/LeanBCH && .lake/build/bin/xcheck_idxN ${prefix} 0)`,
  },
}, null, 2));
