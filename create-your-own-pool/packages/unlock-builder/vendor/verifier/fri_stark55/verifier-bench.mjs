// Comprehensive FRI-STARK verifier bench.
//
// This is the release-facing companion to the small red-team scripts.  It has
// two deliberately separate jobs:
//
//   1. execute the verifier/reference pair and exercise the soundness,
//      transcript, Merkle, FRI, split-input, token, parser, and BCH resource
//      boundaries; and
//   2. decide whether the result is eligible for production at all.
//
// A VM-accepted toy proof is not a production result.  The second job therefore
// fails closed unless production_manifest.json supplies a concrete application
// statement, >=128-bit *provable* security evidence, real mainnet CashToken
// provenance, multiple distinct runtime proofs, reproducible artifacts, and
// independent verifier/full-node evidence.  The checked-in Fibonacci fixture is
// intentionally expected to FAIL this bench.
import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

import {
  authenticationInstructionIsMalformed,
  decodeAuthenticationInstructions,
  encodeDataPush,
  encodeTransaction,
  hash256,
  bigIntToVmNumber,
  OpcodesBchSpec,
} from '../node_modules/@bitauth/libauth/build/index.js';
import { createVirtualMachineBch2026 } from '../node_modules/@bitauth/libauth/build/index.js';

import {
  LOGN,
  LOG_BLOWUP,
  NUM_QUERIES,
  MIN_RESEARCH_QUERIES,
  MAX_TOTAL_BYTES,
  CATEGORY,
  init,
  buildBundle,
  metrics,
  assertStandard,
  accepted,
  cloneBytes,
  p2sh32,
} from './common.mjs';
import { qStarkProve } from '../fri_stark/qstark.mjs';
import { buildQStarkWitnessCapture } from '../fri_stark/build_qstark_split.mjs';
import { qRecomputeChallenges, qStarkVerify } from '../fri_stark/qstark_verify.mjs';
import { QTranscript } from '../fri_stark/qhelpers.mjs';
import { QM31 } from '../fri_stark/qm31.mjs';
import { Asm } from '../fri_stark/asm.mjs';
import { collectLocalModuleClosure } from './source_closure.mjs';
import { buildLibraryArtifact, buildLibraryPin, buildWitnessLoader, itemDigest } from './dynamic_library.mjs';

const here = new URL('.', import.meta.url);
const repoRoot = fileURLToPath(new URL('../', here));
const manifestPath = fileURLToPath(new URL('./production_manifest.json', here));
const rootPath = (p) => resolve(repoRoot, p);
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const digest = (bytes) => hex(hash256(bytes));
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');
const concat = (...parts) => {
  const size = parts.reduce((n, part) => n + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const sameBytes = (a, b) => a instanceof Uint8Array && b instanceof Uint8Array &&
  a.length === b.length && a.every((value, i) => value === b[i]);
const pushedPayload = (instruction) => {
  if (!instruction || authenticationInstructionIsMalformed(instruction)) return undefined;
  if ('data' in instruction) return Uint8Array.from(instruction.data);
  if (instruction.opcode === OpcodesBchSpec.OP_0) return new Uint8Array();
  if (instruction.opcode === OpcodesBchSpec.OP_1NEGATE) return Uint8Array.of(0x81);
  if (instruction.opcode >= OpcodesBchSpec.OP_1 && instruction.opcode <= OpcodesBchSpec.OP_16) {
    return Uint8Array.of(instruction.opcode - OpcodesBchSpec.OP_1 + 1);
  }
  return undefined;
};
const vmNumberPayload = (value) => Uint8Array.from(bigIntToVmNumber(BigInt(value)));
const fixtureLanguage = (value) => /(?:^|[^a-z])(toy|demo(?:nstrator)?|mock|placeholder|synthetic|fixture|test deployment)(?:[^a-z]|$)/i.test(String(value));
const isHex32 = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
const isDigest = (value) => isHex32(value);
const MAX_TOKEN_AMOUNT = 9_223_372_036_854_775_807n;
const isTokenAmount = (value) => {
  if (!/^\d+$/.test(String(value ?? ''))) return false;
  try { return BigInt(String(value)) <= MAX_TOKEN_AMOUNT; } catch { return false; }
};
const isRepoRelativePath = (value) => {
  if (typeof value !== 'string' || value.trim() === '' || value.includes('\0') || value.startsWith('/')) return false;
  const resolved = resolve(repoRoot, value);
  return resolved === repoRoot || resolved.startsWith(`${repoRoot}/`);
};

const checks = [];
const check = (id, pass, details, evidence = undefined) => {
  checks.push({ id, pass: Boolean(pass), details, ...(evidence === undefined ? {} : { evidence }) });
};

const childResult = (script) => {
  const result = spawnSync(process.execPath, [fileURLToPath(new URL(script, here))], {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 180_000,
  });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim();
  const lines = output.split(/\r?\n/).filter(Boolean);
  return { ok: result.status === 0, status: result.status, output: lines.at(-1) ?? '' };
};

function cloneToken(token) {
  if (token === undefined) return undefined;
  return {
    ...token,
    category: cloneBytes(token.category),
    ...(token.nft ? { nft: { ...token.nft, commitment: cloneBytes(token.nft.commitment) } } : {}),
  };
}

function cloneBundle(bundle) {
  return {
    ...bundle,
    H: bundle.H && cloneBytes(bundle.H),
    lockings: bundle.lockings.map(cloneBytes),
    redeems: bundle.redeems?.map(cloneBytes),
    unlockings: bundle.unlockings.map(cloneBytes),
    sourceOutputs: bundle.sourceOutputs.map((output) => ({
      ...output,
      lockingBytecode: cloneBytes(output.lockingBytecode),
      ...(output.token ? { token: cloneToken(output.token) } : {}),
    })),
    transaction: {
      ...bundle.transaction,
      inputs: bundle.transaction.inputs.map((input) => ({
        ...input,
        outpointTransactionHash: cloneBytes(input.outpointTransactionHash),
        unlockingBytecode: cloneBytes(input.unlockingBytecode),
      })),
      outputs: bundle.transaction.outputs.map((output) => ({
        ...output,
        lockingBytecode: cloneBytes(output.lockingBytecode),
        ...(output.token ? { token: cloneToken(output.token) } : {}),
      })),
    },
    serializedTransaction: cloneBytes(bundle.serializedTransaction),
  };
}

function transactionWithCurrentUnlockings(bundle) {
  return {
    ...bundle.transaction,
    inputs: bundle.unlockings.map((unlockingBytecode, i) => ({
      ...bundle.transaction.inputs[i],
      unlockingBytecode,
    })),
  };
}

function runVm(bundle, standard) {
  try {
    if (!bundle || !Array.isArray(bundle.lockings) || bundle.lockings.length < 1 ||
      !Array.isArray(bundle.unlockings) || bundle.unlockings.length !== bundle.lockings.length ||
      !Array.isArray(bundle.sourceOutputs) || bundle.sourceOutputs.length !== bundle.lockings.length ||
      !bundle.transaction || !Array.isArray(bundle.transaction.inputs) ||
      bundle.transaction.inputs.length !== bundle.lockings.length ||
      !(bundle.serializedTransaction instanceof Uint8Array)) {
      return { states: [], allAccepted: false, consensusValid: false, error: 'candidate bundle has no non-empty, input-aligned transaction witness' };
    }
    // Use the same transaction object for every input.  In particular, this
    // prevents a test from accidentally evaluating stale serialized bytes.
    const vm = createVirtualMachineBch2026(standard);
    const transaction = transactionWithCurrentUnlockings(bundle);
    // `evaluate` checks only one authentication program.  A production bench
    // must also exercise the VM's stateless transaction verifier, which covers
    // CashToken category/capability/amount rules and transaction-wide standard
    // limits.  Without this call, a mutation could be rejected by neither the
    // covenant nor the script runner while still being invalid at consensus.
    const transactionVerdict = vm.verify({ transaction, sourceOutputs: bundle.sourceOutputs });
    if (transactionVerdict !== true) {
      return {
        states: [],
        allAccepted: false,
        consensusValid: false,
        error: String(transactionVerdict),
      };
    }
    const states = bundle.lockings.map((_, inputIndex) => vm.evaluate({
      inputIndex,
      sourceOutputs: bundle.sourceOutputs,
      transaction,
    }));
    return { states, allAccepted: states.every(accepted), consensusValid: true, error: undefined };
  } catch (error) {
    return { states: [], allAccepted: false, consensusValid: false, error: error instanceof Error ? error.message : String(error) };
  }
}

function runCase(label, bundle, expectedAccepted, options = {}) {
  const standard = options.standard ?? true;
  const result = runVm(bundle, standard);
  const pass = expectedAccepted ? result.allAccepted : !result.allAccepted;
  const failures = result.states.filter((state) => !accepted(state)).length;
  const inputCount = Array.isArray(bundle?.lockings) ? bundle.lockings.length : 0;
  check(`${label}.vm.${standard ? 'standard' : 'strict'}`, pass,
    result.error ?? `${failures}/${inputCount} inputs rejected`, {
      expectedAccepted,
      actualAccepted: result.allAccepted,
      inputCount,
    });
  return result;
}

function checkedMetrics(bundle, standardStates) {
  // Keep the existing score/metric implementation as the canonical report for
  // this fixture, but independently re-check the hard resource ceilings below.
  return metrics(bundle, standardStates);
}

function patchOne(nameToChange) {
  return (name, value) => {
    if (name !== nameToChange) return value;
    if (typeof value === 'bigint') return value + 1n;
    const out = cloneBytes(value);
    if (out.length === 0) return Uint8Array.of(1);
    out[0] ^= 1;
    return out;
  };
}

function mutateTransaction(bundle, mutate) {
  const out = cloneBundle(bundle);
  mutate(out);
  return out;
}

function canonicalPushOnly(script) {
  try {
    const instructions = decodeAuthenticationInstructions(script);
    return instructions.length > 0 && instructions.every((instruction) => {
      if (authenticationInstructionIsMalformed(instruction)) return false;
      return 'data' in instruction || instruction.opcode >= 0x00 && instruction.opcode <= 0x60;
    });
  } catch {
    return false;
  }
}

function outputLockingIsDummy(output) {
  const code = output?.lockingBytecode;
  return code instanceof Uint8Array && code.length === 25 && code[0] === 0x76 && code[1] === 0xa9 &&
    code[2] === 0x14 && code.slice(3, 23).every((b) => b === 0x55) && code[23] === 0x88 && code[24] === 0xac;
}

function sourceOutpointsAreSynthetic(bundle) {
  return bundle.transaction.inputs.every((input, i) =>
    input.outpointIndex === 0 && input.outpointTransactionHash.every((b) => b === i + 1));
}

function fixtureValuesAreSynthetic(bundle) {
  return bundle.sourceOutputs.every((output) => output.valueSatoshis === 1_000n) &&
    bundle.transaction.outputs.length === 1 && bundle.transaction.outputs[0].valueSatoshis === 900n;
}

function bundleShape(bundle) {
  const tx = transactionWithCurrentUnlockings(bundle);
  const serialized = encodeTransaction(tx);
  return {
    inputCount: bundle.lockings.length,
    sourceCount: bundle.sourceOutputs.length,
    txInputCount: tx.inputs.length,
    lockingSourceParity: bundle.lockings.every((locking, i) => sameBytes(locking, bundle.sourceOutputs[i]?.lockingBytecode)),
    serializedMatches: sameBytes(serialized, bundle.serializedTransaction),
    pushOnlyUnlockings: bundle.unlockings.every(canonicalPushOnly),
    inputUnlockingParity: bundle.transaction.inputs.every((input, i) => sameBytes(input.unlockingBytecode, bundle.unlockings[i])),
  };
}

function p2shWitnessShape(bundle) {
  try {
    if (!bundle || !Array.isArray(bundle.redeems) || !Array.isArray(bundle.lockings) ||
      !Array.isArray(bundle.unlockings) || bundle.redeems.length !== bundle.lockings.length ||
      bundle.unlockings.length !== bundle.lockings.length || bundle.lockings.length < 1) {
      return { applicable: false, valid: false, reason: 'redeems are absent or do not cover every input' };
    }
    const rows = bundle.redeems.map((redeem, i) => {
      const expectedLocking = p2sh32(redeem);
      const suffix = encodeDataPush(redeem);
      const unlocking = bundle.unlockings[i] ?? new Uint8Array();
      const suffixStart = unlocking.length - suffix.length;
      return {
        locking: sameBytes(bundle.lockings[i], expectedLocking),
        redeemSuffix: suffixStart >= 0 && sameBytes(unlocking.slice(suffixStart), suffix),
      };
    });
    return { applicable: true, valid: rows.every((row) => row.locking && row.redeemSuffix), rows };
  } catch (error) {
    return { applicable: false, valid: false, reason: `malformed P2SH witness shape: ${error instanceof Error ? error.message : String(error)}` };
  }
}

function dynamicLibraryShape(bundle) {
  try {
    const libraryIndex = bundle?.libraryIndex;
    const library = bundle?.library;
    if (libraryIndex === undefined && library === undefined) {
      return { applicable: false, valid: true, reason: 'candidate does not use a dynamic verifier library' };
    }
    const queryIndices = bundle?.queryInputIndices;
    if (!Number.isInteger(libraryIndex) || !library || !Array.isArray(library.items) ||
      !Array.isArray(queryIndices) || libraryIndex !== bundle.lockings.length - 1 ||
      libraryIndex >= bundle.lockings.length || bundle.sourceOutputs[libraryIndex]?.token !== undefined) {
      return { applicable: false, valid: false, reason: 'library metadata/index or tokenless library input is missing' };
    }
    const ids = library.items.map((item) => item?.id);
    const bodiesValid = library.items.every((item) => item?.bytes instanceof Uint8Array && item.bytes.length <= 520);
    const idsValid = ids.every((id) => Number.isInteger(id) && id >= 0 && id <= 255) && new Set(ids).size === ids.length;
    const chunkItems = library.items.filter((item) => item?.kind === 'verifier-chunk').sort((a, b) => (a.index ?? -1) - (b.index ?? -1));
    const chunkIdsValid = chunkItems.length === (library.chunks?.length ?? -1) &&
      chunkItems.every((item, i) => item.index === i && item.id === 100 + i);
    const digestValid = library.digest instanceof Uint8Array && sameBytes(library.digest, itemDigest(library.items));
    const chunkProgramExact = library.program instanceof Uint8Array && Array.isArray(library.chunks) &&
      sameBytes(concat(...library.chunks), library.program);
    const coreParity = sameBytes(bundle.lockings[libraryIndex], library.locking) &&
      sameBytes(bundle.redeems[libraryIndex], library.redeem) &&
      sameBytes(bundle.unlockings[libraryIndex], library.unlocking);
    const expectedQueries = queryIndices.length > 0 && queryIndices.every((index, i) => index === i + 1);
    const followerRedeems = queryIndices.map((index) => bundle.redeems[index]);
    const sameFollowerRedeem = followerRedeems.length > 0 && followerRedeems.every((redeem) => sameBytes(redeem, followerRedeems[0]));
    const expectedLibraryHash = hash256(bundle.lockings[libraryIndex]);
    const dynamicLoaderBound = followerRedeems.length > 0 && followerRedeems.every((redeem) => {
      const instructions = decodeAuthenticationInstructions(redeem);
      const hasInputBytecode = instructions.some((instruction, i) => instruction.opcode === OpcodesBchSpec.OP_INPUTBYTECODE &&
        i > 0 && sameBytes(pushedPayload(instructions[i - 1]), vmNumberPayload(libraryIndex)));
      const hasLibraryPin = instructions.some((instruction, i) => instruction.opcode === OpcodesBchSpec.OP_UTXOBYTECODE &&
        i > 0 && sameBytes(pushedPayload(instructions[i - 1]), vmNumberPayload(libraryIndex)) &&
        instructions[i + 1]?.opcode === OpcodesBchSpec.OP_HASH256 &&
        sameBytes(pushedPayload(instructions[i + 2]), expectedLibraryHash) &&
        instructions[i + 3]?.opcode === OpcodesBchSpec.OP_EQUALVERIFY);
      const invokedIds = [];
      for (let i = 0; i < instructions.length; i++) {
        if (instructions[i].opcode !== OpcodesBchSpec.OP_INVOKE) continue;
        const idBytes = i > 0 ? pushedPayload(instructions[i - 1]) : undefined;
        if (idBytes === undefined || idBytes.length > 2) return false;
        let id = 0;
        for (let j = idBytes.length - 1; j >= 0; j--) id = (id * 256) + idBytes[j];
        invokedIds.push(id);
      }
      const expectedInvokes = Array.from({ length: library.chunks.length }, (_, i) => 100 + i);
      const invokesExact = invokedIds.length === expectedInvokes.length && invokedIds.every((id, i) => id === expectedInvokes[i]);
      return hasInputBytecode && hasLibraryPin && invokesExact;
    });
    return {
      applicable: true,
      valid: coreParity && bodiesValid && idsValid && chunkIdsValid && digestValid && chunkProgramExact && expectedQueries && sameFollowerRedeem && dynamicLoaderBound,
      coreParity,
      bodiesValid,
      idsValid,
      chunkIdsValid,
      digestValid,
      chunkProgramExact,
      expectedQueries,
      sameFollowerRedeem,
      dynamicLoaderBound,
      itemCount: library.items.length,
      libraryIndex,
    };
  } catch (error) {
    return { applicable: false, valid: false, reason: `malformed dynamic library metadata: ${error instanceof Error ? error.message : String(error)}` };
  }
}

// Regression for canonical BCH pushes whose encoding is a single opcode
// (OP_0, OP_1NEGATE, OP_1..OP_16).  A raw-byte loader must consume the opcode
// as one encoded item and restore its semantic stack value; otherwise it can
// read the next item and silently change the verifier witness.  This probe is
// independent of the Fibonacci fixture and exercises both the committed
// library spend and a caller that authenticates/loads its witness.
function specialPushLoaderRegression() {
  const items = [
    { id: 1, bytes: Uint8Array.of(1), kind: 'shared-witness', index: 0 },
    { id: 2, bytes: new Uint8Array(), kind: 'shared-witness', index: 1 },
    { id: 3, bytes: Uint8Array.of(0x81), kind: 'shared-witness', index: 2 },
    { id: 4, bytes: Uint8Array.of(16), kind: 'shared-witness', index: 3 },
    { id: 5, bytes: Uint8Array.of(34), kind: 'shared-witness', index: 4 },
  ];
  const libraryIndex = 1;
  const artifact = buildLibraryArtifact(items, { inputIndex: libraryIndex, totalInputs: 2, p2sh: p2sh32 });
  const redeemAsm = new Asm();
  redeemAsm.raw(buildWitnessLoader(items, libraryIndex));
  redeemAsm.raw(buildLibraryPin(libraryIndex, hash256(artifact.locking)));
  for (let i = items.length - 1; i >= 0; i--) redeemAsm.push(items[i].bytes).o('OP_EQUALVERIFY');
  redeemAsm.num(1);
  const callerRedeem = redeemAsm.bytecode();
  const callerLocking = p2sh32(callerRedeem);
  const callerUnlocking = encodeDataPush(callerRedeem);
  const transaction = {
    version: 2,
    inputs: [
      { outpointTransactionHash: Uint8Array.of(1, ...new Uint8Array(31)), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: callerUnlocking },
      { outpointTransactionHash: Uint8Array.of(2, ...new Uint8Array(31)), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: artifact.unlocking },
    ],
    outputs: [{ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 0n }],
    locktime: 0,
  };
  const sourceOutputs = [
    { lockingBytecode: callerLocking, valueSatoshis: 1_000n },
    { lockingBytecode: artifact.locking, valueSatoshis: 1_000n },
  ];
  const vm = createVirtualMachineBch2026(true);
  const states = [0, 1].map((inputIndex) => vm.evaluate({ inputIndex, sourceOutputs, transaction }));
  return states.every(accepted);
}

// The L2 deployment absorbs the merged trace root (legacy mode absorbs c0/c1
// separately) before squeezing alpha. Keep this transcript-prefix assertion
// beside the VM bench so a legacy structural probe cannot silently exercise a
// different challenge path than the deployed verifier.
function transcriptAlphaRegression(prove) {
  const transcript = new QTranscript();
  transcript.absorbF(prove.target);
  if (prove.L2 !== false) transcript.absorb(prove.traceTree.root);
  else { transcript.absorb(prove.c0tree.root); transcript.absorb(prove.c1tree.root); }
  const squeezed = transcript.challengeQM31();
  const recomputed = qRecomputeChallenges(prove).alpha;
  return QM31.eq(squeezed, recomputed);
}

function valueAccounting(bundle) {
  try {
    const inputValue = (bundle?.sourceOutputs ?? []).reduce((sum, output) => sum + BigInt(output?.valueSatoshis ?? 0n), 0n);
    const outputValue = (bundle?.transaction?.outputs ?? []).reduce((sum, output) => sum + BigInt(output?.valueSatoshis ?? 0n), 0n);
    return { inputValue, outputValue, nonInflationary: outputValue <= inputValue };
  } catch (error) {
    return { inputValue: 0n, outputValue: 0n, nonInflationary: false, error: error instanceof Error ? error.message : String(error) };
  }
}

function bundleFingerprint(bundle) {
  try {
    return digest(concat(...(bundle.lockings ?? []), ...(bundle.unlockings ?? []), bundle.serializedTransaction ?? new Uint8Array()));
  } catch {
    return undefined;
  }
}

function caseQuality(entries) {
  entries = Array.isArray(entries) ? entries : [];
  const labels = entries.map((entry) => entry?.label).filter((label) => typeof label === 'string');
  const fingerprints = entries.map((entry) => bundleFingerprint(entry?.bundle)).filter((fingerprint) => fingerprint !== undefined);
  const families = new Set(entries.map((entry) => entry?.family).filter((family) => typeof family === 'string'));
  const nonVacuous = entries.length > 0 && entries.every((entry) => {
    const bundle = entry?.bundle;
    return bundle && Array.isArray(bundle.lockings) && bundle.lockings.length > 0 &&
      Array.isArray(bundle.unlockings) && bundle.unlockings.length === bundle.lockings.length &&
      Array.isArray(bundle.sourceOutputs) && bundle.sourceOutputs.length === bundle.lockings.length &&
      bundle.transaction && Array.isArray(bundle.transaction.inputs) &&
      bundle.transaction.inputs.length === bundle.lockings.length &&
      bundle.serializedTransaction instanceof Uint8Array;
  });
  return {
    uniqueLabels: new Set(labels).size === labels.length,
    uniqueVectors: new Set(fingerprints).size === fingerprints.length,
    nonVacuous,
    familyCount: families.size,
    families,
  };
}

// Production invalid cases must reach the verifier whenever their family is a
// proof/soundness family.  A transaction that fails stateless validation before
// the locking program runs is not evidence that the AIR/PCS verifier rejected
// the case; accepting such a case would let an adapter pad its suite with
// malformed transactions.  Parser cases are the one intentional exception,
// because malformed push/transaction encodings are themselves the subject of
// that family.
const verifierReachabilityFamilies = new Set([
  'statement', 'transcript', 'ood', 'fri', 'merkle', 'coverage', 'binding',
]);

function caseReachesVerifier(entry, standardResult, strictResult) {
  if (!verifierReachabilityFamilies.has(entry?.family)) return true;
  return standardResult?.consensusValid === true && standardResult?.allAccepted === false &&
    strictResult?.consensusValid === true && strictResult?.allAccepted === false;
}

function fileSha256(relativePath) {
  try {
    return createHash('sha256').update(readFileSync(rootPath(relativePath))).digest('hex');
  } catch {
    return undefined;
  }
}

function validateManifest(manifest) {
  const errors = [];
  const requireString = (field) => {
    if (typeof manifest[field] !== 'string' || manifest[field].trim() === '') errors.push(`${field} missing`);
  };
  const requireDigest = (field) => {
    requireString(field);
    if (manifest[field] !== undefined && !isDigest(manifest[field])) errors.push(`${field} must be a 32-byte hex digest`);
  };
  requireString('statementId');
  requireString('statementDescription');
  requireDigest('statementSpecSha256');
  requireDigest('reproducibleBuildSha256');
  requireDigest('vectorSha256');
  requireDigest('securityCertificateSha256');
  requireDigest('dependencyLockSha256');
  requireString('proofSystem');
  requireString('soundnessModel');
  if (!Array.isArray(manifest.verifierSourcePaths) || manifest.verifierSourcePaths.length < 1) errors.push('verifierSourcePaths missing');
  else {
    const sourcePaths = new Set();
    for (const [i, sourcePath] of manifest.verifierSourcePaths.entries()) {
      if (!isRepoRelativePath(sourcePath)) errors.push(`verifierSourcePaths[${i}] must be a repository-relative path`);
      if (sourcePaths.has(sourcePath)) errors.push(`verifierSourcePaths[${i}] duplicates another source path`);
      sourcePaths.add(sourcePath);
    }
  }
  if (typeof manifest.adapterModule !== 'string' || manifest.adapterModule.trim() === '') errors.push('adapterModule missing');
  else if (!isRepoRelativePath(manifest.adapterModule)) errors.push('adapterModule must be a repository-relative path');
  if (typeof manifest.independentReferenceModule !== 'string' || manifest.independentReferenceModule.trim() === '') errors.push('independentReferenceModule missing');
  else if (!isRepoRelativePath(manifest.independentReferenceModule)) errors.push('independentReferenceModule must be a repository-relative path');
  if (manifest.independentReferenceModule === manifest.adapterModule) errors.push('independentReferenceModule must differ from adapterModule');
  if (!manifest.verifierSourceSha256 || typeof manifest.verifierSourceSha256 !== 'object' || Array.isArray(manifest.verifierSourceSha256)) {
    errors.push('verifierSourceSha256 must map every production source path to a digest');
  } else {
    for (const [sourcePath, sourceDigest] of Object.entries(manifest.verifierSourceSha256)) {
      if (!isRepoRelativePath(sourcePath) || !isDigest(sourceDigest)) errors.push(`verifierSourceSha256[${sourcePath}] must be a repository-relative path + digest`);
      if (Array.isArray(manifest.verifierSourcePaths) && !manifest.verifierSourcePaths.includes(sourcePath)) errors.push(`verifierSourceSha256[${sourcePath}] is not listed in verifierSourcePaths`);
    }
  }
  if (fixtureLanguage(manifest.statementId) || fixtureLanguage(manifest.statementDescription) || fixtureLanguage(manifest.proofSystem)) {
    errors.push('statement metadata contains toy/demo/mock/fixture language');
  }
  if (manifest.network !== 'mainnet') errors.push('network must be mainnet');
  if (manifest.proofSystem !== 'FRI-STARK') errors.push('proofSystem must be FRI-STARK');
  if (manifest.soundnessModel !== 'provable') errors.push('soundnessModel must be provable, not empirical/conjectured');
  if (!Number.isInteger(manifest.securityTargetBits) || manifest.securityTargetBits < 128) errors.push('securityTargetBits must be >= 128');
  if (!Number.isInteger(manifest.soundnessBoundBits) || manifest.soundnessBoundBits < (manifest.securityTargetBits ?? 129)) errors.push('soundnessBoundBits does not cover target');
  if (!Number.isInteger(manifest.challengeFieldBits) || manifest.challengeFieldBits < (manifest.securityTargetBits ?? 129)) errors.push('challengeFieldBits does not cover target');
  if (!Number.isInteger(manifest.queryCount) || manifest.queryCount < 1) errors.push('queryCount missing');
  if (manifest.maxTotalBytes !== MAX_TOTAL_BYTES) errors.push(`maxTotalBytes must equal the hard crown cap ${MAX_TOTAL_BYTES}`);
  if (manifest.proofBinding !== 'runtime') errors.push('proofBinding must be runtime');
  requireDigest('genesisCategory');
  requireDigest('genesisTxid');
  if (/^0+$/.test(String(manifest.genesisCategory ?? ''))) errors.push('genesisCategory must be non-zero');
  if (/^0+$/.test(String(manifest.genesisTxid ?? ''))) errors.push('genesisTxid must be non-zero');
  const deterministicFixtureCategory = hex(hash256(new TextEncoder().encode('verifier.cash/fri-stark55/category/v1')));
  if (String(manifest.genesisCategory ?? '').toLowerCase() === deterministicFixtureCategory) errors.push('genesisCategory is the checked-in deterministic fixture category');
  if (manifest.genesisInputIndex !== 0) errors.push('genesisInputIndex must be 0');
  const fundingTxidList = Array.isArray(manifest.fundingTxids) ? manifest.fundingTxids : [];
  const fundingTxids = new Set(fundingTxidList.map((txid) => String(txid).toLowerCase()));
  if (!Array.isArray(manifest.fundingTxids) || manifest.fundingTxids.length < 1) errors.push('fundingTxids must contain the real funding transaction IDs');
  if (fundingTxids.size !== fundingTxidList.length) errors.push('fundingTxids must be unique');
  if (typeof manifest.genesisTxid === 'string' && !fundingTxids.has(manifest.genesisTxid.toLowerCase())) errors.push('fundingTxids must include genesisTxid');
  for (const [i, txid] of fundingTxidList.entries()) if (!isHex32(txid) || /^0+$/.test(String(txid))) errors.push(`fundingTxids[${i}] must be a non-zero 32-byte txid`);
  const fundingUtxoList = Array.isArray(manifest.fundingUtxos) ? manifest.fundingUtxos : [];
  if (fundingUtxoList.length < 1) errors.push('fundingUtxos must contain real UTXOs');
  const fundingUtxoKeys = new Set();
  let applicationUtxoCount = 0;
  for (const [i, utxo] of fundingUtxoList.entries()) {
    if (!utxo || !isHex32(utxo.txid) || /^0+$/.test(String(utxo?.txid ?? '')) || !Number.isInteger(utxo.vout) || utxo.vout < 0) errors.push(`fundingUtxos[${i}] missing non-zero txid/vout`);
    if (!/^[1-9]\d*$/.test(String(utxo?.valueSatoshis ?? ''))) errors.push(`fundingUtxos[${i}] valueSatoshis must be a positive integer`);
    if (!isDigest(utxo?.lockingBytecodeSha256)) errors.push(`fundingUtxos[${i}] lockingBytecodeSha256 must be a 32-byte digest`);
    const key = `${String(utxo?.txid ?? '').toLowerCase()}:${utxo?.vout}`;
    if (fundingUtxoKeys.has(key)) errors.push(`fundingUtxos[${i}] duplicates another funded outpoint`);
    fundingUtxoKeys.add(key);
    if (utxo?.txid && !fundingTxids.has(String(utxo.txid).toLowerCase())) errors.push(`fundingUtxos[${i}] txid is not listed in fundingTxids`);
    const role = utxo?.role ?? 'application';
    if (role !== 'application' && role !== 'library') errors.push(`fundingUtxos[${i}] role must be application or library`);
    if (role === 'application') {
      applicationUtxoCount++;
      if (utxo?.category !== manifest.genesisCategory) errors.push(`fundingUtxos[${i}] category is not genesisCategory`);
      if (utxo?.capability !== 'mutable') errors.push(`fundingUtxos[${i}] capability must be mutable`);
      if (!isTokenAmount(utxo?.tokenAmount)) errors.push(`fundingUtxos[${i}] tokenAmount exceeds the BCH-2026 maximum or is not a decimal integer`);
      if (!isDigest(utxo?.nftCommitmentSha256)) errors.push(`fundingUtxos[${i}] nftCommitmentSha256 must be a 32-byte digest`);
    } else if (utxo?.category !== undefined || utxo?.capability !== undefined || utxo?.tokenAmount !== undefined || utxo?.nftCommitmentSha256 !== undefined) {
      errors.push(`fundingUtxos[${i}] library role must be tokenless (omit category/capability)`);
    }
  }
  if (applicationUtxoCount < 1) errors.push('fundingUtxos must contain at least one application-token UTXO');
  const evidence = (field, minimum) => {
    if (!Array.isArray(manifest[field]) || manifest[field].length < minimum) errors.push(`${field} needs ${minimum} entries`);
    const seen = new Set();
    const seenDigests = new Set();
    for (const [i, item] of (manifest[field] ?? []).entries()) {
      if (!item || typeof item.path !== 'string' || !isDigest(item.sha256)) errors.push(`${field}[${i}] needs path + sha256`);
      else {
        if (!isRepoRelativePath(item.path)) {
          errors.push(`${field}[${i}] path must stay inside the repository`);
          continue;
        }
        const identity = `${item.path}\0${item.sha256.toLowerCase()}`;
        if (seen.has(identity)) errors.push(`${field}[${i}] duplicates another evidence entry`);
        seen.add(identity);
        if (seenDigests.has(item.sha256.toLowerCase())) errors.push(`${field}[${i}] reuses another artifact digest`);
        seenDigests.add(item.sha256.toLowerCase());
        if (fileSha256(item.path) !== item.sha256.toLowerCase()) errors.push(`${field}[${i}] hash mismatch or missing file`);
      }
    }
  };
  evidence('distinctValidProofArtifacts', 2);
  evidence('independentVerifierArtifacts', 2);
  evidence('fullNodeEvidence', 2);
  evidence('auditReferences', 1);
  evidence('applicationTests', 1);
  for (const [pathField, digestField] of [['statementSpecPath', 'statementSpecSha256'], ['reproducibleBuildPath', 'reproducibleBuildSha256'], ['vectorPath', 'vectorSha256'], ['securityCertificatePath', 'securityCertificateSha256'], ['dependencyLockPath', 'dependencyLockSha256']]) {
    if (!isRepoRelativePath(manifest[pathField])) errors.push(`${pathField} must be a repository-relative path`);
    else if (fileSha256(manifest[pathField]) !== String(manifest[digestField]).toLowerCase()) errors.push(`${pathField} hash mismatch or missing`);
  }
  if (typeof manifest.dependencyLockPath !== 'string' ||
    !/(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock)$/.test(manifest.dependencyLockPath)) {
    errors.push('dependencyLockPath must name a recognized package-manager lockfile');
  }
  return errors;
}

await init();

try {
  const specialPushesValid = specialPushLoaderRegression();
  check('regression.canonical-special-push-loader', specialPushesValid,
    specialPushesValid
      ? 'committed witness loader preserves OP_0/OP_1NEGATE/OP_1..OP_16 semantic values'
      : 'canonical special-push witness loader did not preserve semantic stack values');
} catch (error) {
  check('regression.canonical-special-push-loader', false,
    `canonical special-push loader regression threw: ${error instanceof Error ? error.message : String(error)}`);
}

const report = {
  schemaVersion: 1,
  implementation: 'FRI-STARK55',
  generatedAt: new Date().toISOString(),
  checks,
  metrics: {},
};

// ---- production identity / release policy ---------------------------------
let manifest;
const productionConfigured = existsSync(manifestPath);
if (!productionConfigured) {
  check('production.manifest', false, 'production_manifest.json is absent; no real application contract is in scope');
  check('production.statement', false, 'no concrete application statement/specification');
  check('production.security', false, 'no independently evidenced provable security target');
  check('production.provenance', false, 'no mainnet genesis category or funded UTXO set');
  check('production.generality', false, 'no distinct valid runtime proof vectors');
  check('production.reproducibility', false, 'no reproducible production artifact manifest');
  check('production.independent-evidence', false, 'no independent verifier/full-node evidence');
} else {
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    const errors = validateManifest(manifest);
    check('production.manifest', errors.length === 0, errors.length ? errors.join('; ') : 'production manifest is complete and independently hashed');
  } catch (error) {
    check('production.manifest', false, `production_manifest.json is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const releaseGate = childResult('./release_gate.mjs');
check('production.release-gate', releaseGate.ok, releaseGate.ok ? 'release gate passed' : releaseGate.output || `release gate exited ${releaseGate.status}`);

// Source-level tripwires are intentionally redundant with release_gate.mjs.
// They make the bench report explain *why* the checked-in artifact cannot be
// promoted, even when it happens to accept every local VM test.
const sourceFiles = Array.isArray(manifest?.verifierSourcePaths) ? manifest.verifierSourcePaths : [
  'fri_stark/qstark.mjs',
  'fri_stark55/common.mjs',
  'fri_stark55/build.mjs',
];
const sourceRoots = sourceFiles.filter((sourcePath) => typeof sourcePath === 'string');
const adapterRoot = typeof manifest?.adapterModule === 'string' ? [manifest.adapterModule] : [];
const referenceRoot = typeof manifest?.independentReferenceModule === 'string' ? [manifest.independentReferenceModule] : [];
const sourceClosure = collectLocalModuleClosure(repoRoot, [...sourceRoots, ...adapterRoot, ...referenceRoot]);
check('source.local-import-closure', sourceClosure.missing.length === 0 && sourceClosure.outside.length === 0,
  sourceClosure.missing.length === 0 && sourceClosure.outside.length === 0
    ? `all local verifier imports resolve (${sourceClosure.files.length} files)`
    : `missing/outside local imports: ${[...sourceClosure.missing, ...sourceClosure.outside].join(', ')}`);
if (typeof manifest?.adapterModule === 'string' && typeof manifest?.independentReferenceModule === 'string' &&
  isRepoRelativePath(manifest.adapterModule) && isRepoRelativePath(manifest.independentReferenceModule)) {
  const adapterPath = resolve(rootPath(manifest.adapterModule));
  const referenceClosure = collectLocalModuleClosure(repoRoot, [manifest.independentReferenceModule]);
  check('source.reference-independent', !referenceClosure.files.includes(adapterPath),
    referenceClosure.files.includes(adapterPath)
      ? 'independent reference closure imports the production adapter'
      : 'independent reference closure does not depend on the production adapter');
}
if (typeof manifest?.adapterModule === 'string') {
  const declaredSources = new Set(sourceRoots);
  const omitted = sourceClosure.files.map((file) => sourceClosure.relative(file)).filter((file) => !declaredSources.has(file));
  const reachableNames = new Set(sourceClosure.files.map((file) => sourceClosure.relative(file)));
  const extra = sourceRoots.filter((file) => !reachableNames.has(file));
  check('source.declared-closure', omitted.length === 0 && extra.length === 0,
    omitted.length === 0 && extra.length === 0
      ? 'manifest declares exactly the reachable verifier source closure'
      : `manifest source closure differs (omitted: ${omitted.join(', ') || 'none'}; extra: ${extra.join(', ') || 'none'})`);
}
if (productionConfigured) {
  const sourceHashes = manifest?.verifierSourceSha256;
  const closureNames = new Set(sourceClosure.files.map((file) => sourceClosure.relative(file)));
  const missingHashes = [];
  const mismatchedHashes = [];
  for (const file of sourceClosure.files) {
    const relativeName = sourceClosure.relative(file);
    const expected = sourceHashes?.[relativeName];
    if (!isDigest(expected)) missingHashes.push(relativeName);
    else {
      try {
        const actual = createHash('sha256').update(readFileSync(file)).digest('hex');
        if (actual !== expected.toLowerCase()) mismatchedHashes.push(relativeName);
      } catch { mismatchedHashes.push(relativeName); }
    }
  }
  const extraHashes = sourceHashes && typeof sourceHashes === 'object'
    ? Object.keys(sourceHashes).filter((name) => !closureNames.has(name))
    : [];
  check('source.hash-closure', missingHashes.length === 0 && mismatchedHashes.length === 0 && extraHashes.length === 0,
    missingHashes.length === 0 && mismatchedHashes.length === 0 && extraHashes.length === 0
      ? `all reachable verifier sources match pinned SHA-256 digests (${closureNames.size} files)`
      : `source hash mismatch/missing/extra: ${[...missingHashes, ...mismatchedHashes, ...extraHashes].join(', ')}`);
}
const sourceText = sourceClosure.files.map((file) => {
  try { return readFileSync(file, 'utf8'); } catch { return ''; }
}).join('\n');
const sourceTripwires = [
  ['source.no-fibonacci', /fibTrace|Fibonacci|Fib\(/, 'Fibonacci AIR is a research fixture'],
  ['source.no-test-category', /verifier\.cash\/fri-stark55\/category\/v1/, 'deterministic test category'],
  ['source.no-synthetic-outpoints', /new Uint8Array\(32\)\.fill\(i \+ 1\)/, 'synthetic sequential outpoint hashes'],
  ['source.no-dummy-output', /new Uint8Array\(20\)\.fill\(0x55\)/, 'dummy P2PKH output'],
  ['source.no-fixture-values', /valueSatoshis:\s*1_000n|valueSatoshis:\s*900n/, 'fixture satoshi values'],
  ['source.no-tiny-query-parameter', /NUM_QUERIES\s*=\s*[1-9]\b|(?:three|five) FRI queries/i, 'tiny-query demonstrator parameter'],
  ['source.no-nondeterminism', /Math\.random\s*\(|Date\.now\s*\(|process\.env\b/, 'environment-dependent or non-reproducible verifier behavior'],
  ['source.no-untrusted-dynamic-code', /\beval\s*\(|new\s+Function\s*\(|https?:\/\//i, 'untrusted/network-loaded verifier behavior'],
  ['source.no-dynamic-import', /\b(?:import|require)\s*\(\s*(?!['"])/, 'non-literal dynamic module loading outside the pinned source closure'],
  ['source.no-experimental-shared-witness', /sharedWitness|shared-witness/i, 'experimental shared-witness path is not production-audited'],
  ['source.no-experimental-fold-loop', /loopFold|P3_LOOPFOLD/i, 'experimental fold-loop path is not production-audited'],
];
for (const [id, pattern, reason] of sourceTripwires) check(id, !pattern.test(sourceText), pattern.test(sourceText) ? reason : 'not present');

// ---- candidate construction ------------------------------------------------
// The checked-in adapter is intentionally the research fixture. A production
// manifest may point to an adapter module exposing loadVerifierBench(); it must
// return the same bundle shape plus independent reference results, soundness and
// mutation cases, extra valid vectors, a byte-identical rebuild, and provenance.
// This keeps the runner reusable without silently treating the fixture as production.
let candidate = { kind: 'research-fixture' };
let adapterReload;
if (typeof manifest?.adapterModule === 'string' && isRepoRelativePath(manifest.adapterModule)) {
  try {
    const adapterUrl = pathToFileURL(rootPath(manifest.adapterModule)).href;
    const adapter = await import(adapterUrl);
    if (typeof adapter.loadVerifierBench !== 'function') throw new Error('adapter must export loadVerifierBench()');
    const loaded = await adapter.loadVerifierBench();
    if (!loaded || typeof loaded !== 'object') throw new Error('loadVerifierBench() returned no candidate object');
    candidate = loaded;
    // Invoke the adapter a second time rather than trusting an adapter-provided
    // `reproducible: true` label or a self-reported rebuild object.  The second
    // call is the independent runtime reproducibility witness.
    // Force a fresh ESM module instance.  Calling the same cached module twice
    // would not detect top-level mutable state or a one-shot fixture loader.
    const reloadedAdapter = await import(`${adapterUrl}?independent-load=1`);
    if (typeof reloadedAdapter.loadVerifierBench !== 'function') throw new Error('second adapter module must export loadVerifierBench()');
    const reloaded = await reloadedAdapter.loadVerifierBench();
    if (!reloaded || typeof reloaded !== 'object') throw new Error('second loadVerifierBench() returned no candidate object');
    adapterReload = reloaded;
  } catch (error) {
    check('candidate.adapter', false, `adapter failed to load: ${error instanceof Error ? error.message : String(error)}`);
  }
}
let independentVerify;
if (productionConfigured && typeof manifest?.independentReferenceModule === 'string' && isRepoRelativePath(manifest.independentReferenceModule)) {
  try {
    const referenceModule = await import(pathToFileURL(rootPath(manifest.independentReferenceModule)).href);
    independentVerify = referenceModule.verify;
    check('candidate.reference-module', typeof independentVerify === 'function',
      typeof independentVerify === 'function' ? 'independent reference module exports verify(bundle)' : 'independent reference module must export verify(bundle)');
  } catch (error) {
    check('candidate.reference-module', false, `independent reference module failed to load: ${error instanceof Error ? error.message : String(error)}`);
  }
} else if (productionConfigured) {
  check('candidate.reference-module', false, 'manifest must name a repository-local independentReferenceModule');
}
if (productionConfigured || manifest?.adapterModule) {
  // A free-form label is not an identity boundary.  Require the adapter to
  // explicitly declare that it is the production adapter, bind it to the
  // exact application statement named by the manifest, and reject fixture
  // language in its self-description.  This keeps a demonstrator from being
  // promoted by changing only `kind` or a README/status string.
  const candidateIdentityText = [
    candidate.kind,
    candidate.deploymentStatus,
    candidate.statementId,
    candidate.statementSpecSha256,
    candidate.statementDescription,
  ].filter((value) => value !== undefined).join('\n');
  const candidateIdentityValid = productionConfigured &&
    candidate.kind === 'production-adapter' &&
    candidate.deploymentStatus === 'production' &&
    candidate.statementId === manifest?.statementId &&
    candidate.statementSpecSha256 === manifest?.statementSpecSha256 &&
    candidate.statementDescription === manifest?.statementDescription &&
    isDigest(candidate.statementSpecSha256) &&
    !fixtureLanguage(candidateIdentityText);
  check('candidate.production-identity', candidateIdentityValid,
    candidateIdentityValid
      ? 'adapter declares production status and is bound to the manifest statement'
      : 'adapter must declare production identity plus the exact manifest statementId/spec digest without fixture language');
  const candidateParametersValid = Number.isInteger(candidate.queryCount) && candidate.queryCount === manifest?.queryCount &&
    Number.isInteger(candidate.securityTargetBits) && candidate.securityTargetBits === manifest?.securityTargetBits &&
    candidate.soundnessModel === manifest?.soundnessModel && candidate.proofBinding === manifest?.proofBinding;
  check('candidate.parameter-identity', candidateParametersValid,
    candidateParametersValid
      ? 'adapter query/security/binding parameters match the manifest'
      : 'adapter must expose queryCount, securityTargetBits, soundnessModel, and proofBinding matching the manifest');
  check('candidate.adapter-contract', candidateIdentityValid && candidate.valid !== undefined,
    'production adapter must return an explicitly identified real valid bundle, not the checked-in fixture');
  const firstFingerprint = bundleFingerprint(candidate.valid);
  const secondFingerprint = bundleFingerprint(adapterReload?.valid);
  check('candidate.second-load-reproducibility', firstFingerprint !== undefined && firstFingerprint === secondFingerprint &&
    candidate.statementId === adapterReload?.statementId && candidate.statementSpecSha256 === adapterReload?.statementSpecSha256,
  firstFingerprint !== undefined && firstFingerprint === secondFingerprint
    ? 'two independent adapter loads produced byte-identical valid vectors and statement identity'
    : 'independent adapter loads differed or the second load was unavailable');
  check('candidate.reference-differential', candidate.reference?.validAccepted === true && candidate.reference?.invalidRejected === true,
    'adapter must report an independent reference result for valid and invalid proofs');
  check('candidate.soundness-cases', Array.isArray(candidate.soundnessCases) && candidate.soundnessCases.length >= 8,
    'adapter must provide at least eight false-statement/transcript/FRI soundness cases');
  check('candidate.mutation-cases', Array.isArray(candidate.mutationCases) && candidate.mutationCases.length >= 12,
    'adapter must provide at least twelve production mutation cases');
  check('candidate.soundness-case-shapes', Array.isArray(candidate.soundnessCases) &&
    candidate.soundnessCases.length >= 8 && candidate.soundnessCases.every((entry) =>
      entry?.bundle && typeof entry.label === 'string' && typeof entry.family === 'string'),
  'every soundness case must provide a labelled invalid bundle and a soundness family');
  check('candidate.mutation-case-shapes', Array.isArray(candidate.mutationCases) &&
    candidate.mutationCases.length >= 12 && candidate.mutationCases.every((entry) =>
      entry?.bundle && typeof entry.label === 'string' && typeof entry.family === 'string'),
  'every mutation case must provide a labelled invalid bundle and a mutation family');
  const soundnessQuality = caseQuality(candidate.soundnessCases ?? []);
  const mutationQuality = caseQuality(candidate.mutationCases ?? []);
  const requiredSoundnessFamilies = ['statement', 'transcript', 'ood', 'fri', 'merkle', 'coverage', 'binding', 'parser'];
  check('candidate.soundness-case-uniqueness', soundnessQuality.uniqueLabels && soundnessQuality.uniqueVectors,
    'soundness cases must have distinct labels and distinct invalid vectors');
  check('candidate.soundness-case-nonvacuous', soundnessQuality.nonVacuous,
    'soundness cases must contain non-empty, input-aligned transaction witnesses');
  check('candidate.soundness-case-families', requiredSoundnessFamilies.every((family) => soundnessQuality.families.has(family)),
    `soundness cases must cover families: ${requiredSoundnessFamilies.join(', ')}`);
  check('candidate.mutation-case-uniqueness', mutationQuality.uniqueLabels && mutationQuality.uniqueVectors,
    'mutation cases must have distinct labels and distinct invalid vectors');
  check('candidate.mutation-case-nonvacuous', mutationQuality.nonVacuous,
    'mutation cases must contain non-empty, input-aligned transaction witnesses');
  check('candidate.mutation-case-families', mutationQuality.familyCount >= 8,
    'mutation cases must cover at least eight independent fault families');
  check('candidate.reproducibility', candidate.reproducible === true,
    'adapter must attest that it regenerated the exact pinned vectors twice');
  check('candidate.rebuild-vector', candidate.rebuildValid && typeof candidate.rebuildValid === 'object',
    'adapter must return the second byte-identical rebuild as rebuildValid');
}

// Presence of a production manifest is itself a mode switch.  If its adapter
// is absent or fails to load, keep the candidate unavailable and fail closed;
// never silently run the checked-in Fibonacci fixture as a substitute.
const productionCandidate = productionConfigured;
const researchCandidate = !productionConfigured;
let honestProof;
const honestBundle = productionCandidate ? candidate.valid : buildBundle(
  honestProof = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES),
);
if (researchCandidate) {
  check('security.research-query-floor', NUM_QUERIES >= MIN_RESEARCH_QUERIES,
    `research regression profile retains at least ${MIN_RESEARCH_QUERIES} FRI queries (configured ${NUM_QUERIES})`);
}
if (productionCandidate) {
  check('reference.valid', candidate.reference?.validAccepted === true,
    candidate.reference?.validAccepted === true ? 'independent reference accepted the valid vector' : 'independent reference did not accept the valid vector');
  check('candidate.reference-runtime', typeof independentVerify === 'function',
    'production manifest reference module must expose an executable verify(bundle) differential');
  if (typeof independentVerify === 'function') {
    try {
      const referenceResult = await independentVerify(honestBundle);
      const referenceAccepted = referenceResult === true || referenceResult?.ok === true;
      check('reference.runtime-valid', referenceAccepted, referenceAccepted ? 'independent reference accepted the valid bundle' : 'independent reference rejected the valid bundle');
    } catch (error) {
      check('reference.runtime-valid', false, `independent reference threw: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
} else {
  const honestJs = qStarkVerify(honestProof, buildQStarkWitnessCapture(honestProof).openings);
  check('reference.valid', honestJs.ok === true, honestJs.ok ? 'JS reference accepted honest proof' : honestJs.why);
  let alphaSynchronized = false;
  try { alphaSynchronized = transcriptAlphaRegression(honestProof); }
  catch { alphaSynchronized = false; }
  check('regression.transcript-alpha-sync', alphaSynchronized,
    alphaSynchronized ? 'L2 merged-trace transcript squeezes the same alpha as the verifier' : 'transcript alpha prefix diverged from the verifier challenge path');
}
const validStandard = runCase('correctness.valid', honestBundle, true, { standard: true });
runCase('correctness.valid', honestBundle, true, { standard: false });

if (validStandard.states.length > 0) {
  const measured = checkedMetrics(honestBundle, validStandard.states);
  report.metrics = measured;
  try {
    assertStandard(measured);
    check('resources.standard-caps', true, 'candidate metrics fit the configured BCH script/tx/op-cost caps');
  } catch (error) {
    check('resources.standard-caps', false, error instanceof Error ? error.message : String(error));
  }
  check('resources.real-vm', runVm(honestBundle, false).allAccepted, 'strict BCH-2026 VM acceptance');
}

let shape;
try {
  shape = bundleShape(honestBundle);
} catch (error) {
  shape = { inputCount: 0, sourceCount: 0, txInputCount: 0, lockingSourceParity: false, serializedMatches: false, pushOnlyUnlockings: false };
  check('candidate.bundle-shape', false, `candidate bundle is malformed: ${error instanceof Error ? error.message : String(error)}`);
}
check('transaction.shape', shape.inputCount === shape.sourceCount && shape.inputCount === shape.txInputCount, JSON.stringify(shape));
check('transaction.source-locking-parity', shape.lockingSourceParity, 'every spent output locking bytecode matches the evaluated locking program');
check('transaction.input-unlocking-parity', shape.inputUnlockingParity, 'transaction input unlockings match the witness bytes being benchmarked');
check('transaction.serialization', shape.serializedMatches, 'serialized transaction exactly matches the evaluated transaction');
check('proof.parser-canonical-pushes', shape.pushOnlyUnlockings, 'all unlockings decode as well-formed push-only witnesses');
const p2shShape = p2shWitnessShape(honestBundle);
check('transaction.p2sh-redeem-binding', p2shShape.applicable && p2shShape.valid,
  p2shShape.applicable ? 'each P2SH32 locking hash and unlocking redeem suffix agree' : p2shShape.reason);
const libraryShape = dynamicLibraryShape(honestBundle);
check('transaction.dynamic-library-binding', libraryShape.valid,
  libraryShape.applicable ? JSON.stringify(libraryShape) : libraryShape.reason);
const valueTotals = valueAccounting(honestBundle);
check('transaction.value-non-inflation', valueTotals.nonInflationary,
  `input satoshis=${valueTotals.inputValue} output satoshis=${valueTotals.outputValue}`);
if (shape.inputCount > 0 && honestBundle.unlockings?.[0]?.length > 0) {
  try {
    const staleSerialization = cloneBundle(honestBundle);
    staleSerialization.unlockings[0][staleSerialization.unlockings[0].length - 1] ^= 1;
    check('transaction.serialization-mutation-detector', !bundleShape(staleSerialization).serializedMatches,
      'a witness mutation cannot hide behind stale serialized transaction bytes');
  } catch (error) {
    check('transaction.serialization-mutation-detector', false, `serialization mutation probe failed: ${error instanceof Error ? error.message : String(error)}`);
  }
} else {
  check('transaction.serialization-mutation-detector', false, 'candidate has no witness to mutate');
}

// Deterministic rebuild: a real deployment must be able to regenerate the
// exact vectors and transaction bytes from pinned source/parameters.
let sameLockings = false;
let sameUnlockings = false;
if (productionCandidate) {
  const rebuilt = candidate.rebuildValid;
  if (rebuilt && typeof rebuilt === 'object') {
    sameLockings = honestBundle?.lockings?.length === rebuilt.lockings?.length && honestBundle.lockings.every((v, i) => sameBytes(v, rebuilt.lockings[i]));
    sameUnlockings = honestBundle?.unlockings?.length === rebuilt.unlockings?.length && honestBundle.unlockings.every((v, i) => sameBytes(v, rebuilt.unlockings[i]));
    check('reproducibility.same-lockings', sameLockings, sameLockings ? digest(concat(...honestBundle.lockings)) : 'locking bytes changed on adapter rebuild');
    check('reproducibility.same-witness', sameUnlockings, sameUnlockings ? digest(concat(...honestBundle.unlockings)) : 'witness bytes changed on adapter rebuild');
    check('reproducibility.same-transaction', sameBytes(honestBundle.serializedTransaction, rebuilt.serializedTransaction), 'serialized transaction changed on adapter rebuild');
    check('reproducibility.rebuild-matches-second-load', bundleFingerprint(rebuilt) !== undefined &&
      bundleFingerprint(rebuilt) === bundleFingerprint(adapterReload?.valid),
    'adapter rebuildValid must match the independently reloaded valid vector');
  } else {
    check('reproducibility.same-lockings', false, 'adapter did not return rebuildValid.lockings');
    check('reproducibility.same-witness', false, 'adapter did not return rebuildValid.unlockings');
    check('reproducibility.same-transaction', false, 'adapter did not return rebuildValid.serializedTransaction');
  }
} else {
  const rebuilt = buildBundle(qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES));
  sameLockings = honestBundle.lockings.length === rebuilt.lockings.length && honestBundle.lockings.every((v, i) => sameBytes(v, rebuilt.lockings[i]));
  sameUnlockings = honestBundle.unlockings.length === rebuilt.unlockings.length && honestBundle.unlockings.every((v, i) => sameBytes(v, rebuilt.unlockings[i]));
  check('reproducibility.same-lockings', sameLockings, sameLockings ? digest(concat(...honestBundle.lockings)) : 'locking bytes changed on rebuild');
  check('reproducibility.same-witness', sameUnlockings, sameUnlockings ? digest(concat(...honestBundle.unlockings)) : 'witness bytes changed on rebuild');
  check('reproducibility.same-transaction', sameBytes(honestBundle.serializedTransaction, rebuilt.serializedTransaction), 'serialized transaction is deterministic');
}

// A fixed verifier must accept genuinely distinct valid proofs, not merely
// replay one baked witness. The current Fibonacci relation has one deterministic
// witness and therefore fails this gate (as it should).
const extraValidRuns = Array.isArray(candidate.extraValid) ? candidate.extraValid : [];
let mutationCaseCount = 0;
if (productionCandidate) {
  const validDigests = new Set();
  let extraPassed = 0;
  let extraSameLocking = true;
  for (const extra of extraValidRuns) {
    // Extra valid vectors are part of the production claim, so they must pass
    // both VM modes.  Checking only standard mode would allow a vector that
    // relies on a consensus/standardness discrepancy to satisfy generality.
    const standardResult = runVm(extra, true);
    const strictResult = runVm(extra, false);
    if (standardResult.allAccepted && strictResult.allAccepted) {
      extraPassed++;
      validDigests.add(digest(concat(...extra.unlockings)));
      extraSameLocking &&= extra.lockings?.length === honestBundle.lockings?.length && honestBundle.lockings.every((v, i) => sameBytes(v, extra.lockings[i]));
    }
  }
  check('proof-generality.same-locking', extraSameLocking && extraPassed === extraValidRuns.length,
    extraSameLocking ? 'all extra valid vectors use the pinned locking set' : 'an extra valid vector changes the locking set or is rejected');
  check('proof-generality.distinct-valid-proofs', extraValidRuns.length >= 2 && extraPassed === extraValidRuns.length && validDigests.size >= 2,
    `${extraPassed}/${extraValidRuns.length} extra valid vectors accepted; distinct witness vectors=${validDigests.size}`);
} else {
  const secondProof = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES);
  const secondBundle = buildBundle(secondProof);
  const distinctLockings = sameLockings;
  const distinctWitness = !sameUnlockings;
  let extraPassed = 0;
  for (const extra of extraValidRuns) if (runVm(extra, true).allAccepted) extraPassed++;
  check('proof-generality.same-locking', distinctLockings, distinctLockings ? 'all regenerated proofs use one locking set' : 'locking set changes with proof');
  check('proof-generality.distinct-valid-proofs', distinctWitness || extraPassed >= 2, `distinct valid proofs accepted under one locking: ${extraPassed + (distinctWitness ? 1 : 0)}`);
}

// ---- false statements and mutation matrix ----------------------------------
let mutationNames = [];
let txMutations = [];
if (researchCandidate) {
  function falseTrace(n) {
    const a = new Array(n); const b = new Array(n);
    a[0] = 1n; b[0] = 1n; a[1] = 1n; b[1] = 3n;
    for (let i = 2; i < n; i++) { a[i] = b[i - 1]; b[i] = (a[i - 1] + b[i - 1]) % 2147483647n; }
    return { a, b };
  }
  const falseProof = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES, { trace: falseTrace(1 << LOGN) });
  const falseBundle = buildBundle(falseProof);
  const falseJs = qStarkVerify(falseProof, buildQStarkWitnessCapture(falseProof).openings);
  check('soundness.false-air-reference', falseJs.ok === false, falseJs.ok ? 'false transition accepted by JS reference' : `JS rejected: ${falseJs.why}`);
  runCase('soundness.false-air', falseBundle, false, { standard: true });
  runCase('soundness.false-air', falseBundle, false, { standard: false });

  const witness = buildQStarkWitnessCapture(honestProof);
  mutationNames = [
    'target', 'alpha__a0', 'zetaX__a0', 'gamma0__a0', 'beta0__a0',
    'finalConst__a0', 'invVz__a0', 'q0_faIdx0', 'q0_half0', 'q0_fa0__a0',
    'q0_fb0__a0', 'q0_fax0', 'q0_finv0', 'q0_tr_sib0', 'q0_tr_dir0',
    'q0_q_sib0', 'q0_q_dir0', 'q0_fp0_sib0', 'q0_fp0_dir0',
    'traceRoot', 'qroot', 'friRoot0',
  ].filter((name, i, names) => witness.names.includes(name) && names.indexOf(name) === i);
  for (const name of mutationNames) {
    const mutated = buildBundle(honestProof, patchOne(name));
    runCase(`mutation.witness.${name}`, mutated, false, { standard: true });
    runCase(`mutation.witness.${name}`, mutated, false, { standard: false });
  }

  txMutations = [
    ['p2sh-redeem', (bundle) => { bundle.unlockings[1][bundle.unlockings[1].length - 1] ^= 1; }],
    ['follower-swap', (bundle) => { [bundle.unlockings[1], bundle.unlockings[2]] = [bundle.unlockings[2], bundle.unlockings[1]]; }],
    ['duplicate-follower', (bundle) => { bundle.unlockings[2] = cloneBytes(bundle.unlockings[1]); }],
    ['leader-bypass', (bundle) => { const redeem = Uint8Array.from([0x51]); bundle.sourceOutputs[0].lockingBytecode = p2sh32(redeem); bundle.unlockings[0] = Uint8Array.from([redeem.length, ...redeem]); }],
    ['missing-follower-input', (bundle) => { bundle.unlockings.pop(); bundle.transaction.inputs.pop(); }],
    ['foreign-category-source', (bundle) => { bundle.sourceOutputs[3].token.category = hash256(CATEGORY); }],
    ['foreign-category-output', (bundle) => { bundle.transaction.outputs[0].token.category = hash256(CATEGORY); }],
    ['foreign-H-commitment', (bundle) => { bundle.transaction.outputs[0].token.nft.commitment = hash256(bundle.H); }],
    ['capability-escalation-input', (bundle) => { bundle.sourceOutputs[0].token.nft.capability = 'minting'; }],
    ['capability-escalation-output', (bundle) => { bundle.transaction.outputs[0].token.nft.capability = 'minting'; }],
    ['source-locking-substitution', (bundle) => { bundle.sourceOutputs[2].lockingBytecode = Uint8Array.from([0x51]); }],
    ['library-body-mutation', (bundle) => {
      const index = bundle.libraryIndex;
      // The first library push is the final verifier chunk (canonical PUSHDATA2 header), so the
      // fourth byte is inside the body while preserving the push framing.  The library hash-chain
      // spend must reject it; no follower may execute an uncommitted body.
      if (!Number.isInteger(index) || bundle.unlockings[index].length < 4) throw new Error('library witness too short');
      bundle.unlockings[index][3] ^= 1;
    }],
    ['library-redeem-mutation', (bundle) => {
      const index = bundle.libraryIndex;
      bundle.unlockings[index][bundle.unlockings[index].length - 1] ^= 1;
    }],
    ['library-source-locking-substitution', (bundle) => {
      bundle.sourceOutputs[bundle.libraryIndex].lockingBytecode = Uint8Array.from([0x51]);
    }],
    ['unlocking-truncation', (bundle) => {
      const index = bundle.unlockings.length - 1;
      bundle.unlockings[index] = bundle.unlockings[index].slice(0, -1);
    }],
  ];
  for (const [label, mutate] of txMutations) {
    const mutated = mutateTransaction(honestBundle, mutate);
    runCase(`mutation.transaction.${label}`, mutated, false, { standard: true });
    runCase(`mutation.transaction.${label}`, mutated, false, { standard: false });
  }

  // The red-team programs remain independent regression suites. Running them here
  // prevents a future “bench cleanup” from deleting a previously found exploit.
  for (const [label, script] of [['regression.redteam', './redteam.mjs'], ['regression.adaptive-zeta', './adaptive_zeta_redteam.mjs']]) {
    const result = childResult(script);
    check(label, result.ok, result.ok ? result.output || 'sub-suite passed' : result.output || `sub-suite exited ${result.status}`);
  }
} else {
  check('soundness.adapter-suite', Array.isArray(candidate.soundnessCases) && candidate.soundnessCases.length >= 8, 'production adapter soundness suite is present');
  check('mutation.adapter-suite', Array.isArray(candidate.mutationCases) && candidate.mutationCases.length >= 12, 'production adapter mutation suite is present');
}

// ---- deployment/provenance tripwires ---------------------------------------
const provenanceSourceOutputs = honestBundle?.sourceOutputs ?? [];
const provenanceTransactionOutputs = honestBundle?.transaction?.outputs ?? [];
if (researchCandidate) {
  check('provenance.no-test-category', !sameBytes(CATEGORY, hash256(new TextEncoder().encode('verifier.cash/fri-stark55/category/v1'))), 'category must come from a real genesis transaction, not a deterministic project label');
  check('provenance.no-synthetic-outpoints', !sourceOutpointsAreSynthetic(honestBundle), 'outpoints must be real funded UTXOs');
  check('provenance.no-fixture-values', !fixtureValuesAreSynthetic(honestBundle), 'values must come from the real application transaction set');
  check('provenance.no-dummy-output', !honestBundle.transaction.outputs.some(outputLockingIsDummy), 'recipient/output scripts must be real application outputs');
} else {
  const provenance = candidate.provenance ?? {};
  const transactionInputs = honestBundle?.transaction?.inputs ?? [];
  const transactionOutputs = honestBundle?.transaction?.outputs ?? [];
  const inputKeys = transactionInputs.map((input) => `${input.outpointTransactionHash instanceof Uint8Array ? hex(input.outpointTransactionHash) : 'missing'}:${input.outpointIndex}`);
  const realOutpoints = inputKeys.length > 0 && inputKeys.every((key, i) => {
    const input = transactionInputs[i];
    return input.outpointTransactionHash instanceof Uint8Array && input.outpointTransactionHash.length === 32 &&
      input.outpointTransactionHash.some((byte) => byte !== 0) && Number.isInteger(input.outpointIndex) && input.outpointIndex >= 0;
  }) && new Set(inputKeys).size === inputKeys.length;
  check('provenance.adapter', provenance.real === true && provenance.mainnet === true && provenance.fundingVerified === true,
    'adapter must attest real mainnet funding and independently verified provenance');
  check('provenance.no-fixture-language', !fixtureLanguage(JSON.stringify(provenance)), 'adapter provenance contains toy/demo/mock/fixture language');
  check('provenance.real-outpoints', realOutpoints, 'every production input must carry a distinct non-zero 32-byte funded outpoint');
  check('provenance.no-dummy-output', !transactionOutputs.some(outputLockingIsDummy), 'recipient/output scripts must be real application outputs');

  // Self-attested provenance is not enough: bind every runtime outpoint and
  // application-token category to the exact funding records named by the
  // manifest.  This prevents an adapter from presenting a real-looking
  // manifest while evaluating a different/random category or an unlisted UTXO.
  const fundingUtxos = Array.isArray(manifest?.fundingUtxos) ? manifest.fundingUtxos : [];
  const fundingByOutpoint = new Map(fundingUtxos.map((utxo) => [
    `${String(utxo?.txid ?? '').toLowerCase()}:${utxo?.vout}`,
    utxo,
  ]));
  const manifestCategory = String(manifest?.genesisCategory ?? '').toLowerCase();
  const runtimeFundingBindings = transactionInputs.map((input, i) => {
    const key = `${input?.outpointTransactionHash instanceof Uint8Array ? hex(input.outpointTransactionHash).toLowerCase() : 'missing'}:${input?.outpointIndex}`;
    const funding = fundingByOutpoint.get(key);
    const isLibrary = Number.isInteger(honestBundle?.libraryIndex) && i === honestBundle.libraryIndex;
    const role = funding?.role ?? 'application';
    const roleMatches = funding !== undefined && ((isLibrary && role === 'library') || (!isLibrary && role === 'application'));
    const sourceOutput = honestBundle?.sourceOutputs?.[i];
    const token = honestBundle?.sourceOutputs?.[i]?.token;
    const categoryMatches = isLibrary
      ? token === undefined
      : token?.category instanceof Uint8Array && hex(token.category).toLowerCase() === manifestCategory;
    let valueMatches = false;
    try { valueMatches = funding !== undefined && BigInt(sourceOutput?.valueSatoshis ?? -1n) === BigInt(String(funding.valueSatoshis)); }
    catch { valueMatches = false; }
    const lockingMatches = funding !== undefined && sourceOutput?.lockingBytecode instanceof Uint8Array &&
      sha256Hex(sourceOutput.lockingBytecode).toLowerCase() === String(funding.lockingBytecodeSha256 ?? '').toLowerCase();
    let applicationTokenMatches = isLibrary;
    if (!isLibrary) {
      let amountMatches = false;
      try { amountMatches = token?.amount !== undefined && BigInt(token.amount) === BigInt(String(funding?.tokenAmount)); }
      catch { amountMatches = false; }
      const commitmentMatches = token?.nft?.commitment instanceof Uint8Array &&
        sha256Hex(token.nft.commitment).toLowerCase() === String(funding?.nftCommitmentSha256 ?? '').toLowerCase();
      applicationTokenMatches = amountMatches && commitmentMatches;
    }
    return funding !== undefined && roleMatches && categoryMatches && valueMatches && lockingMatches && applicationTokenMatches;
  });
  check('provenance.runtime-utxos-bound', runtimeFundingBindings.length > 0 && runtimeFundingBindings.every(Boolean),
    runtimeFundingBindings.every(Boolean)
      ? 'every runtime input matches a manifest-listed UTXO, role, value, locking hash, and token commitment'
      : 'runtime transaction uses an unlisted/mismatched funded UTXO, wrong role, tokenized library, or altered locking/value/commitment');
  const runtimeApplicationOutputs = (honestBundle?.sourceOutputs ?? []).filter((_, i) => i !== honestBundle?.libraryIndex);
  const runtimeCategories = runtimeApplicationOutputs
    .map((output) => output?.token?.category instanceof Uint8Array ? hex(output.token.category).toLowerCase() : undefined)
    .filter((value) => value !== undefined);
  check('provenance.runtime-genesis-category', runtimeCategories.length > 0 && runtimeCategories.every((value) => value === manifestCategory) &&
    provenanceTransactionOutputs.every((output) => output?.token === undefined ||
      (output.token.category instanceof Uint8Array && hex(output.token.category).toLowerCase() === manifestCategory)),
  'runtime application tokens and token outputs use the manifest genesis category');
}
// A committed verifier-library input is intentionally tokenless.  Token continuity/capability
// checks apply to the application-token inputs, while the dynamic-library binding above checks
// that the tokenless code input is itself committed and consensus-valid.
const tokenSourceOutputs = provenanceSourceOutputs.filter((_, i) => i !== honestBundle?.libraryIndex);
check('provenance.token-category-continuity', tokenSourceOutputs.length > 0 && provenanceTransactionOutputs.length > 0 && tokenSourceOutputs.every((output) => output.token?.category && sameBytes(output.token.category, provenanceTransactionOutputs[0]?.token?.category)), 'token category must be continuous across every application-token input and output');
check('provenance.nft-capability', tokenSourceOutputs.length > 0 && provenanceTransactionOutputs[0]?.token?.nft?.capability === 'none' && tokenSourceOutputs.every((output) => output.token?.nft?.capability === 'mutable'), 'NFT capability transition must be explicit and non-escalating for application-token inputs');
let inputTokenAmount = 0n;
let outputTokenAmount = 0n;
let tokenAccountingValid = true;
try {
  inputTokenAmount = provenanceSourceOutputs.reduce((total, output) => total + BigInt(output.token?.amount ?? 0n), 0n);
  outputTokenAmount = provenanceTransactionOutputs.reduce((total, output) => total + BigInt(output.token?.amount ?? 0n), 0n);
} catch {
  tokenAccountingValid = false;
}
check('provenance.token-amount-conservation', tokenAccountingValid && outputTokenAmount <= inputTokenAmount, `token amounts input=${inputTokenAmount} output=${outputTokenAmount}`);

// If an adapter supplied explicit invalid/soundness cases, run them too. This
// is the extension point for a production application relation (the fixture
// cases above intentionally remain Fibonacci-specific research diagnostics).
if (productionCandidate) {
  const checkIndependentReference = async (label, bundle) => {
    if (typeof independentVerify !== 'function' || !bundle) return;
    try {
      const result = await independentVerify(bundle);
      const acceptedByReference = result === true || result?.ok === true;
      check(`reference.invalid.${label}`, !acceptedByReference,
        acceptedByReference ? 'independent reference accepted an invalid case' : 'independent reference rejected the invalid case');
    } catch (error) {
      check(`reference.invalid.${label}`, false, `independent reference threw: ${error instanceof Error ? error.message : String(error)}`);
    }
  };
  const soundnessReachability = new Map();
  const mutationReachability = new Map();
  const recordReachability = (map, entry, standardResult, strictResult) => {
    const family = typeof entry?.family === 'string' ? entry.family : '<missing-family>';
    const rows = map.get(family) ?? [];
    rows.push({ standardResult, strictResult });
    map.set(family, rows);
  };
  for (const entry of (Array.isArray(candidate.soundnessCases) ? candidate.soundnessCases : [])) {
    if (!entry?.bundle) continue;
    const standardResult = runCase(`adapter.soundness.${entry.label}`, entry.bundle, false, { standard: true });
    const strictResult = runCase(`adapter.soundness.${entry.label}`, entry.bundle, false, { standard: false });
    recordReachability(soundnessReachability, entry, standardResult, strictResult);
    if (verifierReachabilityFamilies.has(entry.family)) {
      check(`adapter.soundness.${entry.label}.verifier-reachable`, caseReachesVerifier(entry, standardResult, strictResult),
        caseReachesVerifier(entry, standardResult, strictResult)
          ? 'invalid case reached the verifier under both VM modes'
          : 'invalid case was rejected by stateless transaction validation before the verifier ran');
    }
    await checkIndependentReference(`soundness.${entry.label}`, entry.bundle);
  }
  for (const entry of (Array.isArray(candidate.mutationCases) ? candidate.mutationCases : [])) {
    if (!entry?.bundle) continue;
    mutationCaseCount++;
    const standardResult = runCase(`adapter.mutation.${entry.label}`, entry.bundle, false, { standard: true });
    const strictResult = runCase(`adapter.mutation.${entry.label}`, entry.bundle, false, { standard: false });
    recordReachability(mutationReachability, entry, standardResult, strictResult);
    if (verifierReachabilityFamilies.has(entry.family)) {
      check(`adapter.mutation.${entry.label}.verifier-reachable`, caseReachesVerifier(entry, standardResult, strictResult),
        caseReachesVerifier(entry, standardResult, strictResult)
          ? 'invalid case reached the verifier under both VM modes'
          : 'invalid case was rejected by stateless transaction validation before the verifier ran');
    }
    await checkIndependentReference(`mutation.${entry.label}`, entry.bundle);
  }
  for (const [family, rows] of soundnessReachability.entries()) {
    if (!verifierReachabilityFamilies.has(family)) continue;
    check(`candidate.soundness-family.${family}.reachable`, rows.some((row) =>
      row.standardResult?.consensusValid === true && row.strictResult?.consensusValid === true),
    'soundness family includes at least one consensus-valid verifier-reachable invalid case');
  }
  for (const [family, rows] of mutationReachability.entries()) {
    if (!verifierReachabilityFamilies.has(family)) continue;
    check(`candidate.mutation-family.${family}.reachable`, rows.some((row) =>
      row.standardResult?.consensusValid === true && row.strictResult?.consensusValid === true),
    'mutation family includes at least one consensus-valid verifier-reachable invalid case');
  }
  for (const entry of (Array.isArray(candidate.invalid) ? candidate.invalid : [])) {
    if (!entry?.bundle) continue;
    runCase(`adapter.invalid.${entry.label ?? 'case'}`, entry.bundle, false, { standard: true });
    runCase(`adapter.invalid.${entry.label ?? 'case'}`, entry.bundle, false, { standard: false });
    await checkIndependentReference(`invalid.${entry.label ?? 'case'}`, entry.bundle);
  }
}

report.pass = checks.every((entry) => entry.pass);
report.summary = {
  passed: checks.filter((entry) => entry.pass).length,
  failed: checks.filter((entry) => !entry.pass).length,
  mutationCases: mutationCaseCount + mutationNames.length + txMutations.length,
  candidateKind: candidate.kind ?? (manifest ? 'production-adapter' : 'research-fixture'),
  productionManifest: Boolean(manifest),
};

console.log(JSON.stringify(report, null, 2));
if (!report.pass) process.exitCode = 1;
