#!/usr/bin/env node

/**
 * Beta-only local Libauth qualification runner.
 *
 * This intentionally has a different command, evidence schema, eligibility,
 * and publication record from the development lane. It never opens a network
 * connection or broadcasts a transaction. The emitted three transactions are
 * fully signed local BCH transactions and are freshly evaluated by Libauth.
 */
import { createHash } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  open,
  readdir,
  realpath,
} from 'node:fs/promises';
import path from 'node:path';

import * as snarkjs from 'snarkjs';

import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../packages/action/v2/packet.mjs';
import {
  decodeDirectV2BindingUnlock,
} from '../packages/action/v2/binding-unlock.mjs';
import {
  V2_BETA_LOCAL_ELIGIBILITY,
} from '../packages/profile/v2/beta-local-profile.mjs';
import {
  verifyBetaProofQualification,
} from './v2-beta-proof-qualification.mjs';
import {
  evaluateV2RawTransactionInputs,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  PF10_BETA_LIBAUTH_PUBLICATION_SCHEMA,
  PF10_BETA_LIBAUTH_QUALIFICATION_SCHEMA,
  PF10_LIBAUTH_PUBLICATION_FILE,
  parseBetaOptions,
  runPf10LibauthQualification,
  validatePf10BetaLibauthEvidence,
} from './v2-pf10-libauth-qualification.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const PROJECT_ROOT = path.resolve(import.meta.dirname, '../../..');
const expectedFiles = Object.freeze([
  'libauth.json',
  'qualification-summary.json',
  'stderr.txt',
  'stdout.txt',
]);

export class BetaLibauthQualificationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'BetaLibauthQualificationError';
  }
}

const fail = (message) => {
  throw new BetaLibauthQualificationError(message);
};
function assertSafeRuntime() {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major < 22 || (major === 22 && minor < 5)) {
    fail('beta Libauth qualification requires Node >=22.5.0');
  }
  const benignTestArgument = (entry) => entry === '--test'
    || entry === '--test-reporter=tap'
    || /^--test-concurrency=[1-9][0-9]*$/u.test(entry);
  if (process.execArgv.some((entry) => !benignTestArgument(entry))) {
    fail('beta Libauth qualification refuses Node preload, loader, inspector, or evaluator arguments');
  }
  const contaminated = Object.keys(process.env).filter((name) =>
    name === 'NODE_OPTIONS'
      || name === 'NODE_PATH'
      || name === 'NODE_V8_COVERAGE'
      || name.startsWith('LD_')
      || name.startsWith('DYLD_'));
  if (contaminated.length !== 0) {
    fail(`beta Libauth qualification refuses ambient loader controls: ${contaminated.sort().join(',')}`);
  }
}

const readPrivateRegularFile = async (
  filename,
  label,
  { allowEmpty = false } = {},
) => {
  const resolved = path.resolve(filename);
  const metadata = await lstat(resolved, { bigint: true });
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || (metadata.mode & 0o777n) !== 0o600n
    || (!allowEmpty && metadata.size === 0n)
    || metadata.size > BigInt(Number.MAX_SAFE_INTEGER)
    || await realpath(resolved) !== resolved
  ) fail(`${label} must be a mode-0600 single-link regular file`);
  const handle = await open(
    resolved,
    fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW,
  );
  try {
    const before = await handle.stat({ bigint: true });
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const pathAfter = await lstat(resolved, { bigint: true });
    for (const current of [before, after, pathAfter]) {
      if (
        current.dev !== metadata.dev
        || current.ino !== metadata.ino
        || current.size !== metadata.size
        || current.mtimeNs !== metadata.mtimeNs
        || current.ctimeNs !== metadata.ctimeNs
      ) fail(`${label} changed while it was read`);
    }
    if (bytes.length !== Number(metadata.size)
        || await realpath(resolved) !== resolved) {
      fail(`${label} changed length or canonical path while it was read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
};

const readCanonicalJson = async (filename, label) => {
  const bytes = await readPrivateRegularFile(filename, label);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (!bytes.equals(Buffer.from(canonicalizeJcs(value), 'utf8'))) {
    fail(`${label} is not exact canonical JCS`);
  }
  return Object.freeze({ bytes, value });
};

export const resolvePf10BetaProofArtifactPath = (record, label) => {
  if (
    record === null
    || Array.isArray(record)
    || typeof record !== 'object'
    || typeof record.path !== 'string'
    || typeof record.sha256 !== 'string'
  ) fail(`${label} evidence record is invalid`);
  if (record.pathScope === 'absolute') {
    if (!path.isAbsolute(record.path) || path.resolve(record.path) !== record.path) {
      fail(`${label} absolute path is invalid`);
    }
    return record.path;
  }
  if (record.pathScope !== undefined && record.pathScope !== 'repository') {
    fail(`${label} path scope is invalid`);
  }
  const resolved = path.resolve(PROJECT_ROOT, record.path);
  if (resolved === PROJECT_ROOT || !resolved.startsWith(`${PROJECT_ROOT}${path.sep}`)) {
    fail(`${label} repository path escapes the project`);
  }
  return resolved;
};

/**
 * Independently rehash, parse, and re-evaluate every published transaction.
 * It deliberately does not trust the row summaries written by the child test.
 */
export const verifyPf10BetaLibauthQualification = async ({
  output,
  betaProofEvidencePath,
}) => {
  assertSafeRuntime();
  if (typeof betaProofEvidencePath !== 'string'
      || betaProofEvidencePath.length === 0) {
    fail('beta Libauth verification requires beta proof evidence');
  }
  const directory = path.resolve(output);
  const directoryMetadata = await lstat(directory);
  if (
    !directoryMetadata.isDirectory()
    || directoryMetadata.isSymbolicLink()
    || (directoryMetadata.mode & 0o777) !== 0o700
    || await realpath(directory) !== directory
  ) fail('beta Libauth output must be a mode-0700 direct directory');
  const present = (await readdir(directory)).sort();
  const expected = [...expectedFiles, PF10_LIBAUTH_PUBLICATION_FILE].sort();
  if (
    present.length !== expected.length
    || present.some((name, index) => name !== expected[index])
  ) fail('beta Libauth output contains missing or unknown files');
  const completion = await readCanonicalJson(
    path.join(directory, PF10_LIBAUTH_PUBLICATION_FILE),
    'beta Libauth completion record',
  );
  if (
    completion.value?.schema !== PF10_BETA_LIBAUTH_PUBLICATION_SCHEMA
    || !Array.isArray(completion.value.files)
    || completion.value.files.length !== expectedFiles.length
  ) fail('beta Libauth completion record has an invalid schema or file list');
  const records = new Map(completion.value.files.map((entry) => [entry.path, entry]));
  if (records.size !== expectedFiles.length) fail('beta Libauth completion record duplicates files');
  for (const filename of expectedFiles) {
    const bytes = await readPrivateRegularFile(
      path.join(directory, filename),
      `beta Libauth ${filename}`,
      { allowEmpty: filename === 'stderr.txt' },
    );
    const record = records.get(filename);
    if (
      record?.bytes !== bytes.length
      || record?.sha256 !== sha256(bytes)
    ) fail(`beta Libauth completion record does not bind ${filename}`);
  }
  const evidence = await readCanonicalJson(
    path.join(directory, 'libauth.json'),
    'beta Libauth evidence',
  );
  const validated = validatePf10BetaLibauthEvidence(evidence.value);
  const summary = await readCanonicalJson(
    path.join(directory, 'qualification-summary.json'),
    'beta Libauth summary',
  );
  if (
    summary.value?.schema !== PF10_BETA_LIBAUTH_QUALIFICATION_SCHEMA
    || summary.value?.eligibility !== V2_BETA_LOCAL_ELIGIBILITY
    || summary.value?.evidence?.path !== 'libauth.json'
    || summary.value?.evidence?.bytes !== evidence.bytes.length
    || summary.value?.evidence?.sha256 !== sha256(evidence.bytes)
  ) fail('beta Libauth summary does not bind the verified beta evidence');
  const actions = validated.evidence.pf10FusedQGenesisActions.actions;
  const fresh = actions.map((action) => evaluateV2RawTransactionInputs({
    rawTransactionHex: action.rawTransactionHex,
    sourceTransactionHexes: action.inputSources.map((source) =>
      source.parentKind === 'funding'
        ? action.sourceParents.funding.rawTransactionHex
        : action.sourceParents.previousBundle.rawTransactionHex),
  }));
  if (
    fresh.some((result) => !result.allInputsAccepted)
    || fresh.some((result) => result.inputs.length !== 13)
  ) fail('fresh BCH_2026_STANDARD Libauth evaluation did not accept every beta input');
  const proofPath = path.resolve(betaProofEvidencePath);
  const proofEvidence = await readCanonicalJson(
    proofPath,
    'beta proof qualification evidence',
  );
  if (
    sha256(proofEvidence.bytes)
    !== validated.evidence.betaProofQualification.sha256
  ) fail('supplied beta proof evidence does not match the Libauth evidence pin');
  const proofResult = await verifyBetaProofQualification({
    evidencePath: proofPath,
  });
  if (proofResult.eligibility !== V2_BETA_LOCAL_ELIGIBILITY) {
    fail('supplied beta proof evidence has the wrong eligibility');
  }
  if (
    proofResult.profileId !== validated.evidence.identity.profileId
    || proofResult.instanceId !== validated.evidence.identity.instanceId
  ) {
    fail('supplied beta proof evidence has the wrong profile or instance');
  }
  const verificationKeyRecord =
    proofEvidence.value?.sourceArtifacts?.verificationKey;
  const verificationKeyBytes = await readPrivateRegularFile(
    resolvePf10BetaProofArtifactPath(
      verificationKeyRecord,
      'verification key',
    ),
    'ceremony-pinned verification key',
  );
  if (
    verificationKeyBytes.length !== verificationKeyRecord.bytes
    || sha256(verificationKeyBytes) !== verificationKeyRecord.sha256
  ) fail('ceremony-pinned verification key differs from beta proof evidence');
  let verificationKey;
  try {
    verificationKey = JSON.parse(verificationKeyBytes.toString('utf8'));
  } catch (error) {
    fail(`ceremony-pinned verification key is not JSON: ${error.message}`);
  }
  const transactionSpecific = [];
  for (const [index, action] of actions.entries()) {
    const packet = Buffer.from(action.packetHex, 'hex');
    if (
      packet.length !== 552
      || packet.toString('hex') !== action.packetHex
      || sha256(packet) !== action.packetSha256
    ) fail(`${action.kind} transaction-specific packet hash is invalid`);
    const decoded = decodeActionPacket(packet, {
      denominationSats: '10000000',
    });
    if (
      decoded.kind !== action.kind
      || decoded.instanceId !== validated.evidence.identity.instanceId
      || decoded.preState.profileId !== validated.evidence.identity.profileId
      || decoded.transactionContextHash !== action.contextHash
    ) fail(`${action.kind} transaction-specific packet identity is invalid`);
    const publicInputs = actionPacketPublicLimbs(packet, {
      denominationSats: '10000000',
    });
    if (
      publicInputs.length !== 2
      || publicInputs.some((entry, limb) => entry !== action.publicInputs[limb])
    ) fail(`${action.kind} public inputs differ from its exact packet`);
    const proofBindingSha256 = sha256(Buffer.from(canonicalizeJcs({
      packetSha256: action.packetSha256,
      proof: action.proof,
      publicInputs: action.publicInputs,
    }), 'utf8'));
    if (proofBindingSha256 !== action.proofBindingSha256) {
      fail(`${action.kind} transaction-specific proof binding is invalid`);
    }
    if (!(await snarkjs.groth16.verify(
      verificationKey,
      action.publicInputs,
      action.proof,
    ))) fail(`${action.kind} transaction-specific Groth16 proof returned false`);
    const parsed = parseV2RawTransaction(action.rawTransactionHex);
    decodeDirectV2BindingUnlock({
      expectedPacket: packet,
      sourceLockingBytecode: Buffer.from(
        action.sourceOutputs[10].lockingBytecodeHex,
        'hex',
      ),
      unlockingBytecode: parsed.inputs[10].unlockingBytecode,
    });
    if (fresh[index].transactionId !== action.transactionId) {
      fail(`${action.kind} fresh VM evaluation returned a different transaction`);
    }
    transactionSpecific.push(Object.freeze({
      kind: action.kind,
      packetSha256: action.packetSha256,
      proofBindingSha256,
      proofVerified: true,
      transactionId: action.transactionId,
    }));
  }
  return Object.freeze({
    schema: 'shieldkit-v2-direct-pf10-beta-local-libauth-verification-v1',
    eligibility: V2_BETA_LOCAL_ELIGIBILITY,
    evidenceSha256: sha256(evidence.bytes),
    proofEvidenceReverified: true,
    status: 'beta-local-libauth-reverified-unqualified',
    transactionSpecificProofs: Object.freeze(transactionSpecific),
    transactions: Object.freeze(actions.map((action, index) => Object.freeze({
      kind: action.kind,
      transactionId: fresh[index].transactionId,
      transactionBytes: action.transactionBytes,
      feeSats: action.feeSats,
      inputs: fresh[index].inputs.length,
    }))),
  });
};

export const main = async (argv = process.argv.slice(2)) => {
  assertSafeRuntime();
  if (argv[0] === '--verify') {
    if (argv.length !== 4 || argv[2] !== '--beta-proof-evidence') {
      fail('usage: --verify <output-directory> --beta-proof-evidence <qualification-evidence.json>');
    }
    return verifyPf10BetaLibauthQualification({
      output: argv[1],
      betaProofEvidencePath: argv[3],
    });
  }
  return runPf10LibauthQualification(parseBetaOptions(argv), {
    betaLocal: true,
  });
};

if (process.argv[1] !== undefined && path.resolve(process.argv[1]) === import.meta.filename) {
  main().then(
    (result) => process.stdout.write(
      `${canonicalizeJcs(result)}\n`,
      () => process.exit(0),
    ),
    (error) => process.stderr.write(
      `${error?.stack ?? error}\n`,
      () => process.exit(1),
    ),
  );
}
