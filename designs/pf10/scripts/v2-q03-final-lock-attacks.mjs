#!/usr/bin/env node
/*
 * Offline, fail-closed Q-03 verifier for the exact final PF10 covenant-attack
 * matrix. It never constructs attacks, signs funding inputs, or treats local
 * fixtures as qualification. A qualifying result requires complete raw
 * transactions and source parents, fresh Libauth attribution, and paired
 * signed maintainer/BCHN-mempool/LeanBCH evidence rooted in the final signed
 * descriptor.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  writeSync,
} from 'node:fs';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  directV2VerifierTopologyById,
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
} from '../packages/action/v2/topology.mjs';
import {
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  evaluateV2RawTransactionInputs,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  deriveV2FinalLocksSha256FromValidatedDescriptor,
  deriveV2ManifestArtifactFromValidatedDescriptor,
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2SettlementPinsFromValidatedDescriptor,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  revalidateV2B02FinalVmResult,
  V2_B02_TRANSACTIONS_ARTIFACT_ID,
  V2_B02_TRANSACTIONS_SCHEMA,
} from './v2-b02-final-vm.mjs';
import {
  deriveV2Q02LaneAuthorityContextFromValidatedDescriptor,
  verifyV2Q02AuthorityLaneEvidence,
  V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
} from './v2-q02-lane-evidence.mjs';
import {
  buildV2Q03AttackMatrix,
  validateV2Q03AttackMatrixDelta,
  V2_Q03_ATTACK_MATRIX_CASE_COUNT,
  v2Q03AttackMatrixSha256,
} from './v2-q03-attack-matrix.mjs';

const workspace = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../..',
);
const HASH = /^[0-9a-f]{64}$/u;
const SHA1 = /^[0-9a-f]{40}$/u;
const ROOT_ID = /^[a-z][a-z0-9-]*$/u;
const SAFE_PATH =
  /^(?!\/)(?!.*\\)(?!.*(?:^|\/)\.{1,2}(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/u;
const P2PKH = /^76a914[0-9a-f]{40}88ac$/u;
const ACTIONS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
const LANE_ROLES = Object.freeze([
  'maintainer',
  'bchn-mempool',
  'leanbch',
]);
const FINAL_IDENTITY_KEYS = Object.freeze([
  'descriptorSha256',
  'finalLocksSha256',
  'instanceId',
  'manifestSha256',
  'profileId',
  'profileSha256',
  'releaseBootstrapSha256',
  'releaseRootId',
  'runtimeMaterialSha256',
  'sourceCommit',
  'sourceTree',
  'topologyId',
]);
const STAT_FIELDS = Object.freeze([
  'dev',
  'ino',
  'mode',
  'nlink',
  'size',
  'uid',
  'mtimeNs',
  'ctimeNs',
]);
const MAX_EVIDENCE_FILE_BYTES = 256 * 1024 * 1024;
const MAX_RAW_TRANSACTION_BYTES = 100_000;
const PAIR_WINDOW_MS = 15 * 60 * 1000;
const EXPECTED_LANE_RUNS =
  V2_Q03_ATTACK_MATRIX_CASE_COUNT * LANE_ROLES.length * 2;

export const V2_Q03_CORPUS_SCHEMA =
  'shieldkit-v2-direct-q03-final-lock-attacks-corpus-v4';
export const V2_Q03_INVENTORY_SCHEMA =
  'shieldkit-v2-direct-q03-evidence-inventory-v4';
export const V2_Q03_LANE_SUBJECT_SCHEMA =
  'shieldkit-v2-direct-q03-final-lock-attack-subject-v4';
export const V2_Q03_LANE_ENVELOPE_SCHEMA =
  'shieldkit-v2-direct-q03-lane-envelope-v4';
export const V2_Q03_LANE_ATTESTATION_DOMAIN =
  'shieldkit-v2-direct-q03-final-lock-lane-attestation';
export const V2_Q03_LANE_ATTESTATION_VERSION = 1;
export const V2_Q03_VM_INPUT_SCHEMA =
  'shieldkit-v2-direct-q03-vm-run-input-v1';
export const V2_Q03_VM_OUTPUT_SCHEMA =
  'shieldkit-v2-direct-q03-per-input-run-v1';
export const V2_Q03_MACHINE_MANIFEST_SCHEMA =
  'shieldkit-v2-direct-q03-machine-manifest-v1';
export const V2_Q03_RESULT_SCHEMA =
  'shieldkit-v2-direct-q03-final-lock-attacks-v4';
export const V2_Q03_RESULT_REVALIDATION_SCHEMA =
  'shieldkit-v2-direct-q03-result-revalidation-v1';
export const V2_Q03_FAILURE_SCHEMA =
  'shieldkit-v2-direct-q03-final-lock-attacks-failure-v2';

export class V2Q03FinalLockAttacksError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q03FinalLockAttacksError';
  }
}

const fail = (message) => {
  throw new V2Q03FinalLockAttacksError(message);
};
const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonical = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');
const equal = (left, right) =>
  canonical(left).equals(canonical(right));

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return value;
}

function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(`${label} is outside its integer range`);
  }
  return value;
}

function canonicalDecimal(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    fail(`${label} must be canonical unsigned decimal`);
  }
  return value;
}

function safeRelative(value, label) {
  if (
    typeof value !== 'string'
    || !SAFE_PATH.test(value)
    || value.endsWith('/')
  ) {
    fail(`${label} must be a safe relative path`);
  }
  return value;
}

function absolute(value, label) {
  if (
    typeof value !== 'string'
    || !isAbsolute(value)
    || resolve(value) !== value
  ) {
    fail(`${label} must be an absolute normalized path`);
  }
  return value;
}

function directDirectory(pathname, label) {
  absolute(pathname, label);
  const entry = lstatSync(pathname, {
    bigint: true,
    throwIfNoEntry: false,
  });
  if (
    entry === undefined
    || !entry.isDirectory()
    || entry.isSymbolicLink()
    || realpathSync(pathname) !== pathname
  ) {
    fail(`${label} must be a direct canonical directory`);
  }
  return pathname;
}

function sameStat(left, right) {
  return STAT_FIELDS.every((field) => left[field] === right[field]);
}

function stableBytes(
  pathname,
  label,
  {
    allowEmpty = false,
    maximumBytes = MAX_EVIDENCE_FILE_BYTES,
  } = {},
) {
  absolute(pathname, label);
  const first = lstatSync(pathname, {
    bigint: true,
    throwIfNoEntry: false,
  });
  if (
    first === undefined
    || !first.isFile()
    || first.isSymbolicLink()
    || first.nlink !== 1n
    || realpathSync(pathname) !== pathname
    || (!allowEmpty && first.size === 0n)
    || first.size > BigInt(maximumBytes)
  ) {
    fail(`${label} must be a bounded direct single-link file`);
  }
  let descriptor;
  try {
    descriptor = openSync(
      pathname,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const last = lstatSync(pathname, {
      bigint: true,
      throwIfNoEntry: false,
    });
    if (
      last === undefined
      || !before.isFile()
      || !after.isFile()
      || !last.isFile()
      || last.isSymbolicLink()
      || before.nlink !== 1n
      || after.nlink !== 1n
      || last.nlink !== 1n
      || !sameStat(first, before)
      || !sameStat(before, after)
      || !sameStat(after, last)
    ) {
      fail(`${label} changed while read`);
    }
    return Buffer.from(bytes);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function jcsFile(pathname, label) {
  const bytes = stableBytes(pathname, label);
  let value;
  try {
    value = JSON.parse(bytes);
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(canonical(value))) {
    fail(`${label} must contain exact RFC8785/JCS bytes`);
  }
  return Object.freeze({
    bytes,
    path: pathname,
    sha256: sha256(bytes),
    value,
  });
}

function inside(root, path, label) {
  safeRelative(path, label);
  const pathname = resolve(root, path);
  if (!pathname.startsWith(`${root}${sep}`)) {
    fail(`${label} escapes its evidence root`);
  }
  return pathname;
}

function physicalFiles(root, label) {
  directDirectory(root, label);
  const files = [];
  const walk = (directory, prefix) => {
    const current = lstatSync(directory, { bigint: true });
    if (
      !current.isDirectory()
      || current.isSymbolicLink()
      || realpathSync(directory) !== directory
    ) {
      fail(`${label} contains an unsafe directory`);
    }
    for (const name of readdirSync(directory).sort()) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(name)) {
        fail(`${label} contains an unsafe entry name`);
      }
      const pathname = join(directory, name);
      const relativePath =
        prefix === '' ? name : `${prefix}/${name}`;
      const entry = lstatSync(pathname, { bigint: true });
      if (entry.isSymbolicLink()) {
        fail(`${label} contains a symlink`);
      }
      if (entry.isDirectory()) {
        walk(pathname, relativePath);
      } else if (
        entry.isFile()
        && entry.nlink === 1n
        && realpathSync(pathname) === pathname
      ) {
        files.push(relativePath);
      } else {
        fail(`${label} contains a special or multiply-linked file`);
      }
    }
  };
  walk(root, '');
  return Object.freeze(files.sort());
}

function loadInventory(root, label) {
  const inventoryFile = jcsFile(
    join(root, 'inventory.json'),
    `${label} inventory`,
  );
  const value = inventoryFile.value;
  exact(value, ['artifacts', 'schema'], `${label} inventory`);
  if (
    value.schema !== V2_Q03_INVENTORY_SCHEMA
    || !Array.isArray(value.artifacts)
  ) {
    fail(`${label} inventory schema is invalid`);
  }
  const pins = new Map();
  for (const [index, entry] of value.artifacts.entries()) {
    exact(entry, ['path', 'sha256'], `${label} artifact ${index}`);
    safeRelative(entry.path, `${label} artifact ${index}.path`);
    hash(entry.sha256, `${label} artifact ${index}.sha256`);
    if (pins.has(entry.path)) {
      fail(`${label} inventory repeats an artifact path`);
    }
    pins.set(entry.path, entry.sha256);
  }
  const expectedPhysical = [...pins.keys(), 'inventory.json'].sort();
  if (!equal(expectedPhysical, physicalFiles(root, label))) {
    fail(`${label} inventory does not cover the exact physical file set`);
  }
  return Object.freeze({ inventoryFile, pins });
}

function artifactReference(
  value,
  root,
  pins,
  referenced,
  label,
  options = {},
) {
  exact(value, ['path', 'sha256'], label);
  safeRelative(value.path, `${label}.path`);
  hash(value.sha256, `${label}.sha256`);
  if (pins.get(value.path) !== value.sha256) {
    fail(`${label} is not inventory-pinned`);
  }
  const bytes = stableBytes(
    inside(root, value.path, `${label}.path`),
    label,
    options,
  );
  if (sha256(bytes) !== value.sha256) {
    fail(`${label} bytes differ from their inventory hash`);
  }
  referenced.add(value.path);
  return Object.freeze({
    bytes,
    filename: inside(root, value.path, `${label}.path`),
    path: value.path,
    sha256: value.sha256,
  });
}

function jcsReference(
  value,
  root,
  pins,
  referenced,
  label,
) {
  const artifact = artifactReference(
    value,
    root,
    pins,
    referenced,
    label,
  );
  let parsed;
  try {
    parsed = JSON.parse(artifact.bytes);
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!artifact.bytes.equals(canonical(parsed))) {
    fail(`${label} must contain exact RFC8785/JCS bytes`);
  }
  return Object.freeze({ ...artifact, value: parsed });
}

function assertReferenceClosure(root, pins, referenced, label) {
  const expected = [...pins.keys()].sort();
  const actual = [...referenced].sort();
  if (!equal(expected, actual)) {
    fail(`${label} contains missing, unused, or unreferenced artifacts`);
  }
  const physical = physicalFiles(root, label);
  if (!equal([...actual, 'inventory.json'].sort(), physical)) {
    fail(`${label} physical closure changed during verification`);
  }
}

function identity(value, label) {
  exact(value, FINAL_IDENTITY_KEYS, label);
  for (const key of FINAL_IDENTITY_KEYS) {
    if (['releaseRootId', 'topologyId'].includes(key)) continue;
    if (['sourceCommit', 'sourceTree'].includes(key)) {
      if (!SHA1.test(value[key])) fail(`${label}.${key} is invalid`);
    } else {
      hash(value[key], `${label}.${key}`);
    }
  }
  if (
    !ROOT_ID.test(value.releaseRootId)
    || !ROOT_ID.test(value.topologyId)
  ) {
    fail(`${label} release root or topology ID is invalid`);
  }
  return Object.freeze({ ...value });
}

function normalizedOutput(serializedHex, label) {
  let output;
  try {
    output = parseSerializedSourceOutput(serializedHex);
  } catch (error) {
    fail(`${label} is not an exact serialized output: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  return Object.freeze({
    lockingBytecodeHex: output.lockingBytecodeHex,
    serializedHex: output.serializedHex,
    sha256: output.sha256,
    token: output.token,
    tokenPrefixHex: output.tokenPrefixHex,
    valueSatoshis: output.valueSatoshis.toString(),
  });
}

function normalizedInput(input) {
  return Object.freeze({
    outpoint: Object.freeze({ ...input.outpoint }),
    sequence: input.sequence,
    unlockingBytecodeHex: input.unlockingBytecode.toString('hex'),
  });
}

function candidate(
  value,
  root,
  pins,
  referenced,
  label,
) {
  exact(value, ['rawTransaction', 'sourceTransactions'], label);
  const raw = artifactReference(
    value.rawTransaction,
    root,
    pins,
    referenced,
    `${label}.rawTransaction`,
    { maximumBytes: MAX_RAW_TRANSACTION_BYTES },
  );
  let transaction;
  try {
    transaction = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(raw.bytes.toString('hex')),
    );
  } catch (error) {
    fail(`${label} is outside the generic 100000-byte/10000-byte/unique-outpoint envelope: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    !Array.isArray(value.sourceTransactions)
    || value.sourceTransactions.length !== transaction.inputs.length
    || Object.keys(value.sourceTransactions).length
      !== value.sourceTransactions.length
  ) {
    fail(`${label} requires one complete source transaction per input`);
  }
  const sourceTransactionHexes = [];
  const sources = transaction.inputs.map((input, index) => {
    const sourceArtifact = artifactReference(
      value.sourceTransactions[index],
      root,
      pins,
      referenced,
      `${label}.sourceTransactions[${index}]`,
      { maximumBytes: MAX_RAW_TRANSACTION_BYTES },
    );
    let source;
    try {
      source = assertV2StandardTransactionEnvelope(
        parseV2RawTransaction(sourceArtifact.bytes.toString('hex')),
      );
    } catch (error) {
      fail(`${label} source transaction ${index} is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
    const output = source.outputs[input.outpoint.vout];
    if (source.txid !== input.outpoint.txid || output === undefined) {
      fail(`${label} source transaction ${index} does not authenticate its outpoint`);
    }
    sourceTransactionHexes.push(source.rawTransactionHex);
    const normalized = normalizedOutput(
      output.serializedHex,
      `${label} source output ${index}`,
    );
    return Object.freeze({
      output: normalized,
      serializedOutputHex: normalized.serializedHex,
      sourceTransaction: Object.freeze({
        rawTransactionSha256: sourceArtifact.sha256,
        transactionId: source.txid,
      }),
    });
  });
  const normalized = Object.freeze({
    sources: Object.freeze(sources),
    transaction: Object.freeze({
      inputs: Object.freeze(transaction.inputs.map(normalizedInput)),
      outputs: Object.freeze(transaction.outputs.map((output, index) =>
        normalizedOutput(
          output.serializedHex,
          `${label} output ${index}`,
        ))),
    }),
  });
  return Object.freeze({
    normalized,
    rawTransactionSha256: raw.sha256,
    sourceOutputSha256s: Object.freeze(
      sources.map((source) => source.output.sha256),
    ),
    sourceTransactionHexes: Object.freeze(sourceTransactionHexes),
    sourceTransactionSha256s: Object.freeze(
      sources.map(
        (source) => source.sourceTransaction.rawTransactionSha256,
      ),
    ),
    transaction,
  });
}

function assertTokenlessLockAndValue(
  output,
  lockingBytecode,
  valueSats,
  label,
) {
  if (
    output.lockingBytecodeHex
      !== Buffer.from(lockingBytecode).toString('hex')
    || output.token !== null
    || output.valueSatoshis !== BigInt(valueSats)
  ) {
    fail(`${label} differs from its exact final lock/value/token pin`);
  }
}

function assertStateOutput(
  output,
  settlementPins,
  instanceId,
  reserveSats,
  label,
) {
  if (
    output.lockingBytecodeHex
      !== Buffer.from(settlementPins.stateLockingBytecode).toString(
        'hex',
      )
    || output.valueSatoshis
      !== BigInt(settlementPins.stateBaseSats) + BigInt(reserveSats)
    || output.token?.categoryWire !== instanceId
    || output.token.amount !== '0'
    || output.token.nft?.capability !== 'mutable'
    || output.token.nft.commitmentHex.length !== 256
  ) {
    fail(`${label} differs from the exact final state settlement pin`);
  }
}

function assertB02FinalPins({
  authorityArtifact,
  authorityContext,
  b02File,
  denominationSats,
  expectedIdentity,
  settlementPins,
  transactionsArtifact,
}) {
  const b02 = b02File.value;
  const revalidated = revalidateV2B02FinalVmResult(b02);
  identity(expectedIdentity, 'Q-03 expected final identity');
  for (const key of FINAL_IDENTITY_KEYS) {
    if (b02[key] !== expectedIdentity[key]) {
      fail(`Q-03 B-02 identity drifts at ${key}`);
    }
  }
  if (
    b02.authorityArtifactSha256 !== authorityArtifact.sha256
    || b02.authoritySetSha256 !== authorityContext.authoritySetSha256
    || sha256(canonical(b02.laneAuthorityArtifact))
      !== authorityArtifact.sha256
    || !canonical(b02.laneAuthorityArtifact).equals(
      authorityArtifact.bytes,
    )
    || b02.transactionsManifestSha256
      !== transactionsArtifact.sha256
  ) {
    fail('Q-03 B-02 authority or transaction manifest is not rooted in the final descriptor');
  }
  const manifest = transactionsArtifact.value;
  exact(
    manifest,
    ['identity', 'maintainerBenchmark', 'schema', 'transactions'],
    'Q-03 signed B-02 transactions manifest',
  );
  if (
    manifest.schema !== V2_B02_TRANSACTIONS_SCHEMA
    || !equal(manifest.identity, expectedIdentity)
    || !equal(manifest.maintainerBenchmark, b02.maintainerBenchmark)
    || !Array.isArray(manifest.transactions)
    || manifest.transactions.length !== ACTIONS.length
    || !Array.isArray(b02.transactions)
    || b02.transactions.length !== ACTIONS.length
  ) {
    fail('Q-03 signed B-02 transaction set has the wrong identity or cardinality');
  }
  const carrierCount = settlementPins.verifierCarriers.length;
  const actionByKind = new Map();
  for (const [actionIndex, kind] of ACTIONS.entries()) {
    const entry = b02.transactions[actionIndex];
    const pinned = manifest.transactions[actionIndex];
    if (
      entry.kind !== kind
      || pinned?.kind !== kind
      || pinned.rawTransactionHex !== entry.rawTransactionHex
      || pinned.rawTransactionSha256 !== entry.rawTransactionSha256
      || pinned.transactionId !== entry.transactionId
      || !equal(pinned.sourceOutputs, entry.sourceOutputs)
    ) {
      fail(`Q-03 B-02 ${kind} differs from its signed-manifest transaction`);
    }
    let transaction;
    try {
      transaction = assertV2StandardTransactionEnvelope(
        parseV2RawTransaction(entry.rawTransactionHex),
        { carrierCount },
      );
    } catch (error) {
      fail(`Q-03 B-02 ${kind} transaction is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
    if (
      transaction.outputs.length
        !== carrierCount + (kind === 'withdrawal' ? 4 : 3)
      || entry.sourceOutputs.length !== transaction.inputs.length
      || pinned.carrierCount !== carrierCount
      || pinned.inputCount !== transaction.inputs.length
      || pinned.outputCount !== transaction.outputs.length
      || pinned.serializedBytes !== transaction.sizeBytes
      || !equal(pinned.inputRoles, entry.inputRoleLayout)
      || !equal(pinned.outputRoles, entry.outputRoleLayout)
    ) {
      fail(`Q-03 B-02 ${kind} topology metadata drifts`);
    }
    const sources = entry.sourceOutputs.map((source, index) => {
      if (
        source.index !== index
        || source.outpoint.txid
          !== transaction.inputs[index].outpoint.txid
        || source.outpoint.vout
          !== transaction.inputs[index].outpoint.vout
      ) {
        fail(`Q-03 B-02 ${kind} source ${index} is detached`);
      }
      const parsed = parseSerializedSourceOutput(source.serializedHex);
      if (parsed.sha256 !== source.sha256) {
        fail(`Q-03 B-02 ${kind} source ${index} hash drifts`);
      }
      return parsed;
    });
    for (let index = 0; index < carrierCount; index += 1) {
      assertTokenlessLockAndValue(
        sources[index],
        settlementPins.verifierCarriers[index].lockingBytecode,
        settlementPins.verifierCarriers[index].baseValueSats,
        `Q-03 B-02 ${kind} verifier source ${index}`,
      );
      assertTokenlessLockAndValue(
        parseSerializedSourceOutput(
          transaction.outputs[index + 1].serializedHex,
        ),
        settlementPins.verifierCarriers[index].lockingBytecode,
        settlementPins.verifierCarriers[index].baseValueSats,
        `Q-03 B-02 ${kind} verifier successor ${index + 1}`,
      );
    }
    assertTokenlessLockAndValue(
      sources[carrierCount],
      settlementPins.bindingLockingBytecode,
      settlementPins.bindingBaseSats,
      `Q-03 B-02 ${kind} binding source`,
    );
    assertTokenlessLockAndValue(
      parseSerializedSourceOutput(
        transaction.outputs[carrierCount + 1].serializedHex,
      ),
      settlementPins.bindingLockingBytecode,
      settlementPins.bindingBaseSats,
      `Q-03 B-02 ${kind} binding successor`,
    );
    const reserveBefore = kind === 'deposit' ? '0' : denominationSats;
    const reserveAfter =
      kind === 'withdrawal' ? '0' : denominationSats;
    assertStateOutput(
      sources[carrierCount + 1],
      settlementPins,
      expectedIdentity.instanceId,
      reserveBefore,
      `Q-03 B-02 ${kind} state source`,
    );
    assertStateOutput(
      parseSerializedSourceOutput(
        transaction.outputs[0].serializedHex,
      ),
      settlementPins,
      expectedIdentity.instanceId,
      reserveAfter,
      `Q-03 B-02 ${kind} state successor`,
    );
    const funding = sources[carrierCount + 2];
    if (
      funding.token !== null
      || !P2PKH.test(funding.lockingBytecodeHex)
    ) {
      fail(`Q-03 B-02 ${kind} funding source is not tokenless P2PKH`);
    }
    const publicOutputs = transaction.outputs
      .slice(carrierCount + 2)
      .map((output) =>
        parseSerializedSourceOutput(output.serializedHex));
    if (
      publicOutputs.some(
        (output) =>
          output.token !== null || !P2PKH.test(output.lockingBytecodeHex),
      )
      || (
        kind === 'withdrawal'
        && publicOutputs[0].valueSatoshis !== BigInt(denominationSats)
      )
    ) {
      fail(`Q-03 B-02 ${kind} payout/change outputs are invalid`);
    }
    actionByKind.set(kind, Object.freeze({
      entry,
      transaction,
    }));
  }
  if (
    revalidated.resultSha256 !== b02File.sha256
    || revalidated.transactionCount !== ACTIONS.length
  ) {
    fail('Q-03 B-02 standalone revalidation hash or action count drifts');
  }
  return Object.freeze({
    actionByKind,
    authorityArtifactSha256: authorityArtifact.sha256,
    resultSha256: revalidated.resultSha256,
    transactionsManifestSha256: transactionsArtifact.sha256,
  });
}

function assertBaselineCandidate(candidateValue, b02Action, label) {
  const entry = b02Action.entry;
  if (
    candidateValue.transaction.rawTransactionHex
      !== entry.rawTransactionHex
    || candidateValue.transaction.txid !== entry.transactionId
    || candidateValue.rawTransactionSha256
      !== entry.rawTransactionSha256
    || candidateValue.sourceOutputSha256s.length
      !== entry.sourceOutputs.length
  ) {
    fail(`${label} is not the exact B-02 final action transaction`);
  }
  for (const [index, source] of entry.sourceOutputs.entries()) {
    if (
      source.serializedHex
        !== candidateValue.normalized.sources[index].serializedOutputHex
      || source.sha256 !== candidateValue.sourceOutputSha256s[index]
    ) {
      fail(`${label} source output ${index} differs from B-02`);
    }
  }
  const rollingParents = new Set(
    candidateValue.normalized.sources
      .slice(0, -1)
      .map((source) =>
        source.sourceTransaction.rawTransactionSha256),
  );
  if (rollingParents.size !== 1) {
    fail(`${label} rolling inputs do not share one authenticated parent`);
  }
}

function finalLockSet(settlementPins) {
  return new Set([
    ...settlementPins.verifierCarriers.map((entry) =>
      Buffer.from(entry.lockingBytecode).toString('hex')),
    Buffer.from(settlementPins.bindingLockingBytecode).toString('hex'),
    Buffer.from(settlementPins.stateLockingBytecode).toString('hex'),
  ]);
}

const RESOURCE_REJECTION =
  /(?:operation cost|hash(?:ing)?(?: digest)? iterations?|signature checks?|resource limit|density limit|maximum stack|stack (?:size|depth)|memory limit|exceeds? (?:the )?(?:maximum|limit))/iu;

function assertResourceMetricsWithin(value, label) {
  const pairs = [
    ['operationCost', 'maximumOperationCost'],
    ['hashDigestIterations', 'maximumHashDigestIterations'],
    ['signatureCheckCount', 'maximumSignatureCheckCount'],
  ];
  for (const [usedKey, maximumKey] of pairs) {
    const used = value[usedKey];
    const maximum = value[maximumKey];
    if (
      !['string', 'number'].includes(typeof used)
      || !['string', 'number'].includes(typeof maximum)
      || !/^(0|[1-9][0-9]*)$/u.test(String(used))
      || !/^(0|[1-9][0-9]*)$/u.test(String(maximum))
      || BigInt(used) > BigInt(maximum)
    ) {
      fail(`${label} exceeds or misstates ${maximumKey}`);
    }
  }
}

function assertEvaluationBinding(evaluation, candidateValue, label) {
  exact(evaluation, [
    'allInputsAccepted',
    'inputs',
    'rawTransactionSha256',
    'sourceTransactionSha256s',
    'transactionId',
  ], `${label} evaluation`);
  if (
    evaluation.rawTransactionSha256
      !== candidateValue.rawTransactionSha256
    || evaluation.transactionId !== candidateValue.transaction.txid
    || !equal(
      evaluation.sourceTransactionSha256s,
      candidateValue.sourceTransactionSha256s,
    )
    || !Array.isArray(evaluation.inputs)
    || evaluation.inputs.length
      !== candidateValue.transaction.inputs.length
  ) {
    fail(`${label} Libauth evaluation is detached from exact raw bytes`);
  }
  for (const [index, row] of evaluation.inputs.entries()) {
    exact(row, [
      'accepted',
      'error',
      'index',
      'metrics',
      'sourceOutputSha256',
      'unlockingBytecodeSha256',
    ], `${label} Libauth input ${index}`);
    if (
      row.index !== index
      || typeof row.accepted !== 'boolean'
      || (row.accepted ? row.error !== null : (
        typeof row.error !== 'string' || row.error.length === 0
      ))
      || row.sourceOutputSha256
        !== candidateValue.sourceOutputSha256s[index]
      || row.unlockingBytecodeSha256
        !== sha256(candidateValue.transaction.inputs[index].unlockingBytecode)
    ) {
      fail(`${label} Libauth input ${index} byte or verdict binding drifts`);
    }
    assertResourceMetricsWithin(
      row.metrics,
      `${label} Libauth input ${index}`,
    );
  }
}

function evaluateCandidate(candidateValue, label) {
  let evaluation;
  try {
    evaluation = evaluateV2RawTransactionInputs({
      rawTransactionHex: candidateValue.transaction.rawTransactionHex,
      sourceTransactionHexes:
        candidateValue.sourceTransactionHexes,
    });
  } catch (error) {
    fail(`${label} fresh Libauth evaluation failed as a tool/input error: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  assertEvaluationBinding(evaluation, candidateValue, label);
  return evaluation;
}

function assertLocalAttribution({
  baseline,
  baselineEvaluation,
  mutant,
  mutantEvaluation,
  settlementPins,
  label,
}) {
  if (
    baselineEvaluation.allInputsAccepted !== true
    || baselineEvaluation.inputs.some((input) => !input.accepted)
  ) {
    fail(`${label} baseline is not fresh all-input Libauth acceptance`);
  }
  if (mutantEvaluation.allInputsAccepted !== false) {
    fail(`${label} mutant was accepted by fresh whole-transaction Libauth`);
  }
  const locks = finalLockSet(settlementPins);
  const finalInputIndexes = [];
  const finalRejectedInputIndexes = [];
  const nonFinalRejectedInputIndexes = [];
  for (const [index, row] of mutantEvaluation.inputs.entries()) {
    assertResourceMetricsWithin(
      row.metrics,
      `${label} mutant input ${index}`,
    );
    const source = mutant.normalized.sources[index].output;
    const isFinalLock = locks.has(source.lockingBytecodeHex);
    if (isFinalLock) finalInputIndexes.push(index);
    if (!row.accepted && isFinalLock) {
      finalRejectedInputIndexes.push(index);
      if (RESOURCE_REJECTION.test(row.error)) {
        fail(`${label} final input ${index} rejected only by a resource ceiling`);
      }
    } else if (!row.accepted) {
      nonFinalRejectedInputIndexes.push(index);
    }
  }
  if (
    finalInputIndexes.length === 0
    || finalRejectedInputIndexes.length === 0
    || nonFinalRejectedInputIndexes.length !== 0
  ) {
    fail(`${label} does not isolate rejection to at least one final descriptor lock while every funding/extra input accepts`);
  }
  return Object.freeze({
    baselineEvaluationSha256: sha256(canonical(baselineEvaluation)),
    baselineInputCount: baseline.transaction.inputs.length,
    finalInputIndexes: Object.freeze(finalInputIndexes),
    finalRejectedInputIndexes:
      Object.freeze(finalRejectedInputIndexes),
    mutantEvaluationSha256: sha256(canonical(mutantEvaluation)),
    mutantInputAcceptance: Object.freeze(
      mutantEvaluation.inputs.map((input) => input.accepted),
    ),
    mutantInputCount: mutant.transaction.inputs.length,
    nonFinalRejectedInputIndexes:
      Object.freeze(nonFinalRejectedInputIndexes),
  });
}

/**
 * TEST-ONLY attribution seam. It has no descriptor, release-root, artifact,
 * signature, or qualification authority.
 */
export function validateV2Q03LocalAttributionForTestOnly(value) {
  exact(value, [
    'baseline',
    'baselineEvaluation',
    'mutant',
    'mutantEvaluation',
    'settlementPins',
  ], 'Q-03 test-only local attribution');
  return assertLocalAttribution({
    ...value,
    label: 'Q-03 test-only local attribution',
  });
}

function laneSubject({
  action,
  b02ResultSha256,
  baseline,
  caseId,
  expectation,
  identity: expectedIdentity,
  matrixOrdinal,
  mutant,
}) {
  const pairId = sha256(canonical({
    action,
    baselineRawTransactionSha256: baseline.rawTransactionSha256,
    baselineSourceTransactionSha256s:
      baseline.sourceTransactionSha256s,
    caseId,
    matrixSha256: v2Q03AttackMatrixSha256,
    matrixOrdinal,
    mutantRawTransactionSha256: mutant.rawTransactionSha256,
    mutantSourceTransactionSha256s:
      mutant.sourceTransactionSha256s,
  }));
  const selected =
    expectation === 'accept' ? baseline : mutant;
  return Object.freeze({
    schema: V2_Q03_LANE_SUBJECT_SCHEMA,
    action,
    b02ResultSha256,
    baselineRawTransactionSha256: baseline.rawTransactionSha256,
    baselineSourceTransactionSha256s:
      baseline.sourceTransactionSha256s,
    caseId,
    expectation,
    identity: expectedIdentity,
    inputCount: selected.transaction.inputs.length,
    matrixSha256: v2Q03AttackMatrixSha256,
    matrixOrdinal,
    mutantRawTransactionSha256: mutant.rawTransactionSha256,
    mutantSourceTransactionSha256s:
      mutant.sourceTransactionSha256s,
    pairId,
    rawTransactionSha256: selected.rawTransactionSha256,
    sourceOutputSha256s: selected.sourceOutputSha256s,
    transactionId: selected.transaction.txid,
  });
}

function envelopeClosure(
  reference,
  root,
  pins,
  referenced,
  label,
) {
  const envelope = jcsReference(
    reference,
    root,
    pins,
    referenced,
    `${label} envelope`,
  );
  plain(envelope.value, `${label} envelope`);
  exact(
    envelope.value.execution,
    ['exitCode', 'machineManifest', 'signal', 'stderr', 'stdin', 'stdout'],
    `${label} envelope.execution`,
  );
  const envelopeDirectory = dirname(envelope.path);
  const normalizeChild = (child, childLabel) => {
    exact(child, ['path', 'sha256'], childLabel);
    safeRelative(child.path, `${childLabel}.path`);
    const combined =
      envelopeDirectory === '.'
        ? child.path
        : `${envelopeDirectory}/${child.path}`;
    safeRelative(combined, `${childLabel} inventory path`);
    return Object.freeze({
      path: combined,
      sha256: child.sha256,
    });
  };
  for (const field of ['machineManifest', 'stdin', 'stdout']) {
    jcsReference(
      normalizeChild(
        envelope.value.execution[field],
        `${label} ${field}`,
      ),
      root,
      pins,
      referenced,
      `${label} ${field}`,
    );
  }
  artifactReference(
    normalizeChild(envelope.value.execution.stderr, `${label} stderr`),
    root,
    pins,
    referenced,
    `${label} stderr`,
    { allowEmpty: true },
  );
  return envelope;
}

function verifyLaneRun({
  authorityContext,
  candidate: candidateValue,
  envelope,
  expectation,
  role,
  subject,
}) {
  const expectedSourceOutputSha256s =
    role === 'maintainer' || role === 'leanbch'
      ? candidateValue.sourceOutputSha256s
      : undefined;
  const request = {
    attestationDomain: V2_Q03_LANE_ATTESTATION_DOMAIN,
    attestationVersion: V2_Q03_LANE_ATTESTATION_VERSION,
    authorityContext,
    bchnMinedInputSchema: 'shieldkit-v2-direct-q03-unused-mined-input-v1',
    bchnMinedOutputSchema:
      'shieldkit-v2-direct-q03-unused-mined-output-v1',
    envelopePath: envelope.filename,
    envelopeSchema: V2_Q03_LANE_ENVELOPE_SCHEMA,
    expectedInputCount: candidateValue.transaction.inputs.length,
    expectedRole: role,
    expectedSubject: subject,
    expectedTransaction: {
      expectation,
      rawTransactionSha256: candidateValue.rawTransactionSha256,
      transactionId: candidateValue.transaction.txid,
    },
    machineManifestSchema: V2_Q03_MACHINE_MANIFEST_SCHEMA,
    subjectField: 'subject',
    vmInputSchema: V2_Q03_VM_INPUT_SCHEMA,
    vmOutputSchema: V2_Q03_VM_OUTPUT_SCHEMA,
    ...(expectedSourceOutputSha256s === undefined
      ? {}
      : { expectedSourceOutputSha256s }),
  };
  let derived;
  try {
    derived = verifyV2Q02AuthorityLaneEvidence(request);
  } catch (error) {
    fail(`Q-03 ${role} ${expectation} lane is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    derived.envelopeSha256 !== envelope.sha256
    || derived.derivedOutcome
      !== (expectation === 'accept' ? 'accepted' : 'rejected')
    || derived.lane !== role
  ) {
    fail(`Q-03 ${role} ${expectation} lane derived the wrong closure or outcome`);
  }
  return derived;
}

function sortedPerInputRows(execution, inputCount, label) {
  const rows = execution.stdout?.inputs;
  if (!Array.isArray(rows) || rows.length !== inputCount) {
    fail(`${label} has no exact per-input stdout`);
  }
  return [...rows].sort((left, right) =>
    left.inputIndex - right.inputIndex);
}

function assertExternalInputAttribution({
  baselineRun,
  baselineEvaluation,
  mutantRun,
  mutantEvaluation,
  role,
  label,
}) {
  if (role === 'bchn-mempool') return;
  const baselineRows = sortedPerInputRows(
    baselineRun.execution,
    baselineEvaluation.inputs.length,
    `${label} baseline`,
  );
  const mutantRows = sortedPerInputRows(
    mutantRun.execution,
    mutantEvaluation.inputs.length,
    `${label} mutant`,
  );
  if (
    baselineRows.some(
      (row, index) =>
        row.inputIndex !== index
        || row.accepted !== baselineEvaluation.inputs[index].accepted,
    )
    || mutantRows.some(
      (row, index) =>
        row.inputIndex !== index
        || row.accepted !== mutantEvaluation.inputs[index].accepted,
    )
  ) {
    fail(`${label} per-input verdict vector differs from fresh Libauth`);
  }
  for (const row of mutantRows) {
    assertResourceMetricsWithin(row, `${label} input ${row.inputIndex}`);
    if (!row.accepted && RESOURCE_REJECTION.test(row.error)) {
      fail(`${label} attributes mutant rejection to a resource ceiling`);
    }
  }
}

const BCHN_UNRELATED_REJECTION =
  /(?:missing.?inputs?|missingorspent|already spent|mempool conflict|txn-mempool-conflict|already in (?:the )?(?:mempool|block chain)|insufficient fee|min relay fee|mempool min fee|absurd(?:ly)? high fee|max fee|dust|too many ancestors|too-long-mempool-chain|replacement|nonfinal|non-final|rate limit|package)/iu;
const BCHN_STRUCTURAL_REJECTION =
  /^(?:mandatory-script-verify-flag-failed|non-mandatory-script-verify-flag|bad-txns-token(?:-|$))/iu;

function assertBchnStructuralRejection(run, label) {
  const row = run.execution.stdout?.result?.[0];
  const reason =
    typeof row?.['reject-reason'] === 'string'
      ? row['reject-reason']
      : '';
  const details =
    typeof row?.['reject-details'] === 'string'
      ? row['reject-details']
      : '';
  const combined = `${reason} ${details}`;
  if (
    row?.allowed !== false
    || BCHN_UNRELATED_REJECTION.test(combined)
    || !BCHN_STRUCTURAL_REJECTION.test(reason)
  ) {
    fail(`${label} BCHN rejection is absent/spent/conflict/fee/policy evidence rather than script or CashToken rejection`);
  }
}

/**
 * TEST-ONLY reject-reason policy seam. It supplies no signed envelope,
 * authority, raw transaction, source closure, or qualification authority.
 */
export function validateV2Q03BchnRejectionForTestOnly(stdout) {
  assertBchnStructuralRejection(
    { execution: { stdout } },
    'Q-03 test-only BCHN rejection',
  );
  return true;
}

function lanePair({
  action,
  authorityContext,
  b02ResultSha256,
  baseline,
  baselineEvaluation,
  caseId,
  laneRoot,
  lanePins,
  laneReferenced,
  mutant,
  mutantEvaluation,
  matrixOrdinal,
  pair,
  role,
  seenEnvelopeHashes,
  seenRunIds,
  expectedIdentity,
}) {
  exact(pair, ['baseline', 'mutant'], `Q-03 ${caseId} ${role} pair`);
  const baselineEnvelope = envelopeClosure(
    pair.baseline,
    laneRoot,
    lanePins,
    laneReferenced,
    `Q-03 ${caseId} ${role} baseline`,
  );
  const mutantEnvelope = envelopeClosure(
    pair.mutant,
    laneRoot,
    lanePins,
    laneReferenced,
    `Q-03 ${caseId} ${role} mutant`,
  );
  const baselineRun = verifyLaneRun({
    authorityContext,
    candidate: baseline,
    envelope: baselineEnvelope,
    expectation: 'accept',
    role,
    subject: laneSubject({
      action,
      b02ResultSha256,
      baseline,
      caseId,
      expectation: 'accept',
      identity: expectedIdentity,
      matrixOrdinal,
      mutant,
    }),
  });
  const mutantRun = verifyLaneRun({
    authorityContext,
    candidate: mutant,
    envelope: mutantEnvelope,
    expectation: 'reject',
    role,
    subject: laneSubject({
      action,
      b02ResultSha256,
      baseline,
      caseId,
      expectation: 'reject',
      identity: expectedIdentity,
      matrixOrdinal,
      mutant,
    }),
  });
  if (
    baselineRun.authorityId !== mutantRun.authorityId
    || !equal(
      baselineRun.execution.tool,
      mutantRun.execution.tool,
    )
    || !equal(
      baselineRun.execution.command,
      mutantRun.execution.command,
    )
    || baselineRun.execution.machineManifestSha256
      !== mutantRun.execution.machineManifestSha256
    || !equal(
      baselineRun.execution.machineManifest,
      mutantRun.execution.machineManifest,
    )
  ) {
    fail(`Q-03 ${caseId} ${role} pair changes authority, tool, command, or machine`);
  }
  const start = Math.min(
    Date.parse(baselineRun.execution.startedAt),
    Date.parse(mutantRun.execution.startedAt),
  );
  const end = Math.max(
    Date.parse(baselineRun.execution.completedAt),
    Date.parse(mutantRun.execution.completedAt),
  );
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)
    || end - start > PAIR_WINDOW_MS) {
    fail(`Q-03 ${caseId} ${role} pair exceeds the 15-minute evidence window`);
  }
  for (const run of [baselineRun, mutantRun]) {
    if (seenRunIds.has(run.runId)) {
      fail('Q-03 signed lane run IDs must be globally unique');
    }
    seenRunIds.add(run.runId);
    if (seenEnvelopeHashes.has(run.envelopeSha256)) {
      fail('Q-03 signed lane envelopes must be globally unique');
    }
    seenEnvelopeHashes.add(run.envelopeSha256);
  }
  assertExternalInputAttribution({
    baselineEvaluation,
    baselineRun,
    label: `Q-03 ${caseId} ${role}`,
    mutantEvaluation,
    mutantRun,
    role,
  });
  if (role === 'bchn-mempool') {
    assertBchnStructuralRejection(
      mutantRun,
      `Q-03 ${caseId}`,
    );
  }
  return Object.freeze({
    authorityId: baselineRun.authorityId,
    baselineEnvelopeSha256: baselineRun.envelopeSha256,
    baselineRunId: baselineRun.runId,
    commandSha256: sha256(canonical(baselineRun.execution.command)),
    machineManifestSha256:
      baselineRun.execution.machineManifestSha256,
    mutantEnvelopeSha256: mutantRun.envelopeSha256,
    mutantRunId: mutantRun.runId,
    pairWindowMilliseconds: end - start,
    role,
    toolSha256: sha256(canonical(baselineRun.execution.tool)),
  });
}

function verifyCorpus({
  authorityContext,
  b02,
  corpus,
  corpusRoot,
  corpusPins,
  corpusReferenced,
  expectedIdentity,
  laneRoot,
  lanePins,
  laneReferenced,
  settlementPins,
}) {
  exact(corpus, [
    'b02ResultSha256',
    'cases',
    'identity',
    'matrixSha256',
    'schema',
  ], 'Q-03 corpus');
  if (
    corpus.schema !== V2_Q03_CORPUS_SCHEMA
    || corpus.b02ResultSha256 !== b02.resultSha256
    || corpus.matrixSha256 !== v2Q03AttackMatrixSha256
    || !equal(identity(corpus.identity, 'Q-03 corpus identity'), expectedIdentity)
    || !Array.isArray(corpus.cases)
    || corpus.cases.length !== V2_Q03_ATTACK_MATRIX_CASE_COUNT
  ) {
    fail('Q-03 corpus schema, identity, B-02 root, matrix, or cardinality drifts');
  }
  const matrix = buildV2Q03AttackMatrix();
  const seenRunIds = new Set();
  const seenEnvelopeHashes = new Set();
  const summaries = [];
  for (const [caseIndex, matrixEntry] of matrix.entries()) {
    const item = corpus.cases[caseIndex];
    exact(item, [
      'action',
      'baseline',
      'caseId',
      'lanePairs',
      'mutant',
    ], `Q-03 corpus case ${caseIndex}`);
    if (
      item.action !== matrixEntry.action
      || item.caseId !== matrixEntry.caseId
    ) {
      fail(`Q-03 corpus case ${caseIndex} is missing, reordered, or relabeled`);
    }
    const baseline = candidate(
      item.baseline,
      corpusRoot,
      corpusPins,
      corpusReferenced,
      `Q-03 ${item.caseId} baseline`,
    );
    const mutant = candidate(
      item.mutant,
      corpusRoot,
      corpusPins,
      corpusReferenced,
      `Q-03 ${item.caseId} mutant`,
    );
    const b02Action = b02.actionByKind.get(item.action);
    if (b02Action === undefined) {
      fail(`Q-03 ${item.caseId} has no rooted B-02 action`);
    }
    assertBaselineCandidate(
      baseline,
      b02Action,
      `Q-03 ${item.caseId} baseline`,
    );
    validateV2Q03AttackMatrixDelta({
      action: item.action,
      baseline: baseline.normalized,
      caseId: item.caseId,
      mutant: mutant.normalized,
    });
    const baselineEvaluation = evaluateCandidate(
      baseline,
      `Q-03 ${item.caseId} baseline`,
    );
    const mutantEvaluation = evaluateCandidate(
      mutant,
      `Q-03 ${item.caseId} mutant`,
    );
    const local = assertLocalAttribution({
      baseline,
      baselineEvaluation,
      label: `Q-03 ${item.caseId}`,
      mutant,
      mutantEvaluation,
      settlementPins,
    });
    exact(item.lanePairs, LANE_ROLES, `Q-03 ${item.caseId} lane pairs`);
    const lanes = LANE_ROLES.map((role) =>
      lanePair({
        action: item.action,
        authorityContext,
        b02ResultSha256: b02.resultSha256,
        baseline,
        baselineEvaluation,
        caseId: item.caseId,
        expectedIdentity,
        lanePins,
        laneReferenced,
        laneRoot,
        mutant,
        mutantEvaluation,
        matrixOrdinal: caseIndex,
        pair: item.lanePairs[role],
        role,
        seenEnvelopeHashes,
        seenRunIds,
      }));
    summaries.push(Object.freeze({
      action: item.action,
      baselineRawTransactionSha256:
        baseline.rawTransactionSha256,
      baselineTransactionId: baseline.transaction.txid,
      caseId: item.caseId,
      lanes: Object.freeze(lanes),
      local,
      matrixOrdinal: caseIndex,
      mutantRawTransactionSha256: mutant.rawTransactionSha256,
      mutantTransactionId: mutant.transaction.txid,
      sourceClosureSha256: sha256(canonical({
        baseline: baseline.sourceTransactionSha256s,
        mutant: mutant.sourceTransactionSha256s,
      })),
    }));
  }
  if (
    seenRunIds.size !== EXPECTED_LANE_RUNS
    || seenEnvelopeHashes.size !== EXPECTED_LANE_RUNS
  ) {
    fail('Q-03 exact 1314-run signed lane inventory is incomplete');
  }
  return Object.freeze({
    cases: Object.freeze(summaries),
    laneRunCount: seenRunIds.size,
  });
}

function resultTrustRoots(value) {
  exact(value, [
    'authorityArtifactSha256',
    'b02ResultSha256',
    'corpusInventorySha256',
    'corpusSha256',
    'identity',
    'laneInventorySha256',
    'matrixSha256',
    'transactionsManifestSha256',
  ], 'Q-03 independent result trust roots');
  return Object.freeze({
    authorityArtifactSha256: hash(
      value.authorityArtifactSha256,
      'Q-03 expected authority artifact hash',
    ),
    b02ResultSha256: hash(
      value.b02ResultSha256,
      'Q-03 expected B-02 result hash',
    ),
    corpusInventorySha256: hash(
      value.corpusInventorySha256,
      'Q-03 expected corpus inventory hash',
    ),
    corpusSha256: hash(
      value.corpusSha256,
      'Q-03 expected corpus hash',
    ),
    identity: identity(value.identity, 'Q-03 expected result identity'),
    laneInventorySha256: hash(
      value.laneInventorySha256,
      'Q-03 expected lane inventory hash',
    ),
    matrixSha256: hash(
      value.matrixSha256,
      'Q-03 expected matrix hash',
    ),
    transactionsManifestSha256: hash(
      value.transactionsManifestSha256,
      'Q-03 expected transactions manifest hash',
    ),
  });
}

function resultLocal(value, label) {
  exact(value, [
    'baselineEvaluationSha256',
    'baselineInputCount',
    'finalInputIndexes',
    'finalRejectedInputIndexes',
    'mutantEvaluationSha256',
    'mutantInputAcceptance',
    'mutantInputCount',
    'nonFinalRejectedInputIndexes',
  ], label);
  hash(value.baselineEvaluationSha256, `${label}.baselineEvaluationSha256`);
  hash(value.mutantEvaluationSha256, `${label}.mutantEvaluationSha256`);
  integer(value.baselineInputCount, 1, 258, `${label}.baselineInputCount`);
  integer(value.mutantInputCount, 1, 258, `${label}.mutantInputCount`);
  if (
    value.baselineInputCount
      !== directV2VerifierTopologyById(
        DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
      ).inputCount
    || !Array.isArray(value.mutantInputAcceptance)
    || value.mutantInputAcceptance.length !== value.mutantInputCount
    || value.mutantInputAcceptance.some(
      (accepted) => typeof accepted !== 'boolean',
    )
  ) {
    fail(`${label} input counts or acceptance vector are invalid`);
  }
  const indexArray = (entries, name, { allowEmpty }) => {
    if (
      !Array.isArray(entries)
      || (!allowEmpty && entries.length === 0)
      || new Set(entries).size !== entries.length
    ) {
      fail(`${label}.${name} is missing, empty, or duplicate`);
    }
    for (const index of entries) {
      integer(index, 0, value.mutantInputCount - 1, `${label}.${name}`);
    }
  };
  indexArray(value.finalInputIndexes, 'finalInputIndexes', {
    allowEmpty: false,
  });
  indexArray(
    value.finalRejectedInputIndexes,
    'finalRejectedInputIndexes',
    { allowEmpty: false },
  );
  indexArray(
    value.nonFinalRejectedInputIndexes,
    'nonFinalRejectedInputIndexes',
    { allowEmpty: true },
  );
  const finalSet = new Set(value.finalInputIndexes);
  const reportedRejected = [
    ...value.finalRejectedInputIndexes,
    ...value.nonFinalRejectedInputIndexes,
  ].sort((left, right) => left - right);
  const actualRejected = value.mutantInputAcceptance
    .map((accepted, index) => ({ accepted, index }))
    .filter((entry) => !entry.accepted)
    .map((entry) => entry.index);
  if (
    value.finalRejectedInputIndexes.some(
      (index) =>
        !finalSet.has(index) || value.mutantInputAcceptance[index],
    )
    || !equal(reportedRejected, actualRejected)
    || value.nonFinalRejectedInputIndexes.length !== 0
  ) {
    fail(`${label} does not isolate a final-lock rejection`);
  }
  return value;
}

function expectedLocalShape(matrixEntry) {
  if (matrixEntry.family === 'partial-bundle') {
    return Object.freeze({
      finalInputIndexes: Object.freeze(
        Array.from({ length: 11 }, (_, index) => index),
      ),
      mutantInputCount: 12,
    });
  }
  if (
    matrixEntry.family === 'altered-role-count'
    && matrixEntry.mode === 'missing'
  ) {
    const finalCount = matrixEntry.role === 'funding' ? 12 : 11;
    return Object.freeze({
      finalInputIndexes: Object.freeze(
        Array.from({ length: finalCount }, (_, index) => index),
      ),
      mutantInputCount: 12,
    });
  }
  return Object.freeze({
    finalInputIndexes: Object.freeze(
      Array.from({ length: 12 }, (_, index) => index),
    ),
    mutantInputCount:
      matrixEntry.family === 'altered-role-count'
      && matrixEntry.mode === 'extra-input'
        ? 14
        : 13,
  });
}

function resultLane(value, expectedRole, label) {
  exact(value, [
    'authorityId',
    'baselineEnvelopeSha256',
    'baselineRunId',
    'commandSha256',
    'machineManifestSha256',
    'mutantEnvelopeSha256',
    'mutantRunId',
    'pairWindowMilliseconds',
    'role',
    'toolSha256',
  ], label);
  if (
    value.role !== expectedRole
    || typeof value.authorityId !== 'string'
    || !/^[a-z0-9][a-z0-9._-]{0,127}$/u.test(value.authorityId)
  ) {
    fail(`${label} role or authority ID is invalid`);
  }
  for (const key of [
    'baselineEnvelopeSha256',
    'baselineRunId',
    'commandSha256',
    'machineManifestSha256',
    'mutantEnvelopeSha256',
    'mutantRunId',
    'toolSha256',
  ]) {
    hash(value[key], `${label}.${key}`);
  }
  integer(
    value.pairWindowMilliseconds,
    0,
    PAIR_WINDOW_MS,
    `${label}.pairWindowMilliseconds`,
  );
  if (
    value.baselineEnvelopeSha256 === value.mutantEnvelopeSha256
    || value.baselineRunId === value.mutantRunId
  ) {
    fail(`${label} baseline and mutant evidence are not distinct`);
  }
  return value;
}

/**
 * Structural replay of a written success result under independent roots.
 * Omitting the caller-supplied roots is an error; this function never trusts
 * the identity or hashes embedded in the result itself.
 */
export function revalidateV2Q03FinalLockAttacks(value, expectedRoots) {
  const expected = resultTrustRoots(expectedRoots);
  exact(value, [
    'attackSetSha256',
    'authorityArtifactSha256',
    'b02ResultSha256',
    'caseCount',
    'cases',
    'corpusInventorySha256',
    'corpusSha256',
    'identity',
    'laneInventorySha256',
    'lanePairCount',
    'laneRunCount',
    'matrixSha256',
    'production',
    'q03Qualified',
    'releaseQualified',
    'schema',
    'status',
    'transactionsManifestSha256',
  ], 'Q-03 result');
  if (
    value.schema !== V2_Q03_RESULT_SCHEMA
    || value.status
      !== 'q03-qualified-final-lock-attacks-not-production-or-release'
    || value.q03Qualified !== true
    || value.production !== false
    || value.releaseQualified !== false
    || value.authorityArtifactSha256
      !== expected.authorityArtifactSha256
    || value.b02ResultSha256 !== expected.b02ResultSha256
    || value.corpusInventorySha256
      !== expected.corpusInventorySha256
    || value.corpusSha256 !== expected.corpusSha256
    || value.laneInventorySha256
      !== expected.laneInventorySha256
    || value.matrixSha256 !== expected.matrixSha256
    || value.transactionsManifestSha256
      !== expected.transactionsManifestSha256
    || expected.matrixSha256 !== v2Q03AttackMatrixSha256
    || !equal(
      identity(value.identity, 'Q-03 result identity'),
      expected.identity,
    )
    || value.caseCount !== V2_Q03_ATTACK_MATRIX_CASE_COUNT
    || value.lanePairCount
      !== V2_Q03_ATTACK_MATRIX_CASE_COUNT * LANE_ROLES.length
    || value.laneRunCount !== EXPECTED_LANE_RUNS
    || !Array.isArray(value.cases)
    || value.cases.length !== V2_Q03_ATTACK_MATRIX_CASE_COUNT
  ) {
    fail('Q-03 result status, independent roots, or exact counts drift');
  }
  const matrix = buildV2Q03AttackMatrix();
  const runIds = new Set();
  const envelopeHashes = new Set();
  for (const [index, item] of value.cases.entries()) {
    exact(item, [
      'action',
      'baselineRawTransactionSha256',
      'baselineTransactionId',
      'caseId',
      'lanes',
      'local',
      'matrixOrdinal',
      'mutantRawTransactionSha256',
      'mutantTransactionId',
      'sourceClosureSha256',
    ], `Q-03 result case ${index}`);
    if (
      item.action !== matrix[index].action
      || item.caseId !== matrix[index].caseId
      || item.matrixOrdinal !== index
    ) {
      fail(`Q-03 result case ${index} is reordered or relabeled`);
    }
    for (const key of [
      'baselineRawTransactionSha256',
      'baselineTransactionId',
      'mutantRawTransactionSha256',
      'mutantTransactionId',
      'sourceClosureSha256',
    ]) {
      hash(item[key], `Q-03 result case ${index}.${key}`);
    }
    resultLocal(item.local, `Q-03 result case ${index}.local`);
    const expectedLocal = expectedLocalShape(matrix[index]);
    if (
      item.local.mutantInputCount !== expectedLocal.mutantInputCount
      || !equal(
        item.local.finalInputIndexes,
        expectedLocal.finalInputIndexes,
      )
    ) {
      fail(`Q-03 result case ${index} local topology differs from its matrix family`);
    }
    if (
      !Array.isArray(item.lanes)
      || item.lanes.length !== LANE_ROLES.length
    ) {
      fail(`Q-03 result case ${index} lane set is incomplete`);
    }
    item.lanes.forEach((lane, laneIndex) => {
      resultLane(
        lane,
        LANE_ROLES[laneIndex],
        `Q-03 result case ${index} lane ${laneIndex}`,
      );
      for (const runId of [lane.baselineRunId, lane.mutantRunId]) {
        if (runIds.has(runId)) {
          fail('Q-03 result repeats a signed lane run ID');
        }
        runIds.add(runId);
      }
      for (const envelopeSha256 of [
        lane.baselineEnvelopeSha256,
        lane.mutantEnvelopeSha256,
      ]) {
        if (envelopeHashes.has(envelopeSha256)) {
          fail('Q-03 result repeats a signed lane envelope');
        }
        envelopeHashes.add(envelopeSha256);
      }
    });
  }
  if (
    runIds.size !== EXPECTED_LANE_RUNS
    || envelopeHashes.size !== EXPECTED_LANE_RUNS
    || value.attackSetSha256 !== sha256(canonical(value.cases))
  ) {
    fail('Q-03 result run/envelope closure or attack-set hash is invalid');
  }
  return Object.freeze({
    schema: V2_Q03_RESULT_REVALIDATION_SCHEMA,
    attackSetSha256: value.attackSetSha256,
    caseCount: value.caseCount,
    identity: expected.identity,
    laneRunCount: value.laneRunCount,
    production: false,
    q03Qualified: true,
    releaseQualified: false,
    resultSha256: sha256(canonical(value)),
  });
}

export function parseV2Q03Arguments(argv) {
  const names = new Set([
    '--profile-core',
    '--descriptor',
    '--final-manifest',
    '--release-root',
    '--b02-result',
    '--attack-corpus',
    '--lane-evidence-dir',
    '--expected-commit',
    '--expected-tree',
    '--output-dir',
  ]);
  if (!Array.isArray(argv) || argv.length !== names.size * 2) {
    fail(
      'usage: v2-q03-final-lock-attacks.mjs --profile-core <absolute> --descriptor <absolute> --final-manifest <absolute> --release-root <compiled-root-id> --b02-result <absolute> --attack-corpus <absolute> --lane-evidence-dir <absolute> --expected-commit <sha1> --expected-tree <sha1> --output-dir <absolute-new-dir>',
    );
  }
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      !names.has(name)
      || values.has(name)
      || typeof value !== 'string'
      || value.length === 0
    ) {
      fail('Q-03 arguments are missing, duplicate, or malformed');
    }
    values.set(name, value);
  }
  if (
    [...names].some((name) => !values.has(name))
    || !ROOT_ID.test(values.get('--release-root'))
    || !SHA1.test(values.get('--expected-commit'))
    || !SHA1.test(values.get('--expected-tree'))
  ) {
    fail('Q-03 release root or Git pins are malformed');
  }
  return Object.freeze({
    attackCorpusPath: absolute(
      values.get('--attack-corpus'),
      'Q-03 attack corpus',
    ),
    b02ResultPath: absolute(
      values.get('--b02-result'),
      'Q-03 B-02 result',
    ),
    descriptorPath: absolute(
      values.get('--descriptor'),
      'Q-03 descriptor',
    ),
    expectedCommit: values.get('--expected-commit'),
    expectedTree: values.get('--expected-tree'),
    finalManifestPath: absolute(
      values.get('--final-manifest'),
      'Q-03 final manifest',
    ),
    laneEvidenceDirectory: absolute(
      values.get('--lane-evidence-dir'),
      'Q-03 lane evidence directory',
    ),
    outputDirectory: absolute(
      values.get('--output-dir'),
      'Q-03 output directory',
    ),
    profileCorePath: absolute(
      values.get('--profile-core'),
      'Q-03 profile core',
    ),
    releaseRootId: values.get('--release-root'),
  });
}

function assertSafeRuntime() {
  if (
    process.execArgv.length !== 0
    || Object.keys(process.env).some(
      (key) =>
        key === 'NODE_OPTIONS'
        || key === 'NODE_PATH'
        || key.startsWith('LD_')
        || key.startsWith('DYLD_'),
    )
  ) {
    fail('Q-03 refuses loader, preload, or dynamic-linker controls');
  }
}

function trustedGit() {
  for (const pathname of ['/usr/bin/git', '/bin/git']) {
    const entry = lstatSync(pathname, { throwIfNoEntry: false });
    if (
      entry?.isFile()
      && !entry.isSymbolicLink()
      && entry.uid === 0
      && (entry.mode & 0o022) === 0
      && realpathSync(pathname) === pathname
    ) {
      return pathname;
    }
  }
  fail('Q-03 requires a root-owned non-writable Git executable');
}

function cleanGitState() {
  const executable = trustedGit();
  const run = (arguments_) => {
    const result = spawnSync(
      executable,
      [
        '--no-replace-objects',
        '--literal-pathspecs',
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'include.path=/dev/null',
        '-c',
        'core.fsmonitor=false',
        ...arguments_,
      ],
      {
        cwd: workspace,
        encoding: 'utf8',
        env: {
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_NO_REPLACE_OBJECTS: '1',
          GIT_TERMINAL_PROMPT: '0',
          HOME: '/nonexistent',
          LANG: 'C',
          LC_ALL: 'C',
          PATH: '/usr/bin:/bin',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    if (
      result.error !== undefined
      || result.status !== 0
      || result.signal !== null
      || result.stderr !== ''
    ) {
      fail('Q-03 sanitized Git query failed');
    }
    return result.stdout;
  };
  const root = run(['rev-parse', '--show-toplevel']).trim();
  const commit = run(['rev-parse', 'HEAD^{commit}']).trim();
  const tree = run(['rev-parse', 'HEAD^{tree}']).trim();
  const status = run([
    'status',
    '--porcelain=v1',
    '--untracked-files=all',
  ]);
  if (
    root !== workspace
    || !SHA1.test(commit)
    || !SHA1.test(tree)
    || status !== ''
  ) {
    fail('Q-03 requires the exact clean compiled checkout');
  }
  return Object.freeze({ commit, tree });
}

function createOutputDirectory(directory) {
  if (existsSync(directory)) {
    fail('Q-03 refuses a preexisting output directory');
  }
  directDirectory(dirname(directory), 'Q-03 output parent');
  mkdirSync(directory, { mode: 0o700 });
  chmodSync(directory, 0o700);
  const entry = lstatSync(directory);
  if (
    !entry.isDirectory()
    || entry.isSymbolicLink()
    || entry.uid !== process.getuid()
    || (entry.mode & 0o7777) !== 0o700
    || realpathSync(directory) !== directory
  ) {
    fail('Q-03 output directory must be direct user-owned mode 0700');
  }
}

function writeDirect(directory, filename, value) {
  const pathname = join(directory, filename);
  const temporary = join(
    directory,
    `.${process.pid}.${Date.now()}.${filename}.tmp`,
  );
  const bytes = canonical(value);
  let descriptor;
  try {
    descriptor = openSync(
      temporary,
      fsConstants.O_WRONLY
        | fsConstants.O_CREAT
        | fsConstants.O_EXCL
        | (fsConstants.O_NOFOLLOW ?? 0),
      0o600,
    );
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
  chmodSync(temporary, 0o600);
  renameSync(temporary, pathname);
  const entry = lstatSync(pathname);
  if (
    !entry.isFile()
    || entry.isSymbolicLink()
    || entry.nlink !== 1
    || entry.uid !== process.getuid()
    || (entry.mode & 0o7777) !== 0o600
    || realpathSync(pathname) !== pathname
  ) {
    fail(`Q-03 ${filename} is not a direct user-owned mode-0600 file`);
  }
  const directoryDescriptor = openSync(
    directory,
    fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0),
  );
  try {
    fsyncSync(directoryDescriptor);
  } finally {
    closeSync(directoryDescriptor);
  }
  return Object.freeze({
    path: pathname,
    sha256: sha256(bytes),
  });
}

function pathsOverlap(left, right) {
  const fromLeft = relative(left, right);
  const fromRight = relative(right, left);
  const descends = (value) =>
    value === ''
    || (!value.startsWith(`..${sep}`) && value !== '..' && !isAbsolute(value));
  return descends(fromLeft) || descends(fromRight);
}

function writeFailure(options, error, context = {}) {
  try {
    if (
      options === undefined
      || existsSync(options.outputDirectory)
    ) {
      return;
    }
    createOutputDirectory(options.outputDirectory);
    const reason = (
      error instanceof Error ? error.message : String(error)
    )
      .replace(/[\u0000-\u001f\u007f]+/gu, ' ')
      .slice(0, 4096);
    writeDirect(options.outputDirectory, 'failure.json', {
      schema: V2_Q03_FAILURE_SCHEMA,
      status: 'q03-not-qualified',
      q03Qualified: false,
      production: false,
      releaseQualified: false,
      request: {
        expectedCommit: options.expectedCommit,
        expectedTree: options.expectedTree,
        releaseRootId: options.releaseRootId,
      },
      resolved: {
        b02ResultSha256: context.b02ResultSha256 ?? null,
        corpusSha256: context.corpusSha256 ?? null,
        identity: context.identity ?? null,
        matrixSha256: v2Q03AttackMatrixSha256,
      },
      reason,
    });
  } catch {
    // Preserve the primary failure and never overwrite an existing directory.
  }
}

function assertFinalRuntime(runtime) {
  if (
    runtime.eligibility !== 'final-qualified'
    || runtime.claims.finalKey !== true
    || runtime.claims.developmentKey !== false
    || runtime.claims.ceremonyQualified !== true
    || runtime.claims.production !== false
    || runtime.claims.releaseQualified !== false
  ) {
    fail('Q-03 requires exact final-key ceremony-qualified non-production runtime material');
  }
  return runtime;
}

export async function verifyV2Q03FinalLockAttacks(
  options,
  dependencies = undefined,
) {
  if (
    dependencies !== undefined
    && (
      dependencies === null
      || typeof dependencies !== 'object'
      || Object.keys(dependencies).length !== 0
    )
  ) {
    fail('Q-03 production verifier refuses injected dependencies or test doubles');
  }
  exact(options, [
    'attackCorpusPath',
    'b02ResultPath',
    'descriptorPath',
    'expectedCommit',
    'expectedTree',
    'finalManifestPath',
    'laneEvidenceDirectory',
    'outputDirectory',
    'profileCorePath',
    'releaseRootId',
  ], 'Q-03 options');
  const failureContext = {};
  let outputCreated = false;
  try {
    assertSafeRuntime();

    // Trust-order invariant: compiled release authority is resolved before
    // caller-selected files or evidence directories are opened.
    const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId);
    const git = cleanGitState();
    if (
      git.commit !== options.expectedCommit
      || git.tree !== options.expectedTree
    ) {
      fail('Q-03 live source differs from exact expected commit/tree');
    }

    const corpusRoot = directDirectory(
      dirname(options.attackCorpusPath),
      'Q-03 corpus root',
    );
    const laneRoot = directDirectory(
      options.laneEvidenceDirectory,
      'Q-03 lane evidence root',
    );
    if (
      corpusRoot === laneRoot
      || pathsOverlap(corpusRoot, options.outputDirectory)
      || pathsOverlap(laneRoot, options.outputDirectory)
    ) {
      fail('Q-03 corpus, lane, and output roots must be distinct and non-overlapping');
    }

    const profile = jcsFile(options.profileCorePath, 'Q-03 profile core');
    const release = verifyV2FinalReleaseProfileCore(
      releaseRoot,
      profile.bytes,
      profile.value,
    );
    const descriptor = await loadV2InstanceDescriptor({
      descriptorPath: options.descriptorPath,
      profileCore: profile.value,
      trustedSigners: release.descriptorSigners,
    });
    const finalManifest = jcsFile(
      options.finalManifestPath,
      'Q-03 final manifest',
    );
    if (
      descriptor.manifest.filename !== options.finalManifestPath
      || descriptor.manifest.sha256 !== finalManifest.sha256
      || descriptor.profileId !== releaseRoot.profileId
      || descriptor.finalLocks.topology.id
        !== DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
      || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
    ) {
      fail('Q-03 descriptor, manifest, profile, or PF10 topology drifts from the compiled release root');
    }
    const topology = directV2VerifierTopologyById(
      descriptor.finalLocks.topology.id,
    );
    if (
      descriptor.finalLocks.verifiers.length !== topology.carrierCount
      || descriptor.finalLocks.verifiers.some(
        (entry, index) => entry.role !== topology.verifierRoles[index],
      )
      || releaseRoot.topology.verifierRoles.some(
        (role, index) => role !== topology.verifierRoles[index],
      )
    ) {
      fail('Q-03 final verifier role order differs from exact PF10');
    }
    const runtime = assertFinalRuntime(
      await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor),
    );
    const expectedIdentity = identity({
      descriptorSha256: descriptor.descriptor.sha256,
      finalLocksSha256:
        deriveV2FinalLocksSha256FromValidatedDescriptor(descriptor),
      instanceId: descriptor.instanceId,
      manifestSha256: descriptor.manifest.sha256,
      profileId: descriptor.profileId,
      profileSha256: profile.sha256,
      releaseBootstrapSha256: release.releaseBootstrapSha256,
      releaseRootId: release.releaseRootId,
      runtimeMaterialSha256:
        runtime.runtimeMaterial.materialSha256,
      sourceCommit: git.commit,
      sourceTree: git.tree,
      topologyId: descriptor.finalLocks.topology.id,
    }, 'Q-03 final identity');
    failureContext.identity = expectedIdentity;

    const settlementPins =
      deriveV2SettlementPinsFromValidatedDescriptor(descriptor);
    const authorityPin =
      deriveV2ManifestArtifactFromValidatedDescriptor(
        descriptor,
        V2_Q02_LANE_AUTHORITY_ARTIFACT_ID,
      );
    const authorityArtifact = jcsFile(
      authorityPin.path,
      'Q-03 descriptor-pinned lane authority artifact',
    );
    if (authorityArtifact.sha256 !== authorityPin.sha256) {
      fail('Q-03 lane authority artifact differs from its signed-manifest pin');
    }
    const authorityContext =
      deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(descriptor);
    const transactionsPin =
      deriveV2ManifestArtifactFromValidatedDescriptor(
        descriptor,
        V2_B02_TRANSACTIONS_ARTIFACT_ID,
      );
    const transactionsArtifact = jcsFile(
      transactionsPin.path,
      'Q-03 descriptor-pinned B-02 transactions',
    );
    if (transactionsArtifact.sha256 !== transactionsPin.sha256) {
      fail('Q-03 B-02 transactions differ from their signed-manifest pin');
    }
    const b02File = jcsFile(
      options.b02ResultPath,
      'Q-03 B-02 result',
    );
    failureContext.b02ResultSha256 = b02File.sha256;
    const b02 = assertB02FinalPins({
      authorityArtifact,
      authorityContext,
      b02File,
      denominationSats: profile.value.denominationSats,
      expectedIdentity,
      settlementPins,
      transactionsArtifact,
    });

    const corpusInventory = loadInventory(corpusRoot, 'Q-03 corpus');
    const corpusReferenced = new Set();
    const corpusRelative = basename(options.attackCorpusPath);
    if (
      join(corpusRoot, corpusRelative) !== options.attackCorpusPath
      || corpusInventory.pins.get(corpusRelative) === undefined
    ) {
      fail('Q-03 corpus JSON must be an inventory-pinned direct child');
    }
    const corpusFile = jcsReference(
      {
        path: corpusRelative,
        sha256: corpusInventory.pins.get(corpusRelative),
      },
      corpusRoot,
      corpusInventory.pins,
      corpusReferenced,
      'Q-03 corpus',
    );
    failureContext.corpusSha256 = corpusFile.sha256;
    const laneInventory = loadInventory(laneRoot, 'Q-03 lane evidence');
    const laneReferenced = new Set();
    const verified = verifyCorpus({
      authorityContext,
      b02,
      corpus: corpusFile.value,
      corpusPins: corpusInventory.pins,
      corpusReferenced,
      corpusRoot,
      expectedIdentity,
      lanePins: laneInventory.pins,
      laneReferenced,
      laneRoot,
      settlementPins,
    });
    assertReferenceClosure(
      corpusRoot,
      corpusInventory.pins,
      corpusReferenced,
      'Q-03 corpus',
    );
    assertReferenceClosure(
      laneRoot,
      laneInventory.pins,
      laneReferenced,
      'Q-03 lane evidence',
    );
    const result = Object.freeze({
      schema: V2_Q03_RESULT_SCHEMA,
      status:
        'q03-qualified-final-lock-attacks-not-production-or-release',
      q03Qualified: true,
      production: false,
      releaseQualified: false,
      identity: expectedIdentity,
      authorityArtifactSha256: b02.authorityArtifactSha256,
      b02ResultSha256: b02.resultSha256,
      corpusInventorySha256:
        corpusInventory.inventoryFile.sha256,
      corpusSha256: corpusFile.sha256,
      laneInventorySha256:
        laneInventory.inventoryFile.sha256,
      matrixSha256: v2Q03AttackMatrixSha256,
      transactionsManifestSha256:
        b02.transactionsManifestSha256,
      caseCount: verified.cases.length,
      lanePairCount: verified.cases.length * LANE_ROLES.length,
      laneRunCount: verified.laneRunCount,
      cases: verified.cases,
      attackSetSha256: sha256(canonical(verified.cases)),
    });
    revalidateV2Q03FinalLockAttacks(result, {
      authorityArtifactSha256: b02.authorityArtifactSha256,
      b02ResultSha256: b02.resultSha256,
      corpusInventorySha256:
        corpusInventory.inventoryFile.sha256,
      corpusSha256: corpusFile.sha256,
      identity: expectedIdentity,
      laneInventorySha256:
        laneInventory.inventoryFile.sha256,
      matrixSha256: v2Q03AttackMatrixSha256,
      transactionsManifestSha256:
        b02.transactionsManifestSha256,
    });
    createOutputDirectory(options.outputDirectory);
    outputCreated = true;
    const artifact = writeDirect(
      options.outputDirectory,
      'q03-final-lock-attacks.json',
      result,
    );
    return Object.freeze({
      ...result,
      artifactPath: artifact.path,
      artifactSha256: artifact.sha256,
    });
  } catch (error) {
    if (!outputCreated) writeFailure(options, error, failureContext);
    throw error;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const result = await verifyV2Q03FinalLockAttacks(
      parseV2Q03Arguments(process.argv.slice(2)),
    );
    process.stdout.write(`${canonicalizeJcs(result)}\n`);
  } catch (error) {
    process.stderr.write(`Q-03 final-lock attacks failed: ${
      error instanceof Error ? error.message : String(error)
    }\n`);
    process.exitCode = 1;
  }
}
