#!/usr/bin/env node
/*
 * Q-02 is an offline verifier for externally produced final-key evidence.
 * It never produces proofs, transactions, VM verdicts, or trust roots.
 */
import {
  constants as fsConstants,
  closeSync,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  actionPacketPublicLimbs,
  ACTION_PACKET_OFFSETS,
  decodeActionPacket,
} from '../packages/action/v2/packet.mjs';
import {
  decodeDirectV2BindingUnlock,
} from '../packages/action/v2/binding-unlock.mjs';
import {
  hashDirectV2TransactionContext,
  validateDirectV2RoleTopology,
} from '../packages/action/v2/context.mjs';
import {
  resolveDirectV2VerifierTopology,
} from '../packages/action/v2/topology.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  resolveV2FinalReleaseRoot,
  verifyV2FinalReleaseProfileCore,
} from '../packages/profile/v2/release-bootstrap.mjs';
import {
  deriveV2Pf10RuntimeFromValidatedDescriptor,
  deriveV2Pf10StoreRuntimeMaterialsSha256,
  loadV2InstanceDescriptor,
} from '../packages/profile/v2/instance-descriptor.mjs';
import {
  assertV2SourceOutputTopology,
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
} from '../packages/kit/v2/transaction-policy.mjs';
import {
  createV2LocalVmEvidence,
  inspectV2LocalVmEvidence,
} from '../packages/kit/v2/vm-evidence.mjs';
import {
  verifyV2SignedSettlementEvidence,
} from '../packages/kit/v2/network-gate.mjs';
import {
  buildDirectV2Pf10ActionWitness,
} from '../packages/unlock-builder/v2/pf10-action-witness.mjs';
import {
  deriveV2Q02LaneAuthorityContextFromValidatedDescriptor,
  verifyV2Q02LaneEvidence,
} from './v2-q02-lane-evidence.mjs';

const HASH = /^[0-9a-f]{64}$/;
const KINDS = Object.freeze(['deposit', 'transfer', 'withdrawal']);
// Mined evidence proves canonical inclusion, so it is required only for
// accepted base transactions. Rejected mutations require executable rejection
// from the maintainer verifier, BCHN testmempoolaccept, and LeanBCH; accepting
// a mined-inclusion envelope for a reject case is itself invalid.
export const V2_Q02_ACCEPTANCE_EXTERNAL_LANES = Object.freeze([
  'maintainer',
  'bchn-mempool',
  'bchn-mined',
  'leanbch',
]);
export const V2_Q02_REJECTION_EXTERNAL_LANES = Object.freeze([
  'maintainer',
  'bchn-mempool',
  'leanbch',
]);
const MUTATIONS = Object.freeze([
  'proof',
  'packet',
  'state',
  'profile',
  'category',
  'carrier',
  'token',
  'value',
  'role',
  'outpoint',
  'fee',
  'change',
  'payout',
]);
const MAX_FILE_BYTES = 256 * 1024 * 1024;

export const V2_Q02_CORPUS_SCHEMA =
  'shieldkit-v2-direct-q02-final-key-corpus-v2';

export class V2Q02FinalKeyCorpusError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q02FinalKeyCorpusError';
  }
}

const fail = (message) => {
  throw new V2Q02FinalKeyCorpusError(message);
};
const sha256 = (value) =>
  createHash('sha256').update(value).digest('hex');
const canonicalBytes = (value) =>
  Buffer.from(canonicalizeJcs(value), 'utf8');

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
    || actual.some((entry, index) => entry !== expected[index])
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

function sameFile(before, after) {
  return (
    before.dev === after.dev
    && before.ino === after.ino
    && before.mode === after.mode
    && before.nlink === after.nlink
    && before.size === after.size
    && before.mtimeNs === after.mtimeNs
    && before.ctimeNs === after.ctimeNs
  );
}

function stableFile(
  filename,
  label,
  { allowEmpty = false, maximumBytes = MAX_FILE_BYTES } = {},
) {
  absolute(filename, label);
  const pathname = lstatSync(filename, { bigint: true, throwIfNoEntry: false });
  if (
    pathname === undefined
    || !pathname.isFile()
    || pathname.isSymbolicLink()
    || pathname.nlink !== 1n
    || realpathSync(filename) !== filename
  ) {
    fail(`${label} must be a direct single-link file without symlink ancestors`);
  }
  let descriptor;
  try {
    descriptor = openSync(
      filename,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
    const before = fstatSync(descriptor, { bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || (!allowEmpty && before.size === 0n)
      || before.size > BigInt(maximumBytes)
      || before.dev !== pathname.dev
      || before.ino !== pathname.ino
    ) {
      fail(`${label} has an unsafe type, link count, or byte size`);
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    const finalPath = lstatSync(filename, {
      bigint: true,
      throwIfNoEntry: false,
    });
    if (
      finalPath === undefined
      || !sameFile(before, after)
      || finalPath.dev !== after.dev
      || finalPath.ino !== after.ino
    ) {
      fail(`${label} changed while it was read`);
    }
    return Buffer.from(bytes);
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

function parseJcs(bytes, label) {
  let value;
  try {
    value = JSON.parse(bytes);
  } catch {
    fail(`${label} is not JSON`);
  }
  if (!bytes.equals(canonicalBytes(value))) {
    fail(`${label} must use exact RFC8785/JCS bytes`);
  }
  return value;
}

function jcsFile(filename, label) {
  const bytes = stableFile(filename, label);
  return Object.freeze({
    bytes,
    path: filename,
    sha256: sha256(bytes),
    value: parseJcs(bytes, label),
  });
}

function reference(value, root, label, { jcs = false } = {}) {
  exact(value, ['path', 'sha256'], label);
  hash(value.sha256, `${label}.sha256`);
  if (
    typeof value.path !== 'string'
    || value.path.length === 0
    || isAbsolute(value.path)
    || value.path.split(/[\\/]/u).includes('..')
  ) {
    fail(`${label}.path must be a safe relative path`);
  }
  const filename = resolve(root, value.path);
  if (!filename.startsWith(`${root}/`)) {
    fail(`${label}.path escapes the corpus directory`);
  }
  const bytes = stableFile(filename, label);
  if (sha256(bytes) !== value.sha256) {
    fail(`${label} SHA-256 pin mismatch`);
  }
  return Object.freeze({
    bytes,
    path: filename,
    sha256: value.sha256,
    value: jcs ? parseJcs(bytes, label) : undefined,
  });
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function parseV2Q02Arguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 8) {
    fail(
      'usage: v2-q02-final-key-corpus.mjs --corpus <absolute> --descriptor <absolute> --profile-core <absolute> --release-root <compiled-root-id>',
    );
  }
  const allowed = new Set([
    '--corpus',
    '--descriptor',
    '--profile-core',
    '--release-root',
  ]);
  const parsed = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!allowed.has(key) || Object.hasOwn(parsed, key)) {
      fail('Q-02 arguments are malformed');
    }
    parsed[key] = key === '--release-root'
      ? argv[index + 1]
      : absolute(argv[index + 1], key);
  }
  if (Object.keys(parsed).length !== allowed.size) {
    fail('Q-02 requires all four inputs');
  }
  return Object.freeze({
    corpusPath: parsed['--corpus'],
    descriptorPath: parsed['--descriptor'],
    profileCorePath: parsed['--profile-core'],
    releaseRootId: parsed['--release-root'],
  });
}

function sourceTransactions(value, root, transaction, label) {
  if (
    !Array.isArray(value)
    || value.length !== transaction.inputs.length
  ) {
    fail(`${label} must authenticate every transaction input`);
  }
  return Object.freeze(value.map((entry, index) => {
    const artifact = reference(
      entry,
      root,
      `${label} source transaction ${index}`,
    );
    let source;
    try {
      source = parseV2RawTransaction(artifact.bytes.toString('hex'));
    } catch (error) {
      fail(`${label} source transaction ${index} is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`);
    }
    const outpoint = transaction.inputs[index].outpoint;
    const output = source.outputs[outpoint.vout];
    if (source.txid !== outpoint.txid || output === undefined) {
      fail(`${label} source transaction ${index} does not authenticate its outpoint`);
    }
    return Object.freeze({
      artifact,
      output: parseSerializedSourceOutput(output.serializedHex),
      // Preserve the consensus serialization as well as the decoded form. A
      // decoded-output comparison alone would leave room for a mutation to
      // swap source bytes that happen to decode to the same convenience view.
      serializedOutputHex: output.serializedHex,
      source,
    });
  }));
}

function normalizedOutput(output) {
  return Object.freeze({
    lockingBytecodeHex: output.lockingBytecodeHex,
    token: output.token,
    tokenPrefixHex: output.tokenPrefixHex,
    valueSatoshis: output.valueSatoshis.toString(),
  });
}

function transactionFacts(transaction, sources) {
  return Object.freeze({
    inputs: Object.freeze(transaction.inputs.map((input, index) =>
      Object.freeze({
        outpoint: input.outpoint,
        sequence: input.sequence,
        sourceOutput: normalizedOutput(sources[index].output),
        sourceOutputSerializedHex: sources[index].serializedOutputHex,
        sourceTransactionSha256: sources[index].artifact.sha256,
        unlockingBytecodeSha256: sha256(input.unlockingBytecode),
      }))),
    locktime: transaction.locktime,
    outputs: Object.freeze(transaction.outputs.map((entry) =>
      normalizedOutput(parseSerializedSourceOutput(entry.serializedHex)))),
    version: transaction.version,
  });
}

function withoutUnlocks(facts) {
  return Object.freeze({
    ...facts,
    inputs: Object.freeze(facts.inputs.map((entry) =>
      Object.freeze({
        outpoint: entry.outpoint,
        sequence: entry.sequence,
        sourceOutput: entry.sourceOutput,
        sourceTransactionSha256: entry.sourceTransactionSha256,
      }))),
  });
}

function same(left, right) {
  return canonicalBytes(left).equals(canonicalBytes(right));
}

function bundleHash(value) {
  return sha256(canonicalBytes({
    contextSha256: value.contextSha256,
    packetSha256: value.packet.sha256,
    proofSha256: value.proof.sha256,
    rawTransactionSha256: value.rawTransactionSha256,
    sourceTransactionSha256s: value.sources.map(
      (entry) => entry.artifact.sha256,
    ),
    transactionId: value.transaction.txid,
  }));
}

function assertActionWitnessBinding(transaction, witness, topology, label) {
  if (
    transaction.inputs.length !== topology.inputCount
    || witness.verifierUnlockingBytecodes.length !== topology.carrierCount
  ) {
    fail(`${label} witness/input count differs from the selected topology`);
  }
  for (let index = 0; index < topology.carrierCount; index += 1) {
    if (
      !transaction.inputs[index].unlockingBytecode.equals(
        Buffer.from(witness.verifierUnlockingBytecodes[index]),
      )
    ) {
      fail(
        `${label} verifier input ${index} does not contain its proof-derived witness`,
      );
    }
  }
  if (
    !transaction.inputs[topology.bindingInputIndex].unlockingBytecode.equals(
      Buffer.from(witness.bindingUnlockingBytecode),
    )
    || !transaction.inputs[topology.stateInputIndex].unlockingBytecode.equals(
      Buffer.from(witness.stateUnlockingBytecode),
    )
  ) {
    fail(
      `${label} binding/state input does not contain the exact packet/runtime witness`,
    );
  }
}

function assertPacketBinding(transaction, packet, final, label) {
  try {
    decodeDirectV2BindingUnlock({
      expectedPacket: packet,
      sourceLockingBytecode: final.bindingLock,
      unlockingBytecode:
        transaction.inputs[final.topology.bindingInputIndex]
          .unlockingBytecode,
    });
  } catch (error) {
    fail(`${label} binding input does not embed the exact packet: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
}

function laneReferences(value, expectedNames, label) {
  exact(value, expectedNames, label);
  return value;
}

export function requiredV2Q02ExternalLanesForExpectation(expectation) {
  if (expectation === 'accept') return V2_Q02_ACCEPTANCE_EXTERNAL_LANES;
  if (expectation === 'reject') return V2_Q02_REJECTION_EXTERNAL_LANES;
  fail('Q-02 external lane expectation is invalid');
}

export function assertV2Q02ExternalLaneMapForTestOnly(value, expectation) {
  return laneReferences(
    value,
    requiredV2Q02ExternalLanesForExpectation(expectation),
    'Q-02 external lane references',
  );
}

function verifyExternalLanes({
  authorityContext,
  expectedCase,
  lanes,
  root,
  runIds,
}) {
  const names = requiredV2Q02ExternalLanesForExpectation(
    expectedCase.expectation,
  );
  laneReferences(lanes, names, 'Q-02 external lane references');
  for (const name of names) {
    const artifact = reference(
      lanes[name],
      root,
      `Q-02 ${name} lane envelope`,
      { jcs: true },
    );
    const result = verifyV2Q02LaneEvidence({
      authorityContext,
      envelopePath: artifact.path,
      expectedCase,
    });
    if (
      result.lane !== name
      || result.envelopeSha256 !== artifact.sha256
      || runIds.has(result.runId)
    ) {
      fail('Q-02 external lane result is substituted or replayed');
    }
    runIds.add(result.runId);
  }
}

function validateBaseSources(material, final, context) {
  material.sources.forEach((source, index) => {
    const input = material.transaction.inputs[index];
    const contextInput = context.inputs[index];
    if (
      !contextInput.outpointTransactionHash.equals(
        Buffer.from(input.outpoint.txid, 'hex'),
      )
      || contextInput.outpointIndex !== input.outpoint.vout
      || contextInput.valueSats !== source.output.valueSatoshis
      || !contextInput.lockingBytecode.equals(source.output.lockingBytecode)
      || !contextInput.tokenPrefix.equals(
        Buffer.from(source.output.tokenPrefixHex, 'hex'),
      )
    ) {
      fail(`${material.caseId} source/context outpoint binding mismatch`);
    }
    assertV2SourceOutputTopology({
      index,
      sourceOutput: source.output,
      instanceId: final.instanceId,
      carrierCount: final.topology.carrierCount,
    });
    const expectedLock =
      index < final.topology.carrierCount
        ? final.verifierLocks[index]
        : index === final.topology.bindingInputIndex
          ? final.bindingLock
          : index === final.topology.stateInputIndex
            ? final.stateLock
            : null;
    if (
      expectedLock !== null
      && !source.output.lockingBytecode.equals(expectedLock)
    ) {
      fail(`${material.caseId} source lock differs from final descriptor`);
    }
  });
}

async function validateBaseCase(
  entry,
  root,
  final,
  authorityContext,
  runIds,
) {
  exact(entry, [
    'caseId',
    'index',
    'kind',
    'lanes',
    'localVmEvidence',
    'metadata',
    'packet',
    'proof',
    'rawTransactionHex',
    'sourceTransactions',
    'transactionContext',
  ], 'Q-02 base case');
  if (
    !KINDS.includes(entry.kind)
    || !Number.isInteger(entry.index)
    || entry.index < 0
    || entry.index >= 256
    || entry.caseId !== `${entry.kind}-${entry.index}`
  ) {
    fail('Q-02 base case identity is invalid');
  }
  const proof = reference(
    entry.proof,
    root,
    `Q-02 ${entry.caseId} proof`,
    { jcs: true },
  );
  const packet = reference(
    entry.packet,
    root,
    `Q-02 ${entry.caseId} packet`,
  );
  if (packet.bytes.length !== 552) {
    fail(`Q-02 ${entry.caseId} packet must be exactly 552 bytes`);
  }
  let decodedPacket;
  try {
    decodedPacket = decodeActionPacket(packet.bytes, {
      denominationSats: final.denominationSats,
    });
  } catch (error) {
    fail(`Q-02 ${entry.caseId} packet is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    decodedPacket.kind !== entry.kind
    || decodedPacket.instanceId !== final.instanceId
  ) {
    fail(`Q-02 ${entry.caseId} packet does not bind final identity`);
  }
  if (
    proof.value === null
    || Array.isArray(proof.value)
    || typeof proof.value !== 'object'
    || proof.value.proof === null
    || Array.isArray(proof.value.proof)
    || typeof proof.value.proof !== 'object'
    || !Array.isArray(proof.value.publicInputs)
  ) {
    fail(`Q-02 ${entry.caseId} proof result is malformed`);
  }
  const publicInputs = actionPacketPublicLimbs(packet.bytes, {
    denominationSats: final.denominationSats,
  });
  if (
    !Array.isArray(proof.value.publicInputs)
    || proof.value.publicInputs.length !== publicInputs.length
    || proof.value.publicInputs.some(
      (value, index) => value !== publicInputs[index],
    )
    || !await final.snarkjs.groth16.verify(
      final.verificationKey,
      proof.value.publicInputs,
      proof.value.proof,
    )
  ) {
    fail(`Q-02 ${entry.caseId} final Groth16 proof did not verify`);
  }
  let actionWitness;
  try {
    actionWitness = buildDirectV2Pf10ActionWitness({
      actionPacket: packet.bytes,
      denominationSats: final.denominationSats,
      proofResult: proof.value,
      runtimeMaterial: final.runtimeMaterial,
    });
  } catch (error) {
    fail(
      `Q-02 ${entry.caseId} proof cannot derive the selected PF10 witness: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  let context;
  try {
    context = validateDirectV2RoleTopology(
      entry.transactionContext,
      final.topology.carrierCount,
    );
  } catch (error) {
    fail(`Q-02 ${entry.caseId} context topology is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    context.kind !== entry.kind
    || context.profileId.toString('hex') !== final.profileId
    || context.instanceId.toString('hex') !== final.instanceId
    || !hashDirectV2TransactionContext(context, {
      carrierCount: final.topology.carrierCount,
    }).equals(Buffer.from(decodedPacket.transactionContextHash, 'hex'))
  ) {
    fail(`Q-02 ${entry.caseId} packet/context binding is invalid`);
  }
  let transaction;
  try {
    transaction = assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(entry.rawTransactionHex),
      { carrierCount: final.topology.carrierCount },
    );
  } catch (error) {
    fail(`Q-02 ${entry.caseId} raw transaction is invalid: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  const expectedOutputs =
    entry.kind === 'withdrawal'
      ? final.topology.withdrawalOutputCount
      : final.topology.depositTransferOutputCount;
  if (
    transaction.version !== 2
    || transaction.locktime !== 0
    || transaction.inputs.length !== final.topology.inputCount
    || transaction.outputs.length !== expectedOutputs
  ) {
    fail(`Q-02 ${entry.caseId} selected-topology counts are invalid`);
  }
  const sources = sourceTransactions(
    entry.sourceTransactions,
    root,
    transaction,
    `Q-02 ${entry.caseId}`,
  );
  const material = Object.freeze({
    actionWitness,
    caseId: entry.caseId,
    contextSha256: sha256(canonicalBytes(entry.transactionContext)),
    packet,
    proof,
    rawTransactionSha256: sha256(transaction.bytes),
    sources,
    transaction,
    transactionContext: entry.transactionContext,
  });
  assertActionWitnessBinding(
    transaction,
    actionWitness,
    final.topology,
    `Q-02 ${entry.caseId}`,
  );
  validateBaseSources(material, final, context);
  transaction.outputs.forEach((output, index) => {
    const parsed = parseSerializedSourceOutput(output.serializedHex);
    const contextOutput = context.outputs[index];
    if (
      contextOutput.valueSats !== parsed.valueSatoshis
      || !contextOutput.lockingBytecode.equals(parsed.lockingBytecode)
      || !contextOutput.tokenPrefix.equals(
        Buffer.from(parsed.tokenPrefixHex, 'hex'),
      )
    ) {
      fail(`${entry.caseId} output differs from packet context`);
    }
    if (
      index === 0
      && (
        parsed.token?.categoryWire !== final.instanceId
        || parsed.token.amount !== '0'
        || parsed.token.nft?.capability !== 'mutable'
      )
    ) {
      fail(`${entry.caseId} state output category/token is invalid`);
    }
  });
  if (
    entry.kind === 'withdrawal'
    && decodedPacket.withdrawalLockingBytecodeHash !==
      sha256(context.outputs[final.topology.withdrawalOutputIndex].lockingBytecode)
  ) {
    fail(`${entry.caseId} payout lock is not packet-bound`);
  }
  const metadata = reference(
    entry.metadata,
    root,
    `Q-02 ${entry.caseId} signed metadata`,
    { jcs: true },
  );
  const localVmEvidence = reference(
    entry.localVmEvidence,
    root,
    `Q-02 ${entry.caseId} local VM evidence`,
    { jcs: true },
  );
  const inspected = inspectV2LocalVmEvidence(localVmEvidence.bytes);
  const verified = verifyV2SignedSettlementEvidence({
    binding: final.binding,
    localVmEvidence: localVmEvidence.bytes,
    metadata: deepFreeze(metadata.value),
    packet: packet.bytes,
  });
  if (
    inspected.tool.profileId !== final.profileId
    || verified.action !== entry.kind
    || verified.profileId !== final.profileId
    || verified.instanceId !== final.instanceId
    || verified.transactionId !== transaction.txid
    || verified.rawTransactionSha256 !== material.rawTransactionSha256
    || verified.evidenceHash !== inspected.evidenceHash
  ) {
    fail(`${entry.caseId} production settlement evidence is cross-bound incorrectly`);
  }
  const baseBundleSha256 = bundleHash(material);
  const expectedCase = Object.freeze({
    caseId: entry.caseId,
    expectation: 'accept',
    index: entry.index,
    kind: entry.kind,
    localVmEvidenceSha256: localVmEvidence.sha256,
    metadataSha256: metadata.sha256,
    mutation: null,
    packetSha256: packet.sha256,
    proofSha256: proof.sha256,
    rawTransactionSha256: material.rawTransactionSha256,
    transactionId: transaction.txid,
  });
  verifyExternalLanes({
    authorityContext,
    expectedCase,
    lanes: entry.lanes,
    root,
    runIds,
  });
  return Object.freeze({
    ...material,
    baseBundleSha256,
    facts: transactionFacts(transaction, sources),
    index: entry.index,
    kind: entry.kind,
    localVmTool: inspected.tool,
  });
}

function changedIndexes(left, right) {
  if (left.length !== right.length) return null;
  const changed = [];
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) changed.push(index);
  }
  return changed;
}

function isPacketProfileIdIndex(index) {
  const preStart = ACTION_PACKET_OFFSETS.preState + 4;
  const postStart = ACTION_PACKET_OFFSETS.postState + 4;
  return (
    (index >= preStart && index < preStart + 32)
    || (index >= postStart && index < postStart + 32)
  );
}

/*
 * These predicates are deliberately pure audit helpers. They are used by the
 * qualifying verifier below, but expose neither a trust root nor a way to
 * waive any Q-02 gate. Keeping their exact semantics independently testable
 * prevents the mutation matrix from silently collapsing distinct fields.
 */
export function isV2Q02GenericPacketMutation(basePacket, mutantPacket) {
  if (
    !(basePacket instanceof Uint8Array)
    || !(mutantPacket instanceof Uint8Array)
  ) return false;
  const changed = changedIndexes(basePacket, mutantPacket);
  return (
    changed !== null
    && changed.length > 0
    // A generic packet case must be disjoint from the dedicated profile case.
    && changed.every((index) => !isPacketProfileIdIndex(index))
  );
}

export function isV2Q02IsolatedOutpointMutation(baseInputs, mutantInputs) {
  if (
    !Array.isArray(baseInputs)
    || !Array.isArray(mutantInputs)
    || baseInputs.length !== mutantInputs.length
  ) return false;
  const changed = [];
  for (let index = 0; index < baseInputs.length; index += 1) {
    const before = baseInputs[index];
    const after = mutantInputs[index];
    if (
      before === null || typeof before !== 'object'
      || after === null || typeof after !== 'object'
      // A field-labelled outpoint mutation must not smuggle a sequence or
      // source-output change into either the changed or unchanged input.
      || before.sequence !== after.sequence
      || before.sourceOutputSerializedHex !== after.sourceOutputSerializedHex
      || !same(before.sourceOutput, after.sourceOutput)
    ) return false;
    if (!same(before.outpoint, after.outpoint)) changed.push(index);
    if (
      same(before.outpoint, after.outpoint)
      && before.sourceTransactionSha256 !== after.sourceTransactionSha256
    ) return false;
  }
  return changed.length === 1;
}

function changedOutputIndexes(left, right) {
  if (left.length !== right.length) return null;
  const changed = [];
  for (let index = 0; index < left.length; index += 1) {
    if (!same(left[index], right[index])) changed.push(index);
  }
  return changed;
}

function unlocksDiffer(base, mutant) {
  return base.inputs.some(
    (entry, index) =>
      entry.unlockingBytecodeSha256 !==
      mutant.inputs[index]?.unlockingBytecodeSha256,
  );
}

function assertEqual(value, label) {
  if (!value) fail(`Q-02 mutation shape mismatch: ${label}`);
}

function assertSingleOutputMutation(
  base,
  mutant,
  index,
  label,
  predicate,
) {
  const changed = changedOutputIndexes(base.outputs, mutant.outputs);
  assertEqual(
    changed !== null && changed.length === 1 && changed[0] === index,
    `${label} must alter only output ${index}`,
  );
  assertEqual(
    predicate(base.outputs[index], mutant.outputs[index]),
    `${label} output delta is not the required semantic field`,
  );
}

function assertMutationShape(field, base, mutant, topology) {
  const baseFacts = base.facts;
  const mutantFacts = mutant.facts;
  assertEqual(
    base.rawTransactionSha256 !== mutant.rawTransactionSha256,
    'mutant raw transaction must differ',
  );
  assertEqual(
    same(base.transactionContext, mutant.transactionContext),
    'transaction context is not a mutation-matrix field',
  );
  const sameProof = base.proof.sha256 === mutant.proof.sha256;
  const samePacket = base.packet.sha256 === mutant.packet.sha256;
  const sameSources = base.sources.length === mutant.sources.length
    && base.sources.every(
      (entry, index) =>
        entry.artifact.sha256 === mutant.sources[index].artifact.sha256,
    );
  const sameSkeleton = same(
    withoutUnlocks(baseFacts),
    withoutUnlocks(mutantFacts),
  );
  if (field === 'proof') {
    assertEqual(!sameProof && samePacket && sameSources && sameSkeleton,
      'proof mutation changed non-proof semantics');
    assertEqual(unlocksDiffer(baseFacts, mutantFacts),
      'proof mutation is not embedded in an unlocking bytecode');
    return;
  }
  if (field === 'packet') {
    assertEqual(sameProof && !samePacket && sameSources && sameSkeleton,
      'packet mutation changed non-packet semantics');
    assertEqual(
      isV2Q02GenericPacketMutation(base.packet.bytes, mutant.packet.bytes),
      'packet mutation must alter only bytes outside pre/post SKS2 profileId regions',
    );
    assertEqual(unlocksDiffer(baseFacts, mutantFacts),
      'packet mutation is not embedded in an unlocking bytecode');
    return;
  }
  if (field === 'profile') {
    assertEqual(sameProof && !samePacket && sameSources && sameSkeleton,
      'profile mutation changed non-packet semantics');
    const changed = changedIndexes(base.packet.bytes, mutant.packet.bytes);
    const preStart = ACTION_PACKET_OFFSETS.preState + 4;
    const postStart = ACTION_PACKET_OFFSETS.postState + 4;
    assertEqual(
      changed !== null
      && changed.length > 0
      && changed.every(
        (index) =>
          (
            index >= preStart
            && index < preStart + 32
          )
          || (
            index >= postStart
            && index < postStart + 32
          ),
      ),
      'profile mutation must alter only pre/post SKS2 profileId bytes',
    );
    const preChanges = changed.filter(
      (index) => index >= preStart && index < preStart + 32,
    );
    assertEqual(
      preChanges.length > 0
      && preChanges.every((index) => {
        const post = postStart + (index - preStart);
        return (
          changed.includes(post)
          && mutant.packet.bytes[index] === mutant.packet.bytes[post]
        );
      }),
      'profile mutation must change matching pre/post profile bytes',
    );
    return;
  }
  assertEqual(
    sameProof && samePacket,
    `${field} mutation may not substitute proof or packet artifacts`,
  );
  if (field === 'state') {
    assertEqual(sameSources, 'state mutation may not replace source history');
    assertSingleOutputMutation(
      baseFacts,
      mutantFacts,
      0,
      'state mutation',
      (before, after) =>
        before.valueSatoshis === after.valueSatoshis
        && before.lockingBytecodeHex === after.lockingBytecodeHex
        && before.token?.categoryWire === after.token?.categoryWire
        && before.token?.amount === after.token?.amount
        && before.token?.nft?.capability === after.token?.nft?.capability
        && before.token?.nft?.commitmentHex !==
          after.token?.nft?.commitmentHex,
    );
    return;
  }
  if (field === 'category') {
    assertEqual(sameSources, 'category mutation may not replace source history');
    assertSingleOutputMutation(
      baseFacts,
      mutantFacts,
      0,
      'category mutation',
      (before, after) =>
        before.valueSatoshis === after.valueSatoshis
        && before.lockingBytecodeHex === after.lockingBytecodeHex
        && before.token?.categoryWire !== after.token?.categoryWire
        && before.token?.amount === after.token?.amount
        && before.token?.nft?.capability === after.token?.nft?.capability
        && before.token?.nft?.commitmentHex ===
          after.token?.nft?.commitmentHex,
    );
    return;
  }
  if (field === 'carrier') {
    assertEqual(sameSources, 'carrier mutation may not replace source history');
    const changed = changedOutputIndexes(baseFacts.outputs, mutantFacts.outputs);
    assertEqual(
      changed !== null
      && changed.length === 1
      && changed[0] >= 1
      && changed[0] <= topology.carrierCount,
      'carrier mutation must target exactly one verifier successor',
    );
    const before = baseFacts.outputs[changed[0]];
    const after = mutantFacts.outputs[changed[0]];
    assertEqual(
      before.valueSatoshis === after.valueSatoshis
      && same(before.token, after.token)
      && before.lockingBytecodeHex !== after.lockingBytecodeHex,
      'carrier mutation must change only its locking bytecode',
    );
    return;
  }
  if (field === 'token') {
    assertEqual(sameSources, 'token mutation may not replace source history');
    assertSingleOutputMutation(
      baseFacts,
      mutantFacts,
      0,
      'token mutation',
      (before, after) =>
        before.valueSatoshis === after.valueSatoshis
        && before.lockingBytecodeHex === after.lockingBytecodeHex
        && before.token?.categoryWire === after.token?.categoryWire
        && before.token?.nft?.commitmentHex ===
          after.token?.nft?.commitmentHex
        && (
          before.token?.amount !== after.token?.amount
          || before.token?.nft?.capability !== after.token?.nft?.capability
        ),
    );
    return;
  }
  if (field === 'value') {
    assertEqual(sameSources, 'value mutation may not replace source history');
    const changed = changedOutputIndexes(baseFacts.outputs, mutantFacts.outputs);
    assertEqual(
      changed !== null
      && changed.length === 1
      && changed[0] <= topology.bindingOutputIndex,
      'value mutation must target one rolling/state/binding output',
    );
    const before = baseFacts.outputs[changed[0]];
    const after = mutantFacts.outputs[changed[0]];
    assertEqual(
      before.valueSatoshis !== after.valueSatoshis
      && before.lockingBytecodeHex === after.lockingBytecodeHex
      && same(before.token, after.token),
      'value mutation changed more than a value',
    );
    return;
  }
  if (field === 'role') {
    assertEqual(
      baseFacts.outputs.length === mutantFacts.outputs.length
      && same(baseFacts.outputs, mutantFacts.outputs),
      'role mutation may not alter outputs',
    );
    const baseIds = baseFacts.inputs.map((entry) =>
      `${entry.outpoint.txid}:${entry.outpoint.vout}`).sort();
    const mutantIds = mutantFacts.inputs.map((entry) =>
      `${entry.outpoint.txid}:${entry.outpoint.vout}`).sort();
    assertEqual(
      same(baseIds, mutantIds)
      && !same(
        baseFacts.inputs.map((entry) => entry.outpoint),
        mutantFacts.inputs.map((entry) => entry.outpoint),
      ),
      'role mutation must be a nonidentity input permutation',
    );
    return;
  }
  if (field === 'outpoint') {
    assertEqual(
      same(baseFacts.outputs, mutantFacts.outputs),
      'outpoint mutation may not alter outputs',
    );
    assertEqual(
      isV2Q02IsolatedOutpointMutation(
        baseFacts.inputs,
        mutantFacts.inputs,
      ),
      'outpoint mutation must replace exactly one outpoint while preserving every input sequence and serialized source output',
    );
    return;
  }
  if (field === 'fee') {
    assertEqual(
      same(baseFacts.outputs, mutantFacts.outputs),
      'fee mutation may not alter outputs',
    );
    const index = topology.fundingInputIndex;
    assertEqual(
      baseFacts.inputs.length === mutantFacts.inputs.length
      && baseFacts.inputs.every((entry, inputIndex) =>
        inputIndex === index
          || same(entry, mutantFacts.inputs[inputIndex]))
      && baseFacts.inputs[index].sourceOutput.valueSatoshis !==
        mutantFacts.inputs[index].sourceOutput.valueSatoshis,
      'fee mutation must alter only the funding source amount/outpoint',
    );
    return;
  }
  if (field === 'change') {
    assertEqual(sameSources, 'change mutation may not replace source history');
    const index = base.kind === 'withdrawal'
      ? topology.changeOutputIndex
      : topology.changeOutputIndex - 1;
    assertSingleOutputMutation(
      baseFacts,
      mutantFacts,
      index,
      'change mutation',
      (before, after) =>
        same(before.token, after.token)
        && (
          before.valueSatoshis !== after.valueSatoshis
          || before.lockingBytecodeHex !== after.lockingBytecodeHex
        ),
    );
    return;
  }
  if (field === 'payout') {
    assertEqual(sameSources, 'payout mutation may not replace source history');
    if (base.kind === 'withdrawal') {
      assertSingleOutputMutation(
        baseFacts,
        mutantFacts,
        topology.withdrawalOutputIndex,
        'payout mutation',
        (before, after) =>
          same(before.token, after.token)
          && (
            before.valueSatoshis !== after.valueSatoshis
            || before.lockingBytecodeHex !== after.lockingBytecodeHex
          ),
      );
    } else {
      assertEqual(
        mutantFacts.outputs.length === baseFacts.outputs.length + 1
        && same(
          mutantFacts.outputs.slice(0, baseFacts.outputs.length),
          baseFacts.outputs,
        )
        && mutantFacts.outputs.at(-1).token === null,
        'non-withdrawal payout mutation must append one tokenless payout',
      );
    }
    return;
  }
  fail(`unsupported Q-02 mutation field ${field}`);
}

function rejectedByFreshLibauth(material, base, final) {
  const attempt = Object.freeze({
    carrierCount: final.topology.carrierCount,
    inputs: Object.freeze(material.sources.map((entry) =>
      Object.freeze({
        sourceTransactionHex: entry.artifact.bytes.toString('hex'),
      }))),
    instanceId: final.instanceId,
    rawTransactionHex: material.transaction.rawTransactionHex,
    tool: base.localVmTool,
  });
  let error;
  try {
    createV2LocalVmEvidence(attempt);
  } catch (caught) {
    error = caught;
  }
  if (error === undefined) {
    fail('Q-02 mutation was accepted by a fresh installed Libauth evaluation');
  }
  if (
    typeof error !== 'object'
    || error === null
    || ![
      'V2VmEvidenceError',
      'V2TransactionPolicyError',
      'DirectV2TopologyError',
    ].includes(error.name)
  ) {
    fail(`Q-02 local rejection did not come from a protocol/VM evaluator: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (
    [
      'UNSUPPORTED_VM_TOOL',
      'INVALID_VM_EVIDENCE',
      'VM_METRICS_UNAVAILABLE',
    ].includes(error.code)
  ) {
    fail(`Q-02 local rejection is an evidence/tool failure, not a mutant rejection: ${error.code}`);
  }
  return Object.freeze({
    attemptSha256: sha256(canonicalBytes(attempt)),
    code: typeof error.code === 'string' ? error.code : error.name,
  });
}

function mutationMaterial(entry, root, base, final) {
  exact(entry.candidate, [
    'packet',
    'proof',
    'rawTransactionHex',
    'sourceTransactions',
    'transactionContext',
  ], 'Q-02 mutation candidate');
  const proof = reference(
    entry.candidate.proof,
    root,
    `Q-02 ${entry.caseId}/${entry.field} proof`,
    { jcs: true },
  );
  const packet = reference(
    entry.candidate.packet,
    root,
    `Q-02 ${entry.caseId}/${entry.field} packet`,
  );
  if (packet.bytes.length !== 552) {
    fail('Q-02 mutation packet must remain exactly 552 bytes');
  }
  let transaction;
  try {
    transaction = parseV2RawTransaction(entry.candidate.rawTransactionHex);
  } catch (error) {
    fail(`Q-02 mutation raw transaction must remain structurally parseable: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  if (transaction.inputs.length !== final.topology.inputCount) {
    fail('Q-02 mutation must retain the selected input count');
  }
  const sources = sourceTransactions(
    entry.candidate.sourceTransactions,
    root,
    transaction,
    `Q-02 ${entry.caseId}/${entry.field}`,
  );
  const material = Object.freeze({
    caseId: entry.caseId,
    contextSha256: sha256(canonicalBytes(entry.candidate.transactionContext)),
    facts: transactionFacts(transaction, sources),
    kind: base.kind,
    packet,
    proof,
    rawTransactionSha256: sha256(transaction.bytes),
    sources,
    transaction,
    transactionContext: entry.candidate.transactionContext,
  });
  return Object.freeze({
    ...material,
    mutantBundleSha256: bundleHash(material),
  });
}

async function assertMutantWitnessBinding(field, mutant, base, final) {
  assertPacketBinding(
    mutant.transaction,
    mutant.packet.bytes,
    final,
    `Q-02 ${mutant.caseId}/${field}`,
  );
  let witness = base.actionWitness;
  if (field === 'proof') {
    let verified = false;
    try {
      verified = await final.snarkjs.groth16.verify(
        final.verificationKey,
        mutant.proof.value.publicInputs,
        mutant.proof.value.proof,
      );
    } catch {
      verified = false;
    }
    if (verified) {
      fail('Q-02 proof mutation is another valid final-key proof');
    }
    try {
      witness = buildDirectV2Pf10ActionWitness({
        actionPacket: mutant.packet.bytes,
        denominationSats: final.denominationSats,
        proofResult: mutant.proof.value,
        runtimeMaterial: final.runtimeMaterial,
      });
    } catch (error) {
      fail(
        `Q-02 proof mutation is not a well-formed proof-derived PF10 witness: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  const expectedWitness =
    field === 'packet' || field === 'profile'
      ? Object.freeze({
        ...witness,
        bindingUnlockingBytecode:
          mutant.transaction.inputs[final.topology.bindingInputIndex]
            .unlockingBytecode,
      })
      : witness;
  assertActionWitnessBinding(
    mutant.transaction,
    expectedWitness,
    final.topology,
    `Q-02 ${mutant.caseId}/${field}`,
  );
}

async function validateMutations(
  entries,
  root,
  bases,
  final,
  authorityContext,
  runIds,
) {
  const expectedCount = 256 * KINDS.length * MUTATIONS.length;
  if (!Array.isArray(entries) || entries.length !== expectedCount) {
    fail(`Q-02 requires exactly ${expectedCount} typed mutation cases`);
  }
  const seen = new Set();
  const mutantTransactions = new Set();
  for (const entry of entries) {
    exact(entry, [
      'baseBundleSha256',
      'candidate',
      'caseId',
      'field',
      'lanes',
      'mutantBundleSha256',
    ], 'Q-02 mutation');
    const base = bases.get(entry.caseId);
    if (
      base === undefined
      || !MUTATIONS.includes(entry.field)
      || entry.baseBundleSha256 !== base.baseBundleSha256
    ) {
      fail('Q-02 mutation identity or base-bundle binding is invalid');
    }
    const identity = `${entry.caseId}:${entry.field}`;
    if (seen.has(identity)) fail('Q-02 mutation is duplicated');
    seen.add(identity);
    const mutant = mutationMaterial(entry, root, base, final);
    if (
      entry.mutantBundleSha256 !== mutant.mutantBundleSha256
      || entry.mutantBundleSha256 === entry.baseBundleSha256
      || mutantTransactions.has(mutant.transaction.txid)
    ) {
      fail('Q-02 mutant bundle hash or transaction identity is invalid');
    }
    mutantTransactions.add(mutant.transaction.txid);
    assertMutationShape(entry.field, base, mutant, final.topology);
    await assertMutantWitnessBinding(entry.field, mutant, base, final);
    const local = rejectedByFreshLibauth(mutant, base, final);
    const mutationBinding = Object.freeze({
      baseBundleSha256: entry.baseBundleSha256,
      field: entry.field,
      mutantBundleSha256: entry.mutantBundleSha256,
    });
    const expectedCase = Object.freeze({
      caseId: entry.caseId,
      expectation: 'reject',
      index: base.index,
      kind: base.kind,
      localVmEvidenceSha256: local.attemptSha256,
      metadataSha256: sha256(canonicalBytes({
        localRejectionCode: local.code,
        mutation: mutationBinding,
      })),
      mutation: mutationBinding,
      packetSha256: mutant.packet.sha256,
      proofSha256: mutant.proof.sha256,
      rawTransactionSha256: mutant.rawTransactionSha256,
      transactionId: mutant.transaction.txid,
    });
    verifyExternalLanes({
      authorityContext,
      expectedCase,
      lanes: entry.lanes,
      root,
      runIds,
    });
  }
}

export async function verifyV2Q02FinalKeyCorpus(options, dependencies = {}) {
  if (
    dependencies !== undefined
    && (
      dependencies === null
      || typeof dependencies !== 'object'
      || Object.keys(dependencies).length !== 0
    )
  ) {
    fail('Q-02 qualification refuses injected test doubles');
  }
  exact(options, [
    'corpusPath',
    'descriptorPath',
    'profileCorePath',
    'releaseRootId',
  ], 'Q-02 verifier options');
  // Resolve the compiled bootstrap before opening caller-provided descriptor,
  // profile, or corpus paths. A descriptor may never nominate its own root.
  const releaseRoot = resolveV2FinalReleaseRoot(options.releaseRootId);
  const profileCoreFile = jcsFile(
    options.profileCorePath,
    'Q-02 profile core',
  );
  const profileCore = profileCoreFile.value;
  const release = verifyV2FinalReleaseProfileCore(
    releaseRoot,
    profileCoreFile.bytes,
    profileCore,
  );
  const descriptor = await loadV2InstanceDescriptor({
    descriptorPath: options.descriptorPath,
    profileCore,
    trustedSigners: release.descriptorSigners,
  });
  if (
    descriptor.profileId !== releaseRoot.profileId
    || descriptor.finalLocks.topology.id !== releaseRoot.topology.id
    || descriptor.finalLocks.verifiers.length
      !== releaseRoot.topology.verifierRoles.length
    || descriptor.finalLocks.verifiers.some(
      (entry, index) => entry.role !== releaseRoot.topology.verifierRoles[index],
    )
  ) {
    fail('Q-02 descriptor identity or PF10 topology differs from its approved release root');
  }
  const runtime = await deriveV2Pf10RuntimeFromValidatedDescriptor(descriptor);
  if (
    runtime.eligibility !== 'final-qualified'
    || runtime.claims?.finalKey !== true
    || runtime.claims.developmentKey !== false
    || runtime.claims.ceremonyQualified !== true
    || runtime.claims.production !== false
    || runtime.claims.releaseQualified !== false
  ) {
    fail(
      'Q-02 requires a D-01-qualified final key without a premature production or release claim',
    );
  }
  const authorityContext =
    deriveV2Q02LaneAuthorityContextFromValidatedDescriptor(descriptor);
  const corpus = jcsFile(options.corpusPath, 'Q-02 corpus');
  const root = dirname(corpus.path);
  exact(corpus.value, [
    'descriptorSha256',
    'manifestSha256',
    'mutations',
    'schema',
    'transactions',
  ], 'Q-02 corpus');
  if (
    corpus.value.schema !== V2_Q02_CORPUS_SCHEMA
    || corpus.value.descriptorSha256 !== descriptor.descriptor.sha256
    || corpus.value.manifestSha256 !== descriptor.manifest.sha256
    || !Array.isArray(corpus.value.transactions)
    || corpus.value.transactions.length !== 768
  ) {
    fail('Q-02 corpus pins or base-case count are invalid');
  }
  const topology = resolveDirectV2VerifierTopology({
    id: descriptor.finalLocks.topology.id,
    verifierRoles: descriptor.finalLocks.verifiers.map((entry) => entry.role),
  });
  let verificationKey;
  try {
    verificationKey = JSON.parse(
      stableFile(
        runtime.proofArtifacts.verificationKey.path,
        'Q-02 final verification key',
      ),
    );
  } catch (error) {
    fail(`Q-02 final verification key is unreadable JSON: ${
      error instanceof Error ? error.message : String(error)
    }`);
  }
  let snarkjs;
  try {
    snarkjs = await import('snarkjs');
  } catch {
    fail('Q-02 final Groth16 verifier dependency is unavailable');
  }
  const binding = Object.freeze({
    carrierCount: topology.carrierCount,
    denominationSats: profileCore.denominationSats,
    instanceId: Buffer.from(descriptor.instanceId, 'hex'),
    networkId: profileCore.network.id,
    profileId: Buffer.from(descriptor.profileId, 'hex'),
    runtimeMaterialsSha256:
      deriveV2Pf10StoreRuntimeMaterialsSha256(runtime),
  });
  const final = Object.freeze({
    binding,
    bindingLock: descriptor.artifacts.get(
      descriptor.finalLocks.binding.lockingArtifactId,
    ).data,
    denominationSats: profileCore.denominationSats,
    instanceId: descriptor.instanceId,
    profileId: descriptor.profileId,
    runtimeMaterial: runtime.runtimeMaterial,
    snarkjs,
    stateLock: descriptor.artifacts.get(
      descriptor.finalLocks.state.lockingArtifactId,
    ).data,
    topology,
    verificationKey,
    verifierLocks: descriptor.finalLocks.verifiers.map((entry) =>
      descriptor.artifacts.get(entry.lockingArtifactId).data),
  });
  const runIds = new Set();
  const baseResults = [];
  for (const entry of corpus.value.transactions) {
    baseResults.push(
      await validateBaseCase(
        entry,
        root,
        final,
        authorityContext,
        runIds,
      ),
    );
  }
  const globalIdentities = new Set();
  for (const result of baseResults) {
    for (const identity of [
      result.proof.sha256,
      result.packet.sha256,
      result.transaction.txid,
    ]) {
      if (globalIdentities.has(identity)) {
        fail('Q-02 base proof, packet, and transaction identities must be globally unique');
      }
      globalIdentities.add(identity);
    }
  }
  const bases = new Map(baseResults.map((entry) => [entry.caseId, entry]));
  if (bases.size !== 768) fail('Q-02 base case IDs are not unique');
  await validateMutations(
    corpus.value.mutations,
    root,
    bases,
    final,
    authorityContext,
    runIds,
  );
  return Object.freeze({
    cases: 768,
    descriptorSha256: descriptor.descriptor.sha256,
    externalLaneRuns: runIds.size,
    manifestSha256: descriptor.manifest.sha256,
    mutations: 9_984,
    q02Qualified: true,
    releaseBootstrapSha256: release.releaseBootstrapSha256,
    releaseRootId: release.releaseRootId,
    schema: V2_Q02_CORPUS_SCHEMA,
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    process.stdout.write(`${JSON.stringify(
      await verifyV2Q02FinalKeyCorpus(
        parseV2Q02Arguments(process.argv.slice(2)),
      ),
      null,
      2,
    )}\n`);
  } catch (error) {
    process.stderr.write(
      `Q-02 final-key corpus gate failed: ${
        error instanceof Error ? error.message : String(error)
      }\n`,
    );
    process.exitCode = 1;
  }
}
