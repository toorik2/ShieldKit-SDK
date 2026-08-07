import { createHash } from 'node:crypto';

import { assertV2DeliveryJournal } from './delivery-journal.mjs';
import {
  assertV2SecureEndpoint as assertSecureEndpoint,
  assertV2Transport,
} from './https-transport.mjs';
import {
  assertV2StandardTransactionEnvelope,
  createV2InputRoleLayout,
  parseSerializedSourceOutput,
  parseV2RawTransaction as parseRawTransaction,
} from './transaction-policy.mjs';
import {
  canonicalizeV2Evidence,
  inspectV2LocalVmEvidence,
} from './vm-evidence.mjs';
import {
  decodeActionPacket,
} from '../../action/v2/packet.mjs';
import {
  encodeStateNftCommitment,
} from '../../action/v2/state.mjs';
import {
  hashDirectV2TransactionContext,
} from '../../action/v2/context.mjs';
import {
  directV2NetworkIdFromName,
} from '../../action/v2/network.mjs';
import {
  validateDirectV2RollingBundle,
} from '../../action/v2/rolling-bundle.mjs';
import {
  decodeDirectV2BindingUnlock,
} from '../../action/v2/binding-unlock.mjs';

const METADATA_SCHEMA = 'shieldkit/v2-signed-broadcast-metadata/v3';
const HIGH_FEE_SCHEMA = 'shieldkit/v2-high-fee-confirmation/v1';
const MEMPOOL_OVERLAY_SCHEMA = 'shieldkit/v2-mempool-overlay/v1';
export const V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT =
  'resubmit-exact-persisted-transaction';
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ACTIONS = new Set(['deposit', 'transfer', 'withdrawal']);
const TLS_RANK = Object.freeze({ 'TLSv1.2': 2, 'TLSv1.3': 3 });

export class V2NetworkGateError extends Error {
  constructor(code, message, { recoverable = false } = {}) {
    super(message);
    this.name = 'V2NetworkGateError';
    this.code = code;
    this.recoverable = recoverable;
  }
}

const fail = (code, message, options) => {
  throw new V2NetworkGateError(code, message, options);
};

function plain(value, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_METADATA', `${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(
      'INVALID_METADATA',
      `${label} has missing or unknown fields`,
    );
  }
  return value;
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'INVALID_METADATA',
      `${label} must be lowercase 32-byte hex`,
    );
  }
  return value;
}

function displayTxidToWire(value, label) {
  return Buffer.from(hex32(value, label), 'hex').reverse().toString('hex');
}

function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail('INVALID_METADATA', `${label} is outside its integer range`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function deeplyFrozen(value) {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    Object.isFrozen(value) &&
    Object.values(value).every(
      (child) =>
        !(child && typeof child === 'object') || deeplyFrozen(child),
    )
  );
}

function equal(left, right) {
  return (
    left instanceof Uint8Array &&
    right instanceof Uint8Array &&
    Buffer.from(left).equals(Buffer.from(right))
  );
}

function canonical(value) {
  return canonicalizeV2Evidence(value);
}

function metadataDigest(value) {
  return createHash('sha256').update(canonical(value)).digest('hex');
}

function rawTransactionSha256(rawTransactionHex) {
  return createHash('sha256')
    .update(Buffer.from(rawTransactionHex, 'hex'))
    .digest('hex');
}

function asGateError(error, fallbackCode) {
  if (error instanceof V2NetworkGateError) throw error;
  fail(
    typeof error?.code === 'string' ? error.code : fallbackCode,
    error instanceof Error ? error.message : String(error),
  );
}

export function parseV2RawTransaction(
  rawTransactionHex,
  { carrierCount = undefined } = {},
) {
  try {
    return assertV2StandardTransactionEnvelope(
      parseRawTransaction(rawTransactionHex),
      { carrierCount },
    );
  } catch (error) {
    asGateError(error, 'MALFORMED_TRANSACTION');
  }
}

function inspectEvidence(bytes) {
  try {
    return inspectV2LocalVmEvidence(bytes);
  } catch (error) {
    asGateError(error, 'INVALID_VM_EVIDENCE');
  }
}

function tip(value) {
  exact(
    value,
    ['actionSequence', 'blockHash', 'height', 'state', 'txid', 'vout'],
    'tip',
  );
  if (
    typeof value.state !== 'string' ||
    !/^[0-9a-f]{256}$/.test(value.state)
  ) {
    fail(
      'INVALID_METADATA',
      'tip.state must be lowercase 128-byte hex',
    );
  }
  return Object.freeze({
    state: value.state,
    txid: hex32(value.txid, 'tip.txid'),
    vout: integer(value.vout, 0, 0xffff_ffff, 'tip.vout'),
    actionSequence: integer(
      value.actionSequence,
      0,
      Number.MAX_SAFE_INTEGER,
      'tip.actionSequence',
    ),
    height: integer(
      value.height,
      0,
      Number.MAX_SAFE_INTEGER,
      'tip.height',
    ),
    blockHash: hex32(value.blockHash, 'tip.blockHash'),
  });
}

function vmTool(value) {
  exact(
    value,
    ['name', 'profileSha256', 'version', 'vm'],
    'VM tool metadata',
  );
  if (
    value.name !== '@bitauth/libauth' ||
    value.vm !== 'BCH_2026_STANDARD' ||
    typeof value.version !== 'string' ||
    !/^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(
      value.version,
    )
  ) {
    fail(
      'INVALID_METADATA',
      'VM tool metadata does not identify the required evaluator',
    );
  }
  return Object.freeze({
    name: value.name,
    version: value.version,
    vm: value.vm,
    profileSha256: hex32(
      value.profileSha256,
      'VM tool profileSha256',
    ),
  });
}

function normalizeRole(value, expected, label) {
  exact(value, ['index', 'kind', 'ordinal'], label);
  if (
    value.index !== expected.index ||
    value.kind !== expected.kind ||
    value.ordinal !== expected.ordinal
  ) {
    fail(
      'INPUT_ROLE_LAYOUT_MISMATCH',
      `${label} does not match the carrier-count-derived role`,
    );
  }
  return expected;
}

function inputRoleLayout(value, carrierCount) {
  const expected = createV2InputRoleLayout(carrierCount);
  if (!Array.isArray(value) || value.length !== expected.length) {
    fail(
      'INPUT_ROLE_LAYOUT_MISMATCH',
      'inputRoleLayout length does not match carrierCount',
    );
  }
  return Object.freeze(
    value.map((role, index) =>
      normalizeRole(
        role,
        expected[index],
        `inputRoleLayout[${index}]`,
      ),
    ),
  );
}

function inputSourceOutputHashes(value, expectedInputCount) {
  if (
    !Array.isArray(value) ||
    value.length !== expectedInputCount
  ) {
    fail(
      'INVALID_METADATA',
      `inputSourceOutputHashes must bind exactly ${expectedInputCount} source outputs`,
    );
  }
  return Object.freeze(
    value.map((entry, index) =>
      hex32(entry, `inputSourceOutputHashes[${index}]`),
    ),
  );
}

function normalizeMetadata(value, { allowHash }) {
  const fields = [
    'action',
    'carrierCount',
    'feeSats',
    'inputRoleLayout',
    'inputRoleLayoutHash',
    'inputSourceOutputHashes',
    'instanceId',
    'network',
    'operationId',
    'profileId',
    'rawTxHex',
    'schema',
    'sizeBytes',
    'tip',
    'txid',
    'vmEvidenceHash',
    'vmTool',
  ];
  exact(
    value,
    allowHash ? [...fields, 'metadataHash'] : fields,
    'signed broadcast metadata',
  );
  if (value.schema !== METADATA_SCHEMA) {
    fail(
      'INVALID_METADATA',
      'signed broadcast metadata schema is unsupported',
    );
  }
  if (
    typeof value.operationId !== 'string' ||
    !OPERATION_ID.test(value.operationId)
  ) {
    fail('INVALID_METADATA', 'operationId is invalid');
  }
  if (
    !ACTIONS.has(value.action) ||
    !['mainnet', 'chipnet'].includes(value.network)
  ) {
    fail('INVALID_METADATA', 'action or network is unsupported');
  }
  const carrierCount = integer(
    value.carrierCount,
    1,
    255,
    'carrierCount',
  );
  const roleLayout = inputRoleLayout(
    value.inputRoleLayout,
    carrierCount,
  );
  const roleLayoutHash = metadataDigest(roleLayout);
  if (
    hex32(value.inputRoleLayoutHash, 'inputRoleLayoutHash') !==
    roleLayoutHash
  ) {
    fail(
      'INPUT_ROLE_LAYOUT_MISMATCH',
      'inputRoleLayoutHash does not bind the exact ordered role layout',
    );
  }
  const transaction = parseV2RawTransaction(value.rawTxHex, {
    carrierCount,
  });
  const feeSats =
    typeof value.feeSats === 'string' && DECIMAL.test(value.feeSats)
      ? BigInt(value.feeSats)
      : fail(
          'INVALID_METADATA',
          'feeSats must be a canonical unsigned decimal string',
        );
  const normalized = Object.freeze({
    schema: METADATA_SCHEMA,
    carrierCount,
    inputRoleLayout: roleLayout,
    inputRoleLayoutHash: roleLayoutHash,
    operationId: value.operationId,
    rawTxHex: transaction.rawTransactionHex,
    txid: hex32(value.txid, 'txid'),
    sizeBytes: integer(
      value.sizeBytes,
      1,
      100_000,
      'sizeBytes',
    ),
    feeSats: feeSats.toString(),
    action: value.action,
    profileId: hex32(value.profileId, 'profileId'),
    instanceId: hex32(value.instanceId, 'instanceId'),
    network: value.network,
    tip: tip(value.tip),
    vmEvidenceHash: hex32(
      value.vmEvidenceHash,
      'vmEvidenceHash',
    ),
    inputSourceOutputHashes: inputSourceOutputHashes(
      value.inputSourceOutputHashes,
      roleLayout.length,
    ),
    vmTool: vmTool(value.vmTool),
  });
  if (
    normalized.txid !== transaction.txid ||
    normalized.sizeBytes !== transaction.sizeBytes
  ) {
    fail(
      'TRANSACTION_MUTATED',
      'serialized transaction hash or size differs from signed metadata',
    );
  }
  if (
    allowHash &&
    (typeof value.metadataHash !== 'string' ||
      value.metadataHash !== metadataDigest(normalized))
  ) {
    fail(
      'METADATA_HASH_MISMATCH',
      'signed metadata commitment is invalid',
    );
  }
  return normalized;
}

function actualFee({ transaction, evidence }) {
  const inputValue = evidence.inputs.reduce(
    (sum, input) => sum + BigInt(input.sourceOutput.valueSatoshis),
    0n,
  );
  const outputValue = transaction.outputs.reduce(
    (sum, output) => sum + output.valueSatoshis,
    0n,
  );
  if (inputValue < outputValue) {
    fail(
      'INVALID_TRANSACTION_FEE',
      'serialized outputs exceed the evaluated source-output values',
    );
  }
  return inputValue - outputValue;
}

function assertRollingSourceLineage({ signed, evidence }) {
  const count = signed.carrierCount;
  const parentTxid = signed.tip.txid;
  for (let ordinal = 0; ordinal < count; ordinal += 1) {
    const outpoint = evidence.inputs[ordinal].outpoint;
    if (
      outpoint.txid !== parentTxid ||
      outpoint.vout !== ordinal + 1
    ) {
      fail(
        'ROLLING_PARENT_MISMATCH',
        `verifier input ${ordinal} is not exact output ${ordinal + 1} of the durable state parent`,
      );
    }
  }
  const binding = evidence.inputs[count].outpoint;
  if (
    binding.txid !== parentTxid ||
    binding.vout !== count + 1
  ) {
    fail(
      'ROLLING_PARENT_MISMATCH',
      'binding input is not the exact previous rolling-bundle output',
    );
  }
  const stateInput = evidence.inputs[count + 1];
  if (
    signed.tip.vout !== 0 ||
    stateInput.outpoint.txid !== parentTxid ||
    stateInput.outpoint.vout !== signed.tip.vout
  ) {
    fail(
      'ROLLING_PARENT_MISMATCH',
      'state input is not exact output 0 of the durable state parent',
    );
  }
  if (
    stateInput.sourceOutput.token?.nft?.commitmentHex !== signed.tip.state
  ) {
    fail(
      'STATE_COMMITMENT_MISMATCH',
      'state input NFT commitment differs from the durable canonical state',
    );
  }
}

const bundleRole = (role) => Object.freeze({
  kind: role.kind,
  ordinal: String(role.ordinal ?? 0),
});

function bundleToken(token) {
  if (token === null) return null;
  if (token.nft === null) {
    fail(
      'ROLLING_BUNDLE_INVALID',
      'V2 rolling bundle roles may not carry fungible-only tokens',
    );
  }
  return Object.freeze({
    category: token.categoryWire,
    amount: token.amount,
    nft: Object.freeze({
      capability: token.nft.capability,
      commitment: Buffer.from(token.nft.commitmentHex, 'hex'),
    }),
  });
}

function bundleInputRecord(input, transactionInput) {
  return Object.freeze({
    role: bundleRole(input.role),
    outpointTransactionHash: displayTxidToWire(
      input.outpoint.txid,
      'input outpoint txid',
    ),
    outpointIndex: String(input.outpoint.vout),
    sequence: String(transactionInput.sequence),
    valueSats: input.sourceOutput.valueSatoshis,
    lockingBytecode: Buffer.from(
      input.sourceOutput.lockingBytecodeHex,
      'hex',
    ),
    token: bundleToken(input.sourceOutput.token),
  });
}

function outputRole(index, carrierCount, action) {
  if (index === 0) return bundleRole({ kind: 'state', ordinal: null });
  if (index <= carrierCount) {
    return bundleRole({ kind: 'verifier', ordinal: index - 1 });
  }
  if (index === carrierCount + 1) {
    return bundleRole({ kind: 'binding', ordinal: null });
  }
  if (action === 'withdrawal' && index === carrierCount + 2) {
    return bundleRole({ kind: 'withdrawal', ordinal: null });
  }
  return bundleRole({ kind: 'change', ordinal: null });
}

function bundleOutputRecord(
  transactionOutput,
  index,
  carrierCount,
  action,
) {
  const parsed = parseSerializedSourceOutput(
    transactionOutput.serializedHex,
  );
  return Object.freeze({
    role: outputRole(index, carrierCount, action),
    valueSats: parsed.valueSatoshis.toString(),
    lockingBytecode: Buffer.from(parsed.lockingBytecode),
    token: bundleToken(parsed.token),
  });
}

function decodePersistedPacket(operation, binding) {
  if (
    !(operation.packet instanceof Uint8Array) ||
    operation.packet.length !== 552
  ) {
    fail(
      'ACTION_PACKET_REQUIRED',
      'signed operation must durably retain its exact 552-byte action packet',
    );
  }
  try {
    return decodeActionPacket(operation.packet, {
      denominationSats: binding.denominationSats,
    });
  } catch (error) {
    fail(
      'ACTION_PACKET_INVALID',
      `persisted action packet is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

function assertActionPacketAndBundle({
  signed,
  evidence,
  transaction,
  operation,
  binding,
}) {
  if (
    typeof binding.denominationSats !== 'string' ||
    !DECIMAL.test(binding.denominationSats) ||
    binding.networkId !== directV2NetworkIdFromName(signed.network)
  ) {
    fail(
      'PROFILE_INSTANCE_MISMATCH',
      'durable binding lacks the exact V2 network and denomination',
    );
  }
  const packet = decodePersistedPacket(operation, binding);
  const packetBytes = Buffer.from(operation.packet);
  const bindingEvidence = evidence.inputs[signed.carrierCount];
  try {
    decodeDirectV2BindingUnlock({
      unlockingBytecode:
        transaction.inputs[signed.carrierCount].unlockingBytecode,
      sourceLockingBytecode: Buffer.from(
        bindingEvidence.sourceOutput.lockingBytecodeHex,
        'hex',
      ),
      expectedPacket: packetBytes,
    });
  } catch (error) {
    fail(
      'ACTION_PACKET_BINDING_MISMATCH',
      `binding input does not contain the canonical authenticated action packet and redeem: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  if (
    packet.kind !== signed.action ||
    packet.networkId !== binding.networkId ||
    packet.instanceId !== signed.instanceId ||
    packet.preState.profileId !== signed.profileId
  ) {
    fail(
      'ACTION_PACKET_BINDING_MISMATCH',
      'action packet identity differs from signed metadata and durable binding',
    );
  }
  const stateContext = Object.freeze({
    denominationSats: binding.denominationSats,
  });
  const preCommitment = encodeStateNftCommitment(
    packet.preState,
    stateContext,
  );
  const postCommitment = encodeStateNftCommitment(
    packet.postState,
    stateContext,
  );
  const stateInput = evidence.inputs[signed.carrierCount + 1];
  const parsedOutputs = transaction.outputs.map((output, index) =>
    bundleOutputRecord(
      output,
      index,
      signed.carrierCount,
      signed.action,
    ),
  );
  if (
    stateInput.sourceOutput.token?.nft?.commitmentHex !==
      preCommitment.toString('hex') ||
    parsedOutputs[0]?.token?.nft?.commitment.length !== 128 ||
    !parsedOutputs[0].token.nft.commitment.equals(postCommitment)
  ) {
    fail(
      'ACTION_PACKET_STATE_MISMATCH',
      'packet pre/post states do not equal the consumed and recreated state NFT commitments',
    );
  }
  const stateInputValue = BigInt(
    stateInput.sourceOutput.valueSatoshis,
  );
  const preReserve = BigInt(packet.preState.reserveSats);
  if (stateInputValue <= preReserve) {
    fail(
      'ROLLING_BUNDLE_INVALID',
      'state input does not retain a positive covenant base value',
    );
  }
  const verifierPins = evidence.inputs
    .slice(0, signed.carrierCount)
    .map((input) => Object.freeze({
      baseValueSats: input.sourceOutput.valueSatoshis,
      lockingBytecode: Buffer.from(
        input.sourceOutput.lockingBytecodeHex,
        'hex',
      ),
    }));
  const bindingInput = evidence.inputs[signed.carrierCount];
  let model;
  try {
    model = validateDirectV2RollingBundle({
      carrierCount: signed.carrierCount,
      denominationSats: binding.denominationSats,
      feeSats: signed.feeSats,
      inputs: evidence.inputs.map((input, index) =>
        bundleInputRecord(input, transaction.inputs[index]),
      ),
      instanceId: signed.instanceId,
      kind: signed.action,
      locktime: String(transaction.locktime),
      networkId: binding.networkId,
      outputs: parsedOutputs,
      pins: {
        bindingBaseSats: bindingInput.sourceOutput.valueSatoshis,
        bindingLockingBytecode: Buffer.from(
          bindingInput.sourceOutput.lockingBytecodeHex,
          'hex',
        ),
        previousBundleTransactionHash: displayTxidToWire(
          signed.tip.txid,
          'signed tip txid',
        ),
        stateBaseSats: (stateInputValue - preReserve).toString(),
        stateLockingBytecode: Buffer.from(
          stateInput.sourceOutput.lockingBytecodeHex,
          'hex',
        ),
        verifierCarriers: verifierPins,
      },
      postState: packet.postState,
      preState: packet.preState,
      profileId: signed.profileId,
      transactionVersion: String(transaction.version),
    });
  } catch (error) {
    fail(
      'ROLLING_BUNDLE_INVALID',
      `exact signed transaction is not the required rolling bundle: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  const contextHash = hashDirectV2TransactionContext(
    model.context,
    { carrierCount: signed.carrierCount },
  ).toString('hex');
  if (contextHash !== packet.transactionContextHash) {
    fail(
      'TRANSACTION_CONTEXT_MISMATCH',
      'packet context hash does not bind the exact signed transaction, ordered source outputs, and successor bundle',
    );
  }
  if (signed.action === 'withdrawal') {
    const payout = parsedOutputs[signed.carrierCount + 2];
    const payoutHash = createHash('sha256')
      .update(payout.lockingBytecode)
      .digest('hex');
    if (payoutHash !== packet.withdrawalLockingBytecodeHash) {
      fail(
        'WITHDRAWAL_BINDING_MISMATCH',
        'packet withdrawal locking-bytecode hash differs from the exact payout output',
      );
    }
  }
  return Object.freeze({ packet, model });
}

function assertEvidenceBinding({ signed, evidence, transaction }) {
  if (
    evidence.carrierCount !== signed.carrierCount ||
    canonical(evidence.inputRoleLayout) !==
      canonical(signed.inputRoleLayout) ||
    metadataDigest(evidence.inputRoleLayout) !==
      signed.inputRoleLayoutHash ||
    evidence.instanceId !== signed.instanceId ||
    evidence.transaction.rawTransactionHex !== signed.rawTxHex ||
    evidence.transaction.txid !== signed.txid ||
    evidence.transaction.serializedBytes !== signed.sizeBytes ||
    evidence.tool.profileId !== signed.profileId ||
    evidence.evidenceHash !== signed.vmEvidenceHash ||
    canonical(evidence.inputs.map((input) => input.sourceOutput.sha256)) !==
      canonical(signed.inputSourceOutputHashes) ||
    canonical({
      name: evidence.tool.name,
      version: evidence.tool.version,
      vm: evidence.tool.vm,
      profileSha256: evidence.tool.profileSha256,
    }) !== canonical(signed.vmTool)
  ) {
    fail(
      'VM_EVIDENCE_BINDING_MISMATCH',
      'VM evidence does not bind this exact carrier count, role layout, transaction, profile, instance, tool, and ordered source outputs',
    );
  }
  assertRollingSourceLineage({ signed, evidence });
  const fee = actualFee({ transaction, evidence });
  if (fee !== BigInt(signed.feeSats)) {
    fail(
      'FEE_METADATA_MISMATCH',
      'fee metadata differs from evaluated source and serialized output values',
    );
  }
  return fee;
}

/**
 * Construct signer-side metadata from canonical VM evidence. Input roles,
 * outpoints, source-output facts, token facts, unlock sizes, and resource limits
 * are all parsed or derived; none are accepted as caller labels here.
 */
export function createV2SignedBroadcastMetadata(value) {
  exact(
    value,
    [
      'action',
      'feeSats',
      'instanceId',
      'localVmEvidence',
      'network',
      'operationId',
      'profileId',
      'rawTxHex',
      'tip',
    ],
    'signed broadcast metadata producer input',
  );
  const evidence = inspectEvidence(value.localVmEvidence);
  const transaction = parseV2RawTransaction(value.rawTxHex, {
    carrierCount: evidence.carrierCount,
  });
  const profileId = hex32(value.profileId, 'profileId');
  const instanceId = hex32(value.instanceId, 'instanceId');
  if (
    evidence.transaction.rawTransactionHex !==
      transaction.rawTransactionHex ||
    evidence.transaction.txid !== transaction.txid ||
    evidence.transaction.serializedBytes !== transaction.sizeBytes ||
    evidence.instanceId !== instanceId ||
    evidence.tool.profileId !== profileId
  ) {
    fail(
      'VM_EVIDENCE_BINDING_MISMATCH',
      'VM evidence does not bind the metadata transaction, profile, or instance',
    );
  }
  const suppliedFee =
    typeof value.feeSats === 'string' && DECIMAL.test(value.feeSats)
      ? BigInt(value.feeSats)
      : fail(
          'INVALID_METADATA',
          'feeSats must be a canonical unsigned decimal string',
        );
  if (suppliedFee !== actualFee({ transaction, evidence })) {
    fail(
      'FEE_METADATA_MISMATCH',
      'feeSats must equal evaluated inputs minus serialized outputs',
    );
  }
  const core = normalizeMetadata(
    {
      schema: METADATA_SCHEMA,
      carrierCount: evidence.carrierCount,
      inputRoleLayout: evidence.inputRoleLayout,
      inputRoleLayoutHash: metadataDigest(evidence.inputRoleLayout),
      operationId: value.operationId,
      rawTxHex: transaction.rawTransactionHex,
      txid: transaction.txid,
      sizeBytes: transaction.sizeBytes,
      feeSats: suppliedFee.toString(),
      action: value.action,
      profileId,
      instanceId,
      network: value.network,
      tip: value.tip,
      vmEvidenceHash: evidence.evidenceHash,
      inputSourceOutputHashes: evidence.inputs.map(
        (input) => input.sourceOutput.sha256,
      ),
      vmTool: {
        name: evidence.tool.name,
        version: evidence.tool.version,
        vm: evidence.tool.vm,
        profileSha256: evidence.tool.profileSha256,
      },
    },
    { allowHash: false },
  );
  return deepFreeze({
    ...core,
    metadataHash: metadataDigest(core),
  });
}

/**
 * Re-derive the complete signer-side settlement contract without touching
 * persistence or network state. Qualification and recovery tooling use this
 * same production boundary so a hash-bound packet, local VM result, or raw
 * transaction cannot be accepted independently of the rolling bundle,
 * authenticated source transactions, state NFT, fee, profile, and network.
 */
export function verifyV2SignedSettlementEvidence(value) {
  exact(
    value,
    ['binding', 'localVmEvidence', 'metadata', 'packet'],
    'signed settlement evidence',
  );
  const signed = normalizeMetadata(value.metadata, { allowHash: true });
  const evidence = inspectEvidence(value.localVmEvidence);
  const transaction = parseV2RawTransaction(signed.rawTxHex, {
    carrierCount: signed.carrierCount,
  });
  const fee = assertEvidenceBinding({
    signed,
    evidence,
    transaction,
  });
  const derived = assertActionPacketAndBundle({
    signed,
    evidence,
    transaction,
    operation: Object.freeze({ packet: value.packet }),
    binding: value.binding,
  });
  if (fee < BigInt(signed.sizeBytes)) {
    fail(
      'FEE_TOO_LOW',
      'fee rate below 1 satoshi per serialized byte is refused',
    );
  }
  return Object.freeze({
    action: signed.action,
    carrierCount: signed.carrierCount,
    evidenceHash: evidence.evidenceHash,
    feeSats: fee.toString(),
    instanceId: signed.instanceId,
    metadataHash: value.metadata.metadataHash,
    packet: derived.packet,
    profileId: signed.profileId,
    rawTransactionSha256: rawTransactionSha256(signed.rawTxHex),
    transactionId: transaction.txid,
  });
}

export function createV2HighFeeConfirmation(metadata) {
  if (!deeplyFrozen(metadata)) {
    fail(
      'METADATA_NOT_IMMUTABLE',
      'signed broadcast metadata must be recursively frozen',
    );
  }
  const signed = normalizeMetadata(metadata, { allowHash: true });
  return deepFreeze({
    schema: HIGH_FEE_SCHEMA,
    operationId: signed.operationId,
    metadataHash: metadata.metadataHash,
    purpose: 'confirm-fee-above-10-sat-per-byte',
  });
}

export function assertV2SecureEndpoint(endpoint) {
  try {
    return assertSecureEndpoint(endpoint);
  } catch (error) {
    asGateError(error, 'UNSAFE_ENDPOINT');
  }
}

function requireStore(store) {
  if (
    !store ||
    typeof store.operation !== 'function' ||
    typeof store.binding !== 'function' ||
    typeof store.canonicalState !== 'function' ||
    typeof store.transitionOperation !== 'function' ||
    typeof store.recordMempoolOverlay !== 'function'
  ) {
    fail(
      'PERSISTENCE_REQUIRED',
      'V2 durable pool-store adapter is required',
    );
  }
}

function requireDelivery(delivery) {
  try {
    assertV2DeliveryJournal(delivery);
  } catch (error) {
    asGateError(error, 'PERSISTENCE_REQUIRED');
  }
}

function requireTransport(transport) {
  try {
    return assertV2Transport(transport);
  } catch (error) {
    asGateError(error, 'TRANSPORT_REQUIRED');
  }
}

function requireTipSynchronizer(synchronizeCanonicalTip) {
  if (typeof synchronizeCanonicalTip !== 'function') {
    fail(
      'TIP_SYNCHRONIZER_REQUIRED',
      'an authenticated canonical-tip synchronizer is required inside the network gate',
    );
  }
  return synchronizeCanonicalTip;
}

function sameTip(current, expected) {
  return (
    equal(current.state, Buffer.from(expected.state, 'hex')) &&
    equal(current.outpoint.txid, Buffer.from(expected.txid, 'hex')) &&
    current.outpoint.vout === expected.vout &&
    current.actionSequence === expected.actionSequence &&
    current.height === expected.height &&
    equal(current.blockHash, Buffer.from(expected.blockHash, 'hex'))
  );
}

function emit(log, event, metadata, extra = {}) {
  if (log === undefined) return;
  if (typeof log !== 'function') {
    fail('INVALID_LOGGER', 'log must be a function');
  }
  log(
    Object.freeze({
      event,
      operationId: metadata.operationId,
      txid: metadata.txid,
      action: metadata.action,
      network: metadata.network,
      ...extra,
    }),
  );
}

function validateConfirmation(token, metadata) {
  if (token === undefined) {
    fail(
      'HIGH_FEE_CONFIRMATION_REQUIRED',
      'high fee requires an immutable confirmation for this exact operation',
    );
  }
  exact(
    token,
    ['metadataHash', 'operationId', 'purpose', 'schema'],
    'high fee confirmation',
  );
  if (
    !deeplyFrozen(token) ||
    token.schema !== HIGH_FEE_SCHEMA ||
    token.purpose !== 'confirm-fee-above-10-sat-per-byte' ||
    token.operationId !== metadata.operationId ||
    token.metadataHash !== metadata.metadataHash
  ) {
    fail(
      'HIGH_FEE_CONFIRMATION_REQUIRED',
      'high fee requires an immutable confirmation for this exact operation',
    );
  }
}

function validateTransportReply(reply, endpoint, txid) {
  try {
    exact(
      reply,
      [
        'peerCertificateSha256',
        'redirected',
        'tlsProtocol',
        'txid',
      ],
      'transport reply',
    );
  } catch {
    fail(
      'TRANSPORT_REPLY_INVALID',
      'transport reply has missing or unknown security fields',
      { recoverable: true },
    );
  }
  if (
    reply.redirected !== false ||
    TLS_RANK[reply.tlsProtocol] === undefined ||
    TLS_RANK[reply.tlsProtocol] <
      TLS_RANK[endpoint.tls.minVersion] ||
    reply.peerCertificateSha256 !== endpoint.tls.certificateSha256
  ) {
    fail(
      'TRANSPORT_SECURITY_VIOLATION',
      'transport reported a redirect, TLS downgrade, or certificate mismatch',
      { recoverable: true },
    );
  }
  if (reply.txid !== txid) {
    fail(
      'RPC_TXID_MISMATCH',
      'RPC transaction id does not match the exact serialized bytes',
      { recoverable: true },
    );
  }
  return reply;
}

function overlayBytes(metadata) {
  return Buffer.from(
    canonical({
      schema: MEMPOOL_OVERLAY_SCHEMA,
      source: 'sendrawtransaction',
      txid: metadata.txid,
    }),
    'utf8',
  );
}

function operationAndBinding(store, signed) {
  const operation = store.operation(signed.operationId);
  if (!operation || operation.operationId !== signed.operationId) {
    fail(
      'OPERATION_NOT_PERSISTED',
      'signed operation ID is not persisted',
    );
  }
  const binding = store.binding();
  if (
    !equal(binding.profileId, Buffer.from(signed.profileId, 'hex')) ||
    !equal(binding.instanceId, Buffer.from(signed.instanceId, 'hex'))
  ) {
    fail(
      'PROFILE_INSTANCE_MISMATCH',
      'signed metadata does not match the durable profile and instance binding',
    );
  }
  if (binding.carrierCount !== signed.carrierCount) {
    fail(
      'CARRIER_COUNT_MISMATCH',
      'signed metadata does not match the durable carrier-count binding',
    );
  }
  if (
    operation.kind !== signed.action ||
    operation.journalState === 'needs_reproof' ||
    !sameTip(store.canonicalState(), signed.tip) ||
    !equal(operation.expectedState, Buffer.from(signed.tip.state, 'hex')) ||
    !equal(
      operation.expectedOutpoint.txid,
      Buffer.from(signed.tip.txid, 'hex'),
    ) ||
    operation.expectedOutpoint.vout !== signed.tip.vout ||
    operation.expectedActionSequence !== signed.tip.actionSequence
  ) {
    fail(
      'STALE_TIP',
      'signed operation does not match the current canonical tip',
    );
  }
  if (
    !(operation.signedTx instanceof Uint8Array) ||
    !equal(
      operation.signedTx,
      Buffer.from(signed.rawTxHex, 'hex'),
    )
  ) {
    fail(
      'TRANSACTION_MUTATED',
      'persisted signed transaction differs from signed metadata',
    );
  }
  if (
    !['signed', 'broadcast', 'mempool'].includes(
      operation.journalState,
    )
  ) {
    fail(
      'OPERATION_NOT_SIGNED',
      'operation must be durably signed before broadcast',
    );
  }
  return operation;
}

function assertDeliveryIdentity(record, identity) {
  if (
    record.operationId !== identity.operationId
    || record.txid !== identity.txid
    || record.metadataHash !== identity.metadataHash
    || record.evidenceHash !== identity.evidenceHash
    || record.carrierCount !== identity.carrierCount
    || record.roleLayoutHash !== identity.roleLayoutHash
  ) {
    fail(
      'DIVERGENT_REBROADCAST',
      'durable delivery identity differs from the exact signed operation',
    );
  }
  return record;
}

async function synchronizeImmediatelyBeforeClaim({
  store,
  signed,
  synchronizeCanonicalTip,
}) {
  const request = deepFreeze({
    phase: 'pre-broadcast',
    operationId: signed.operationId,
    priorCanonicalTip: signed.tip,
  });
  let reported;
  try {
    reported = await synchronizeCanonicalTip(request);
  } catch (error) {
    fail(
      'TIP_SYNCHRONIZATION_FAILED',
      `canonical tip synchronization failed immediately before send claim: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { recoverable: true },
    );
  }
  let reportedMatches = false;
  try {
    reportedMatches = sameTip(reported, signed.tip);
  } catch {}
  if (
    !reportedMatches
    || !sameTip(store.canonicalState(), signed.tip)
  ) {
    fail(
      'STALE_TIP',
      'authenticated synchronization changed or contradicted the signed canonical tip',
      { recoverable: true },
    );
  }
  return operationAndBinding(store, signed);
}

function validateSignedDeliveryContext({
  store,
  metadata,
  highFeeConfirmation,
  enforceHighFeeConfirmation,
}) {
  requireStore(store);
  if (!deeplyFrozen(metadata)) {
    fail(
      'METADATA_NOT_IMMUTABLE',
      'signed broadcast metadata must be recursively frozen',
    );
  }
  const signed = normalizeMetadata(metadata, { allowHash: true });
  const operation = operationAndBinding(store, signed);
  if (
    !(operation.localVmEvidence instanceof Uint8Array) ||
    operation.localVmEvidence.length === 0
  ) {
    fail(
      'LOCAL_VM_EVIDENCE_REQUIRED',
      'canonical successful local VM evidence is required',
    );
  }
  const verified = verifyV2SignedSettlementEvidence({
    binding: store.binding(),
    localVmEvidence: operation.localVmEvidence,
    metadata,
    packet: operation.packet,
  });
  const evidence = inspectEvidence(operation.localVmEvidence);
  const fee = BigInt(verified.feeSats);
  if (
    enforceHighFeeConfirmation &&
    fee > BigInt(signed.sizeBytes) * 10n
  ) {
    validateConfirmation(highFeeConfirmation, metadata);
  }
  return Object.freeze({
    signed,
    operation,
    evidence,
    identity: Object.freeze({
      operationId: signed.operationId,
      txid: signed.txid,
      metadataHash: metadata.metadataHash,
      evidenceHash: verified.evidenceHash,
      carrierCount: signed.carrierCount,
      roleLayoutHash: signed.inputRoleLayoutHash,
    }),
  });
}

function finalizeSubmitted({
  store,
  delivery,
  signed,
  log,
  replayed,
}) {
  try {
    let operation = store.operation(signed.operationId);
    if (operation.journalState === 'signed') {
      store.transitionOperation({
        operationId: signed.operationId,
        to: 'broadcast',
        reason: null,
      });
      operation = store.operation(signed.operationId);
    }
    if (operation.journalState === 'broadcast') {
      store.recordMempoolOverlay({
        operationId: signed.operationId,
        overlay: overlayBytes(signed),
      });
      operation = store.operation(signed.operationId);
    }
    if (operation.journalState !== 'mempool') {
      fail(
        'BROADCAST_RECORD_INDETERMINATE',
        'submitted transaction could not reach the durable local mempool state',
        { recoverable: true },
      );
    }
    delivery.markLocallyReconciled({
      operationId: signed.operationId,
      txid: signed.txid,
      rawTransactionSha256: rawTransactionSha256(signed.rawTxHex),
    });
    emit(log, 'broadcast.locally-reconciled', signed);
    return Object.freeze({
      status: 'mempool',
      txid: signed.txid,
      replayed,
    });
  } catch (error) {
    if (
      error instanceof V2NetworkGateError &&
      error.code === 'BROADCAST_RECORD_INDETERMINATE'
    ) {
      throw error;
    }
    emit(log, 'broadcast.store-recovery-required', signed);
    fail(
      'BROADCAST_RECORD_INDETERMINATE',
      'RPC submission is durable but pool-store finalization requires local recovery',
      { recoverable: true },
    );
  }
}

function markIndeterminateBestEffort({
  delivery,
  signed,
  attemptToken,
  failureCode,
}) {
  try {
    delivery.markIndeterminate({
      operationId: signed.operationId,
      attemptToken,
      reason: `post-claim:${failureCode}`.slice(0, 256),
    });
  } catch {}
}

async function submitClaimedAction({
  store,
  delivery,
  selectedTransport,
  secureEndpoint,
  signed,
  claim,
  log,
  replayed,
}) {
  emit(log, 'broadcast.send-claimed', signed, {
    fixtureOnly: selectedTransport.fixtureOnly,
    exactResubmission: replayed,
  });
  try {
    const reply = await selectedTransport.sendRawTransaction({
      rawTxHex: signed.rawTxHex,
      endpoint: secureEndpoint,
    });
    validateTransportReply(reply, secureEndpoint, signed.txid);
    delivery.markSubmitted({
      operationId: signed.operationId,
      attemptToken: claim.attemptToken,
      txid: signed.txid,
      rawTransactionSha256: rawTransactionSha256(signed.rawTxHex),
    });
  } catch (error) {
    const failureCode =
      typeof error?.code === 'string'
        ? error.code
        : 'TRANSPORT_INDETERMINATE';
    markIndeterminateBestEffort({
      delivery,
      signed,
      attemptToken: claim.attemptToken,
      failureCode,
    });
    emit(log, 'broadcast.indeterminate', signed, {
      reason: failureCode,
    });
    fail(
      failureCode,
      'claimed network send is indeterminate; explicit recovery is required',
      { recoverable: true },
    );
  }
  emit(log, 'broadcast.submitted', signed, {
    exactResubmission: replayed,
  });
  return finalizeSubmitted({
    store,
    delivery,
    signed,
    log,
    replayed,
  });
}

/**
 * The only V2 public entry point that invokes network transport. A send is
 * claimed exactly once in SQLite; this function never retries transport.
 *
 * Journal `locally_reconciled` means the submitted RPC and local pool-store
 * lifecycle are durably reconciled. It does not claim BCH chain confirmation.
 */
export async function broadcastAction({
  store,
  delivery,
  transport,
  endpoint,
  metadata,
  synchronizeCanonicalTip,
  highFeeConfirmation = undefined,
  log = undefined,
}) {
  requireDelivery(delivery);
  const selectedTransport = requireTransport(transport);
  const selectedSynchronizer = requireTipSynchronizer(
    synchronizeCanonicalTip,
  );
  const {
    signed,
    operation,
    evidence,
    identity,
  } = validateSignedDeliveryContext({
    store,
    metadata,
    highFeeConfirmation,
    enforceHighFeeConfirmation: true,
  });
  const secureEndpoint = assertV2SecureEndpoint(endpoint);
  if (secureEndpoint.network !== signed.network) {
    fail(
      'NETWORK_MISMATCH',
      'endpoint network does not match signed transaction network',
    );
  }
  let record = delivery.record(signed.operationId);
  if (record !== null) {
    assertDeliveryIdentity(record, identity);
    if (['attempted', 'indeterminate'].includes(record.state)) {
      fail(
        'RECOVERY_REQUIRED',
        `delivery is ${record.state}; automatic retransmission is forbidden`,
        { recoverable: true },
      );
    }
    if (['submitted', 'locally_reconciled'].includes(record.state)) {
      emit(log, 'broadcast.local-replay', signed, {
        deliveryState: record.state,
      });
      return finalizeSubmitted({
        store,
        delivery,
        signed,
        log,
        replayed: true,
      });
    }
    fail(
      'RECOVERY_REQUIRED',
      'delivery journal contains an unsupported recovery state',
      { recoverable: true },
    );
  }
  if (operation.journalState !== 'signed') {
    fail(
      'DIVERGENT_REBROADCAST',
      'pool store records delivery but the durable send journal is absent',
    );
  }

  await synchronizeImmediatelyBeforeClaim({
    store,
    signed,
    synchronizeCanonicalTip: selectedSynchronizer,
  });

  // Full policy envelope and identity are reparsed immediately before the
  // atomic send claim; no smaller risk-margin ceiling is applied.
  const reparsed = parseV2RawTransaction(signed.rawTxHex, {
    carrierCount: signed.carrierCount,
  });
  if (
    reparsed.txid !== signed.txid ||
    reparsed.sizeBytes !== signed.sizeBytes
  ) {
    fail(
      'TRANSACTION_MUTATED',
      'pre-send reparse changed transaction identity',
    );
  }
  let claim;
  try {
    claim = delivery.claimOrCreate(identity);
  } catch (error) {
    asGateError(error, 'SEND_ALREADY_CLAIMED');
  }
  return submitClaimedAction({
    store,
    delivery,
    selectedTransport,
    secureEndpoint,
    signed,
    claim,
    log,
    replayed: false,
  });
}

/**
 * Explicitly retry the exact immutable transaction from an unresolved
 * delivery claim. This is never called by `broadcastAction` or observation
 * recovery: the caller must supply both the current journal CAS token and the
 * literal acknowledgement. The fresh-tip check and send still execute inside
 * this mandatory gate.
 */
export async function rebroadcastExactAction({
  store,
  delivery,
  transport,
  endpoint,
  metadata,
  synchronizeCanonicalTip,
  priorAttemptToken,
  acknowledgement,
  highFeeConfirmation = undefined,
  log = undefined,
}) {
  if (acknowledgement !== V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT) {
    fail(
      'EXACT_RESUBMISSION_ACKNOWLEDGEMENT_REQUIRED',
      `acknowledgement must exactly equal ${V2_EXACT_RESUBMISSION_ACKNOWLEDGEMENT}`,
    );
  }
  requireDelivery(delivery);
  const selectedTransport = requireTransport(transport);
  const selectedSynchronizer = requireTipSynchronizer(
    synchronizeCanonicalTip,
  );
  const {
    signed,
    identity,
  } = validateSignedDeliveryContext({
    store,
    metadata,
    highFeeConfirmation,
    enforceHighFeeConfirmation: true,
  });
  const secureEndpoint = assertV2SecureEndpoint(endpoint);
  if (secureEndpoint.network !== signed.network) {
    fail(
      'NETWORK_MISMATCH',
      'endpoint network does not match signed transaction network',
    );
  }
  const record = delivery.record(signed.operationId);
  if (record === null) {
    fail(
      'DELIVERY_RECORD_REQUIRED',
      'exact resubmission requires an unresolved prior send claim',
      { recoverable: true },
    );
  }
  assertDeliveryIdentity(record, identity);
  if (['submitted', 'locally_reconciled'].includes(record.state)) {
    emit(log, 'broadcast.local-replay', signed, {
      deliveryState: record.state,
    });
    return finalizeSubmitted({
      store,
      delivery,
      signed,
      log,
      replayed: true,
    });
  }
  if (!['attempted', 'indeterminate'].includes(record.state)) {
    fail(
      'RECOVERY_REQUIRED',
      'delivery journal contains an unsupported recovery state',
      { recoverable: true },
    );
  }
  if (
    typeof priorAttemptToken !== 'string'
    || priorAttemptToken !== record.attemptToken
  ) {
    fail(
      'RECOVERY_TOKEN_MISMATCH',
      'exact resubmission requires the current durable attempt token',
      { recoverable: true },
    );
  }

  await synchronizeImmediatelyBeforeClaim({
    store,
    signed,
    synchronizeCanonicalTip: selectedSynchronizer,
  });
  const reparsed = parseV2RawTransaction(signed.rawTxHex, {
    carrierCount: signed.carrierCount,
  });
  if (
    reparsed.txid !== signed.txid
    || reparsed.sizeBytes !== signed.sizeBytes
    || reparsed.rawTransactionHex !== signed.rawTxHex
  ) {
    fail(
      'TRANSACTION_MUTATED',
      'exact resubmission reparse changed transaction identity',
    );
  }
  let claim;
  try {
    claim = delivery.claimExactResubmission({
      identity,
      priorAttemptToken,
    });
  } catch (error) {
    asGateError(error, 'RECOVERY_TOKEN_MISMATCH');
  }
  return submitClaimedAction({
    store,
    delivery,
    selectedTransport,
    secureEndpoint,
    signed,
    claim,
    log,
    replayed: true,
  });
}

/**
 * Recover an ambiguous first send without invoking transport. The injected
 * reader must be an authenticated chain/mempool reader. Only the exact
 * serialized transaction already persisted by the lifecycle can reconcile the
 * delivery claim.
 */
export async function reconcileObservedAction({
  store,
  delivery,
  metadata,
  loadRawTransaction,
  log = undefined,
}) {
  requireDelivery(delivery);
  if (typeof loadRawTransaction !== 'function') {
    fail(
      'CHAIN_READER_REQUIRED',
      'an authenticated raw-transaction reader is required for delivery recovery',
    );
  }
  const {
    signed,
    identity,
  } = validateSignedDeliveryContext({
    store,
    metadata,
    highFeeConfirmation: undefined,
    enforceHighFeeConfirmation: false,
  });
  const record = delivery.record(signed.operationId);
  if (record === null) {
    fail(
      'DELIVERY_RECORD_REQUIRED',
      'delivery recovery requires an existing exact send claim',
      { recoverable: true },
    );
  }
  assertDeliveryIdentity(record, identity);
  if (['submitted', 'locally_reconciled'].includes(record.state)) {
    emit(log, 'broadcast.local-replay', signed, {
      deliveryState: record.state,
    });
    return finalizeSubmitted({
      store,
      delivery,
      signed,
      log,
      replayed: true,
    });
  }
  if (!['attempted', 'indeterminate'].includes(record.state)) {
    fail(
      'RECOVERY_REQUIRED',
      'delivery journal contains an unsupported recovery state',
      { recoverable: true },
    );
  }

  let rawTransactionHex;
  try {
    rawTransactionHex = await loadRawTransaction(deepFreeze({
      networkId: directV2NetworkIdFromName(signed.network),
      transactionId: signed.txid,
    }));
  } catch (error) {
    fail(
      'TRANSACTION_OBSERVATION_FAILED',
      `authenticated transaction observation failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { recoverable: true },
    );
  }
  if (rawTransactionHex === null) {
    fail(
      'TRANSACTION_NOT_OBSERVED',
      'the exact signed transaction was not observed; no resend was attempted',
      { recoverable: true },
    );
  }
  if (
    typeof rawTransactionHex !== 'string'
    || !/^(?:[0-9a-f]{2})+$/.test(rawTransactionHex)
  ) {
    fail(
      'OBSERVED_TRANSACTION_INVALID',
      'authenticated transaction reader returned non-canonical raw transaction bytes',
    );
  }
  const observed = parseV2RawTransaction(rawTransactionHex, {
    carrierCount: signed.carrierCount,
  });
  if (
    observed.txid !== signed.txid
    || observed.rawTransactionHex !== signed.rawTxHex
  ) {
    fail(
      'OBSERVED_TRANSACTION_MISMATCH',
      'observed transaction is not byte-identical to the persisted signed operation',
    );
  }
  try {
    delivery.reconcileObserved({
      operationId: signed.operationId,
      txid: signed.txid,
      rawTransactionSha256: rawTransactionSha256(
        observed.rawTransactionHex,
      ),
    });
  } catch (error) {
    asGateError(error, 'DELIVERY_RECONCILIATION_FAILED');
  }
  emit(log, 'broadcast.observed-recovery', signed);
  return finalizeSubmitted({
    store,
    delivery,
    signed,
    log,
    replayed: true,
  });
}
