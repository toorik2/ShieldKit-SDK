import { TextDecoder } from 'node:util';
import { createRequire } from 'node:module';
import {
  ConsensusBch2025,
  createVirtualMachineBch2026,
  decodeTransaction,
  maximumSignatureCheckCount,
} from '@bitauth/libauth';

import {
  assertV2SourceOutputTopology,
  assertV2StandardTransactionEnvelope,
  createV2InputRoleLayout,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
  sha256Hex,
} from './transaction-policy.mjs';

export const V2_VM_EVIDENCE_SCHEMA =
  'shieldkit/v2-local-vm-evidence/v2';
export const V2_VM_PROFILE = 'BCH_2026_STANDARD';
const LIBAUTH_VERSION = createRequire(import.meta.url)(
  '@bitauth/libauth/package.json',
).version;

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const TOOL_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/;
const METRIC_FIELDS = Object.freeze([
  'arithmeticCost',
  'definedFunctions',
  'densityControlLength',
  'evaluatedInstructionCount',
  'hashDigestIterations',
  'maximumHashDigestIterations',
  'maximumOperationCost',
  'maximumSignatureCheckCount',
  'operationCost',
  'signatureCheckCount',
  'stackPushedBytes',
]);

export class V2VmEvidenceError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2VmEvidenceError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2VmEvidenceError(code, message);
};

function plain(value, label) {
  if (
    value === null ||
    Array.isArray(value) ||
    typeof value !== 'object' ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_VM_EVIDENCE', `${label} must be a plain object`);
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
      'INVALID_VM_EVIDENCE',
      `${label} has missing or unknown fields`,
    );
  }
  return value;
}

function hex32(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'INVALID_VM_EVIDENCE',
      `${label} must be lowercase 32-byte hex`,
    );
  }
  return value;
}

function canonicalDecimal(value, label) {
  if (
    typeof value !== 'string' ||
    value.length > 20 ||
    !DECIMAL.test(value)
  ) {
    fail(
      'INVALID_VM_EVIDENCE',
      `${label} must be a canonical unsigned decimal string`,
    );
  }
  return value;
}

function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail('INVALID_VM_EVIDENCE', `${label} is outside its integer range`);
  }
  return value;
}

export function canonicalizeV2Evidence(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeV2Evidence).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalizeV2Evidence(value[key])}`,
      )
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function normalizeTool(value) {
  exact(
    value,
    ['name', 'profileId', 'profileSha256', 'version', 'vm'],
    'VM tool',
  );
  if (
    value.name !== '@bitauth/libauth' ||
    value.vm !== V2_VM_PROFILE ||
    typeof value.version !== 'string' ||
    !TOOL_VERSION.test(value.version) ||
    value.version !== LIBAUTH_VERSION
  ) {
    fail(
      'UNSUPPORTED_VM_TOOL',
      `VM evidence must identify the installed @bitauth/libauth ${LIBAUTH_VERSION} BCH_2026_STANDARD evaluator`,
    );
  }
  return Object.freeze({
    name: value.name,
    version: value.version,
    vm: value.vm,
    profileId: hex32(value.profileId, 'VM tool profileId'),
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

function normalizeRoleLayout(value, carrierCount) {
  const expected = createV2InputRoleLayout(carrierCount);
  if (!Array.isArray(value) || value.length !== expected.length) {
    fail(
      'INPUT_ROLE_LAYOUT_MISMATCH',
      'input role layout length does not match carrierCount',
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

function normalizeMetrics(value, index, unlockingBytecodeBytes) {
  exact(value, METRIC_FIELDS, `input ${index} metrics`);
  const normalized = {};
  for (const field of METRIC_FIELDS) {
    normalized[field] = canonicalDecimal(
      value[field],
      `input ${index} metrics.${field}`,
    );
  }
  const densityControlLength =
    ConsensusBch2025.densityControlBaseLength + unlockingBytecodeBytes;
  const expectedLimits = Object.freeze({
    densityControlLength: String(densityControlLength),
    maximumOperationCost: String(
      Math.floor(
        densityControlLength *
          ConsensusBch2025.operationCostBudgetPerByte,
      ),
    ),
    maximumHashDigestIterations: String(
      Math.floor(
        densityControlLength *
          ConsensusBch2025.hashDigestIterationsPerByteStandard,
      ),
    ),
    maximumSignatureCheckCount: String(
      maximumSignatureCheckCount(unlockingBytecodeBytes),
    ),
  });
  for (const [field, expected] of Object.entries(expectedLimits)) {
    if (normalized[field] !== expected) {
      fail(
        'VM_RESOURCE_PROFILE_MISMATCH',
        `input ${index} ${field} is not the BCH_2026_STANDARD maximum derived from its unlocking bytecode`,
      );
    }
  }
  const resourcePairs = [
    ['operationCost', 'maximumOperationCost'],
    ['hashDigestIterations', 'maximumHashDigestIterations'],
    ['signatureCheckCount', 'maximumSignatureCheckCount'],
  ];
  for (const [used, limit] of resourcePairs) {
    if (BigInt(normalized[used]) > BigInt(normalized[limit])) {
      fail(
        'VM_RESOURCE_LIMIT',
        `input ${index} ${used} exceeds its full standard-policy limit`,
      );
    }
  }
  const measuredOperationCost =
    BigInt(normalized.evaluatedInstructionCount) *
      BigInt(ConsensusBch2025.baseInstructionCost) +
    BigInt(normalized.signatureCheckCount) *
      BigInt(ConsensusBch2025.signatureCheckCost) +
    BigInt(normalized.hashDigestIterations) *
      BigInt(ConsensusBch2025.hashDigestIterationCostStandard) +
    BigInt(normalized.arithmeticCost) +
    BigInt(normalized.stackPushedBytes);
  if (BigInt(normalized.operationCost) !== measuredOperationCost) {
    fail(
      'VM_RESOURCE_ACCOUNTING_MISMATCH',
      `input ${index} operationCost does not equal its measured BCH_2026_STANDARD components`,
    );
  }
  return Object.freeze(normalized);
}

export function assertV2VmResourceMetrics(
  value,
  { inputIndex = 0, unlockingBytecodeBytes },
) {
  integer(
    inputIndex,
    0,
    Number.MAX_SAFE_INTEGER,
    'VM resource inputIndex',
  );
  integer(
    unlockingBytecodeBytes,
    0,
    10_000,
    'VM resource unlockingBytecodeBytes',
  );
  return normalizeMetrics(value, inputIndex, unlockingBytecodeBytes);
}

function normalizedToken(token) {
  if (token === null) return null;
  return Object.freeze({
    categoryWire: token.categoryWire,
    amount: token.amount,
    nft:
      token.nft === null
        ? null
        : Object.freeze({
            capability: token.nft.capability,
            commitmentHex: token.nft.commitmentHex,
          }),
  });
}

function normalizedSourceOutput(sourceOutput) {
  return Object.freeze({
    serializedHex: sourceOutput.serializedHex,
    sha256: sourceOutput.sha256,
    valueSatoshis: sourceOutput.valueSatoshis.toString(),
    lockingBytecodeHex: sourceOutput.lockingBytecodeHex,
    tokenPrefixHex: sourceOutput.tokenPrefixHex,
    token: normalizedToken(sourceOutput.token),
  });
}

function authenticateSourceTransaction({
  rawTransactionHex,
  outpoint,
  index,
}) {
  const sourceTransaction = parseV2RawTransaction(rawTransactionHex);
  if (sourceTransaction.txid !== outpoint.txid) {
    fail(
      'SOURCE_TRANSACTION_MISMATCH',
      `input ${index} source transaction hash does not match its serialized outpoint`,
    );
  }
  const serializedOutput =
    sourceTransaction.outputs[outpoint.vout]?.serializedHex;
  if (serializedOutput === undefined) {
    fail(
      'SOURCE_OUTPOINT_MISMATCH',
      `input ${index} source transaction does not contain its referenced output`,
    );
  }
  return Object.freeze({
    sourceTransaction: Object.freeze({
      rawTransactionHex: sourceTransaction.rawTransactionHex,
      txid: sourceTransaction.txid,
      serializedBytes: sourceTransaction.sizeBytes,
    }),
    sourceOutput: parseSerializedSourceOutput(serializedOutput),
  });
}

function normalizeProducedInput({
  value,
  index,
  transaction,
  instanceId,
  carrierCount,
  roleLayout,
}) {
  exact(
    value,
    ['sourceTransactionHex'],
    `VM input ${index}`,
  );
  const transactionInput = transaction.inputs[index];
  const authenticated = authenticateSourceTransaction({
    rawTransactionHex: value.sourceTransactionHex,
    outpoint: transactionInput.outpoint,
    index,
  });
  const sourceOutput = authenticated.sourceOutput;
  const role = assertV2SourceOutputTopology({
    index,
    sourceOutput,
    instanceId,
    carrierCount,
  });
  return Object.freeze({
    index,
    role: normalizeRole(
      role,
      roleLayout[index],
      `VM input ${index} role`,
    ),
    outpoint: Object.freeze({
      txid: transactionInput.outpoint.txid,
      vout: transactionInput.outpoint.vout,
    }),
    sourceTransaction: authenticated.sourceTransaction,
    sourceOutput: normalizedSourceOutput(sourceOutput),
    unlockingBytecodeBytes: transactionInput.unlockingBytecodeBytes,
  });
}

function decodeExactTransaction(rawTransactionHex, label) {
  const decoded = decodeTransaction(
    // Do not pass a Node Buffer. Buffer.slice() aliases, while Libauth
    // transaction serialization uses slice().reverse() for wire-order hashes.
    // A plain Uint8Array guarantees those reversals operate on copies.
    Uint8Array.from(Buffer.from(rawTransactionHex, 'hex')),
  );
  if (typeof decoded === 'string') {
    fail(
      'VM_TRANSACTION_DECODE_FAILED',
      `${label} cannot be decoded by the installed Libauth evaluator: ${decoded}`,
    );
  }
  return decoded;
}

function actualMetricRecord(state, index, unlockingBytecodeBytes) {
  const metrics = Object.fromEntries(
    METRIC_FIELDS.map((field) => {
      const value = state.metrics?.[field];
      if (
        !Number.isSafeInteger(value) ||
        value < 0
      ) {
        fail(
          'VM_METRICS_UNAVAILABLE',
          `standard VM input ${index} did not report canonical ${field}`,
        );
      }
      return [field, String(value)];
    }),
  );
  return normalizeMetrics(metrics, index, unlockingBytecodeBytes);
}

function evaluateExactStandardTransaction({ transaction, inputs }) {
  const decodedTransaction = decodeExactTransaction(
    transaction.rawTransactionHex,
    'signed transaction',
  );
  const sourceOutputs = inputs.map((input, index) => {
    const source = decodeExactTransaction(
      input.sourceTransaction.rawTransactionHex,
      `source transaction ${index}`,
    );
    const output = source.outputs[input.outpoint.vout];
    if (output === undefined) {
      fail(
        'SOURCE_OUTPOINT_MISMATCH',
        `source transaction ${index} lacks its authenticated output`,
      );
    }
    return output;
  });
  const vm = createVirtualMachineBch2026(true);
  const verdict = vm.verify({
    sourceOutputs,
    transaction: decodedTransaction,
  });
  if (verdict !== true) {
    fail(
      'VM_TRANSACTION_REJECTED',
      `installed BCH_2026_STANDARD Libauth rejected the exact resolved transaction: ${verdict}`,
    );
  }
  return Object.freeze(
    inputs.map((input, index) => {
      const state = vm.evaluate({
        inputIndex: index,
        sourceOutputs,
        transaction: decodedTransaction,
      });
      const success = vm.stateSuccess(state);
      if (success !== true) {
        fail(
          'VM_INPUT_REJECTED',
          `installed BCH_2026_STANDARD Libauth rejected input ${index}: ${success}`,
        );
      }
      return actualMetricRecord(
        state,
        index,
        input.unlockingBytecodeBytes,
      );
    }),
  );
}

function validateNormalizedSourceTransaction(value, index, outpoint) {
  exact(
    value,
    ['rawTransactionHex', 'serializedBytes', 'txid'],
    `input ${index} source transaction`,
  );
  const authenticated = authenticateSourceTransaction({
    rawTransactionHex: value.rawTransactionHex,
    outpoint,
    index,
  });
  if (
    value.txid !== authenticated.sourceTransaction.txid ||
    value.serializedBytes !==
      authenticated.sourceTransaction.serializedBytes
  ) {
    fail(
      'SOURCE_TRANSACTION_MISMATCH',
      `input ${index} source transaction metadata does not match its exact bytes`,
    );
  }
  return authenticated;
}

function validateNormalizedSourceOutput(
  value,
  index,
  instanceId,
  authenticatedSourceOutput,
  carrierCount,
) {
  exact(
    value,
    [
      'lockingBytecodeHex',
      'serializedHex',
      'sha256',
      'token',
      'tokenPrefixHex',
      'valueSatoshis',
    ],
    `input ${index} source output`,
  );
  const parsed = parseSerializedSourceOutput(value.serializedHex);
  const expected = normalizedSourceOutput(parsed);
  if (value.serializedHex !== authenticatedSourceOutput.serializedHex) {
    fail(
      'SOURCE_OUTPUT_AUTHENTICATION_MISMATCH',
      `input ${index} source output is not the output authenticated by its previous transaction and outpoint`,
    );
  }
  if (canonicalizeV2Evidence(value) !== canonicalizeV2Evidence(expected)) {
    fail(
      'SOURCE_OUTPUT_FACT_MISMATCH',
      `input ${index} source-output facts do not match serialized bytes`,
    );
  }
  assertV2SourceOutputTopology({
    index,
    sourceOutput: parsed,
    instanceId,
    carrierCount,
  });
  return expected;
}

function validateNormalizedInput({
  value,
  index,
  transaction,
  instanceId,
  carrierCount,
  roleLayout,
}) {
  exact(
    value,
    [
      'accepted',
      'index',
      'metrics',
      'outpoint',
      'role',
      'sourceOutput',
      'sourceTransaction',
      'unlockingBytecodeBytes',
    ],
    `VM input ${index}`,
  );
  if (
    value.index !== index ||
    value.accepted !== true
  ) {
    fail(
      'INPUT_TOPOLOGY_MISMATCH',
      `VM input ${index} index, role, or acceptance is invalid`,
    );
  }
  const role = normalizeRole(
    value.role,
    roleLayout[index],
    `VM input ${index} role`,
  );
  exact(value.outpoint, ['txid', 'vout'], `input ${index} outpoint`);
  const transactionInput = transaction.inputs[index];
  if (
    value.outpoint.txid !== transactionInput.outpoint.txid ||
    value.outpoint.vout !== transactionInput.outpoint.vout
  ) {
    fail(
      'SOURCE_OUTPOINT_MISMATCH',
      `input ${index} evidence outpoint differs from the signed transaction`,
    );
  }
  if (
    value.unlockingBytecodeBytes !==
    transactionInput.unlockingBytecodeBytes
  ) {
    fail(
      'UNLOCKING_SIZE_MISMATCH',
      `input ${index} evidence unlocking size differs from serialized bytes`,
    );
  }
  const authenticated = validateNormalizedSourceTransaction(
    value.sourceTransaction,
    index,
    transactionInput.outpoint,
  );
  const sourceOutput = validateNormalizedSourceOutput(
    value.sourceOutput,
    index,
    instanceId,
    authenticated.sourceOutput,
    carrierCount,
  );
  return Object.freeze({
    index,
    role,
    outpoint: Object.freeze({
      txid: transactionInput.outpoint.txid,
      vout: transactionInput.outpoint.vout,
    }),
    sourceTransaction: authenticated.sourceTransaction,
    sourceOutput,
    accepted: true,
    unlockingBytecodeBytes: transactionInput.unlockingBytecodeBytes,
    metrics: normalizeMetrics(
      value.metrics,
      index,
      transactionInput.unlockingBytecodeBytes,
    ),
  });
}

function evidenceCore(value, { allowHash }) {
  exact(
    value,
    [
      'allInputsAccepted',
      ...(allowHash ? ['evidenceHash'] : []),
      'carrierCount',
      'inputRoleLayout',
      'inputs',
      'instanceId',
      'schema',
      'tool',
      'transaction',
    ],
    'VM evidence',
  );
  if (value.schema !== V2_VM_EVIDENCE_SCHEMA) {
    fail('INVALID_VM_EVIDENCE', 'VM evidence schema is unsupported');
  }
  const carrierCount = integer(
    value.carrierCount,
    1,
    255,
    'VM evidence carrierCount',
  );
  const inputRoleLayout = normalizeRoleLayout(
    value.inputRoleLayout,
    carrierCount,
  );
  const instanceId = hex32(value.instanceId, 'VM evidence instanceId');
  const tool = normalizeTool(value.tool);
  exact(
    value.transaction,
    ['inputCount', 'rawTransactionHex', 'serializedBytes', 'txid'],
    'VM evidence transaction',
  );
  const transaction = assertV2StandardTransactionEnvelope(
    parseV2RawTransaction(value.transaction.rawTransactionHex),
    { carrierCount },
  );
  if (
    value.transaction.txid !== transaction.txid ||
    value.transaction.serializedBytes !== transaction.sizeBytes ||
    value.transaction.inputCount !== inputRoleLayout.length
  ) {
    fail(
      'VM_TRANSACTION_MISMATCH',
      'VM evidence transaction identity or input count is invalid',
    );
  }
  if (
    value.allInputsAccepted !== true ||
    !Array.isArray(value.inputs) ||
    value.inputs.length !== inputRoleLayout.length
  ) {
    fail(
      'PARTIAL_VM_ACCEPTANCE',
      `VM evidence must contain all-input acceptance for exactly ${inputRoleLayout.length} inputs`,
    );
  }
  const inputs = value.inputs.map((input, index) =>
    validateNormalizedInput({
      value: input,
      index,
      transaction,
      instanceId,
      carrierCount,
      roleLayout: inputRoleLayout,
    }),
  );
  const actualMetrics = evaluateExactStandardTransaction({
    transaction,
    inputs,
  });
  for (const [index, input] of inputs.entries()) {
    if (
      canonicalizeV2Evidence(input.metrics) !==
      canonicalizeV2Evidence(actualMetrics[index])
    ) {
      fail(
        'VM_METRICS_MISMATCH',
        `input ${index} evidence metrics differ from a fresh evaluation of the exact resolved transaction`,
      );
    }
  }
  const core = Object.freeze({
    schema: V2_VM_EVIDENCE_SCHEMA,
    carrierCount,
    inputRoleLayout,
    instanceId,
    transaction: Object.freeze({
      rawTransactionHex: transaction.rawTransactionHex,
      txid: transaction.txid,
      serializedBytes: transaction.sizeBytes,
      inputCount: inputRoleLayout.length,
    }),
    tool,
    allInputsAccepted: true,
    inputs: Object.freeze(inputs),
  });
  if (
    allowHash &&
    (typeof value.evidenceHash !== 'string' ||
      value.evidenceHash !== sha256Hex(canonicalizeV2Evidence(core)))
  ) {
    fail(
      'VM_EVIDENCE_HASH_MISMATCH',
      'VM evidence hash does not bind the canonical evidence',
    );
  }
  return Object.freeze({
    ...core,
    evidenceHash: sha256Hex(canonicalizeV2Evidence(core)),
  });
}

export function createV2LocalVmEvidence(value) {
  exact(
    value,
    ['carrierCount', 'inputs', 'instanceId', 'rawTransactionHex', 'tool'],
    'VM evidence producer input',
  );
  const carrierCount = integer(
    value.carrierCount,
    1,
    255,
    'VM evidence carrierCount',
  );
  const inputRoleLayout = createV2InputRoleLayout(carrierCount);
  const instanceId = hex32(value.instanceId, 'VM evidence instanceId');
  const transaction = assertV2StandardTransactionEnvelope(
    parseV2RawTransaction(value.rawTransactionHex),
    { carrierCount },
  );
  if (
    !Array.isArray(value.inputs) ||
    value.inputs.length !== inputRoleLayout.length
  ) {
    fail(
      'PARTIAL_VM_ACCEPTANCE',
      `VM evidence producer must supply exactly ${inputRoleLayout.length} input evaluations`,
    );
  }
  const producedInputs = value.inputs.map((input, index) =>
    normalizeProducedInput({
      value: input,
      index,
      transaction,
      instanceId,
      carrierCount,
      roleLayout: inputRoleLayout,
    }),
  );
  const actualMetrics = evaluateExactStandardTransaction({
    transaction,
    inputs: producedInputs,
  });
  const core = Object.freeze({
    schema: V2_VM_EVIDENCE_SCHEMA,
    carrierCount,
    inputRoleLayout,
    instanceId,
    transaction: Object.freeze({
      rawTransactionHex: transaction.rawTransactionHex,
      txid: transaction.txid,
      serializedBytes: transaction.sizeBytes,
      inputCount: inputRoleLayout.length,
    }),
    tool: normalizeTool(value.tool),
    allInputsAccepted: true,
    inputs: Object.freeze(
      producedInputs.map((input, index) =>
        Object.freeze({
          ...input,
          accepted: true,
          metrics: actualMetrics[index],
        }),
      ),
    ),
  });
  const evidence = Object.freeze({
    ...core,
    evidenceHash: sha256Hex(canonicalizeV2Evidence(core)),
  });
  return Buffer.from(canonicalizeV2Evidence(evidence), 'utf8');
}

export function inspectV2LocalVmEvidence(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
    fail(
      'LOCAL_VM_EVIDENCE_REQUIRED',
      'local VM evidence must be nonempty bytes',
    );
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('INVALID_VM_EVIDENCE', 'VM evidence is not valid UTF-8');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail('INVALID_VM_EVIDENCE', 'VM evidence is not valid JSON');
  }
  if (canonicalizeV2Evidence(value) !== text) {
    fail(
      'NON_CANONICAL_VM_EVIDENCE',
      'VM evidence must use exact canonical JSON bytes',
    );
  }
  return evidenceCore(value, { allowHash: true });
}
