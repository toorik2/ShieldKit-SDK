import { createHash } from 'node:crypto';

import { isSupportedDirectV2NetworkId } from './network.mjs';
import { ACTION_KIND_CODES } from './packet.mjs';

export const DIRECT_V2_CONTEXT_HEADER_BYTES = 100;
export const DIRECT_V2_CONTEXT_INPUT_BYTES = 116;
export const DIRECT_V2_CONTEXT_OUTPUT_BYTES = 76;

export const DIRECT_V2_ROLE_CODES = Object.freeze({
  verifier: 1,
  binding: 2,
  state: 3,
  funding: 4,
  withdrawal: 5,
  change: 6,
});

const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const MAX_VECTOR_BYTES = 10_000;
const INPUT_KEYS = Object.freeze([
  'role',
  'outpointTransactionHash',
  'outpointIndex',
  'sequence',
  'valueSats',
  'lockingBytecode',
  'tokenPrefix',
]);
const OUTPUT_KEYS = Object.freeze([
  'role',
  'valueSats',
  'lockingBytecode',
  'tokenPrefix',
]);

export class DirectV2ContextError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2ContextError';
  }
}

const fail = (message) => {
  throw new DirectV2ContextError(message);
};

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length
    || actual.some((key, index) => key !== wanted[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
}

function uint(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(`${label} must be 32 lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function vector(value, label) {
  if (!(value instanceof Uint8Array) || value.length > MAX_VECTOR_BYTES) {
    fail(`${label} must be a Uint8Array of at most ${MAX_VECTOR_BYTES} bytes`);
  }
  return Buffer.from(value);
}

function hash(value) {
  return createHash('sha256').update(value).digest();
}

function u16le(value) {
  const bytes = Buffer.alloc(2);
  bytes.writeUInt16LE(value);
  return bytes;
}

function u32le(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(Number(value));
  return bytes;
}

function u64le(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(value);
  return bytes;
}

function role(value, label) {
  exactKeys(value, label, ['kind', 'ordinal']);
  const code = DIRECT_V2_ROLE_CODES[value.kind];
  if (code === undefined) fail(`${label}.kind is unsupported`);
  const ordinal = uint(value.ordinal, 0xffn, `${label}.ordinal`);
  if (value.kind !== 'verifier' && ordinal !== 0n) {
    fail(`${label}.ordinal must be zero for a non-verifier role`);
  }
  return Object.freeze({ kind: value.kind, code, ordinal: Number(ordinal) });
}

function encodeRole(value) {
  return Buffer.from([value.code, value.ordinal, 0, 0]);
}

function normalizeInput(value, index) {
  const label = `input ${index}`;
  exactKeys(value, label, INPUT_KEYS);
  return Object.freeze({
    role: role(value.role, `${label}.role`),
    outpointTransactionHash: identifier(
      value.outpointTransactionHash,
      `${label}.outpointTransactionHash`,
    ),
    outpointIndex: uint(value.outpointIndex, MAX_U32, `${label}.outpointIndex`),
    sequence: uint(value.sequence, MAX_U32, `${label}.sequence`),
    valueSats: uint(value.valueSats, MAX_U64, `${label}.valueSats`),
    lockingBytecode: vector(value.lockingBytecode, `${label}.lockingBytecode`),
    tokenPrefix: vector(value.tokenPrefix, `${label}.tokenPrefix`),
  });
}

function normalizeOutput(value, index) {
  const label = `output ${index}`;
  exactKeys(value, label, OUTPUT_KEYS);
  return Object.freeze({
    role: role(value.role, `${label}.role`),
    valueSats: uint(value.valueSats, MAX_U64, `${label}.valueSats`),
    lockingBytecode: vector(value.lockingBytecode, `${label}.lockingBytecode`),
    tokenPrefix: vector(value.tokenPrefix, `${label}.tokenPrefix`),
  });
}

function normalizeContext(value) {
  exactKeys(value, 'transaction context', [
    'networkId',
    'kind',
    'profileId',
    'instanceId',
    'transactionVersion',
    'locktime',
    'preActionSequence',
    'postActionSequence',
    'inputs',
    'outputs',
  ]);
  if (!isSupportedDirectV2NetworkId(value.networkId)) fail('transaction context network is unsupported');
  if (ACTION_KIND_CODES[value.kind] === undefined) fail('transaction context kind is unsupported');
  if (!Array.isArray(value.inputs) || value.inputs.length === 0 || value.inputs.length > 0xffff) {
    fail('transaction context inputs must be a nonempty u16-sized array');
  }
  if (!Array.isArray(value.outputs) || value.outputs.length === 0 || value.outputs.length > 0xffff) {
    fail('transaction context outputs must be a nonempty u16-sized array');
  }
  const preActionSequence = uint(
    value.preActionSequence,
    MAX_U64,
    'preActionSequence',
  );
  const postActionSequence = uint(
    value.postActionSequence,
    MAX_U64,
    'postActionSequence',
  );
  if (postActionSequence !== preActionSequence + 1n) {
    fail('postActionSequence must increment preActionSequence by one');
  }
  return Object.freeze({
    networkId: value.networkId,
    kind: value.kind,
    profileId: identifier(value.profileId, 'profileId'),
    instanceId: identifier(value.instanceId, 'instanceId'),
    transactionVersion: uint(value.transactionVersion, MAX_U32, 'transactionVersion'),
    locktime: uint(value.locktime, MAX_U32, 'locktime'),
    preActionSequence,
    postActionSequence,
    inputs: Object.freeze(value.inputs.map(normalizeInput)),
    outputs: Object.freeze(value.outputs.map(normalizeOutput)),
  });
}

function hasNoToken(record) {
  return record.tokenPrefix.length === 0;
}

function assertRole(actual, expectedKind, expectedOrdinal, label) {
  if (
    actual.role.kind !== expectedKind
    || actual.role.ordinal !== expectedOrdinal
  ) {
    fail(`${label} has the wrong role`);
  }
}

export function validateDirectV2RoleTopology(value, carrierCount) {
  const context = normalizeContext(value);
  if (!Number.isInteger(carrierCount) || carrierCount < 1 || carrierCount > 0xff) {
    fail('carrierCount must be an integer from 1 to 255');
  }
  const expectedInputs = carrierCount + 3;
  const expectedOutputs = carrierCount + (context.kind === 'withdrawal' ? 4 : 3);
  if (context.inputs.length !== expectedInputs) fail('transaction context input count is wrong');
  if (context.outputs.length !== expectedOutputs) fail('transaction context output count is wrong');

  for (let index = 0; index < carrierCount; index += 1) {
    assertRole(context.inputs[index], 'verifier', index, `input ${index}`);
    assertRole(context.outputs[index + 1], 'verifier', index, `output ${index + 1}`);
    if (!hasNoToken(context.inputs[index]) || !hasNoToken(context.outputs[index + 1])) {
      fail('verifier carriers must be tokenless');
    }
  }
  assertRole(context.inputs[carrierCount], 'binding', 0, 'binding input');
  assertRole(context.inputs[carrierCount + 1], 'state', 0, 'state input');
  assertRole(context.inputs[carrierCount + 2], 'funding', 0, 'funding input');
  assertRole(context.outputs[0], 'state', 0, 'state output');
  assertRole(context.outputs[carrierCount + 1], 'binding', 0, 'binding output');
  for (const record of [
    context.inputs[carrierCount],
    context.inputs[carrierCount + 2],
    context.outputs[carrierCount + 1],
  ]) {
    if (!hasNoToken(record)) fail('binding and funding roles must be tokenless');
  }
  if (hasNoToken(context.inputs[carrierCount + 1]) || hasNoToken(context.outputs[0])) {
    fail('state roles must carry the state token prefix');
  }
  if (context.kind === 'withdrawal') {
    assertRole(context.outputs[carrierCount + 2], 'withdrawal', 0, 'withdrawal output');
    assertRole(context.outputs[carrierCount + 3], 'change', 0, 'change output');
    if (
      !hasNoToken(context.outputs[carrierCount + 2])
      || !hasNoToken(context.outputs[carrierCount + 3])
    ) {
      fail('withdrawal and change outputs must be tokenless');
    }
  } else {
    assertRole(context.outputs[carrierCount + 2], 'change', 0, 'change output');
    if (!hasNoToken(context.outputs[carrierCount + 2])) {
      fail('change output must be tokenless');
    }
  }
  return context;
}

export function encodeDirectV2TransactionContext(value, { carrierCount } = {}) {
  const context = carrierCount === undefined
    ? normalizeContext(value)
    : validateDirectV2RoleTopology(value, carrierCount);
  const header = Buffer.concat([
    Buffer.from('SDC2', 'ascii'),
    Buffer.from([context.networkId, ACTION_KIND_CODES[context.kind]]),
    Buffer.alloc(2),
    context.profileId,
    context.instanceId,
    u32le(context.transactionVersion),
    u32le(context.locktime),
    u16le(context.inputs.length),
    u16le(context.outputs.length),
    u64le(context.preActionSequence),
    u64le(context.postActionSequence),
  ]);
  if (header.length !== DIRECT_V2_CONTEXT_HEADER_BYTES) {
    fail('internal transaction context header size mismatch');
  }
  const inputs = context.inputs.map((input) => {
    const encoded = Buffer.concat([
      encodeRole(input.role),
      input.outpointTransactionHash,
      u32le(input.outpointIndex),
      u32le(input.sequence),
      u64le(input.valueSats),
      hash(input.lockingBytecode),
      hash(input.tokenPrefix),
    ]);
    if (encoded.length !== DIRECT_V2_CONTEXT_INPUT_BYTES) {
      fail('internal transaction context input size mismatch');
    }
    return encoded;
  });
  const outputs = context.outputs.map((output) => {
    const encoded = Buffer.concat([
      encodeRole(output.role),
      u64le(output.valueSats),
      hash(output.lockingBytecode),
      hash(output.tokenPrefix),
    ]);
    if (encoded.length !== DIRECT_V2_CONTEXT_OUTPUT_BYTES) {
      fail('internal transaction context output size mismatch');
    }
    return encoded;
  });
  return Buffer.concat([header, ...inputs, ...outputs]);
}

export function hashDirectV2TransactionContext(value, options) {
  return hash(encodeDirectV2TransactionContext(value, options));
}
