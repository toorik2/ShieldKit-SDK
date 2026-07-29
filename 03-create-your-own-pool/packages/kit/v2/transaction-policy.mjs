import { createHash } from 'node:crypto';
import { readTokenPrefix } from '@bitauth/libauth';

export const V2_MAX_TRANSACTION_BYTES = 100_000;
export const V2_MAX_UNLOCKING_BYTECODE_BYTES = 10_000;
export const V2_MIN_CARRIER_COUNT = 1;
export const V2_MAX_CARRIER_COUNT = 255;

const HEX = /^[0-9a-f]+$/;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;

export class V2TransactionPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'V2TransactionPolicyError';
    this.code = code;
  }
}

const fail = (code, message) => {
  throw new V2TransactionPolicyError(code, message);
};

export function assertV2CarrierCount(value) {
  if (
    !Number.isSafeInteger(value) ||
    value < V2_MIN_CARRIER_COUNT ||
    value > V2_MAX_CARRIER_COUNT
  ) {
    fail(
      'INVALID_CARRIER_COUNT',
      `carrierCount must be an integer from ${V2_MIN_CARRIER_COUNT} through ${V2_MAX_CARRIER_COUNT}`,
    );
  }
  return value;
}

export function createV2InputRoleLayout(carrierCount) {
  const count = assertV2CarrierCount(carrierCount);
  return Object.freeze([
    ...Array.from({ length: count }, (_, ordinal) =>
      Object.freeze({
        index: ordinal,
        kind: 'verifier',
        ordinal,
      }),
    ),
    Object.freeze({
      index: count,
      kind: 'binding',
      ordinal: null,
    }),
    Object.freeze({
      index: count + 1,
      kind: 'state',
      ordinal: null,
    }),
    Object.freeze({
      index: count + 2,
      kind: 'funding',
      ordinal: null,
    }),
  ]);
}

export const sha256Hex = (value) =>
  createHash('sha256').update(value).digest('hex');

export const transactionId = (bytes) =>
  createHash('sha256')
    .update(createHash('sha256').update(bytes).digest())
    .digest()
    .reverse()
    .toString('hex');

export function readCompactUint(bytes, offset, label = 'compact uint') {
  if (!(bytes instanceof Uint8Array) || offset >= bytes.length) {
    fail('MALFORMED_SERIALIZATION', `truncated ${label}`);
  }
  const first = bytes[offset];
  if (first < 0xfd) return Object.freeze({ value: first, next: offset + 1 });
  const width = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + width > bytes.length) {
    fail('MALFORMED_SERIALIZATION', `truncated ${label}`);
  }
  let value = 0n;
  for (let index = 0; index < width; index += 1) {
    value |= BigInt(bytes[offset + 1 + index]) << BigInt(index * 8);
  }
  if (
    (first === 0xfd && value < 0xfdn) ||
    (first === 0xfe && value <= 0xffffn) ||
    (first === 0xff && value <= 0xffff_ffffn) ||
    value > BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    fail(
      'MALFORMED_SERIALIZATION',
      `${label} is non-canonical or too large`,
    );
  }
  return Object.freeze({ value: Number(value), next: offset + 1 + width });
}

function take(bytes, offset, count, label) {
  if (count < 0 || offset + count > bytes.length) {
    fail('MALFORMED_SERIALIZATION', `truncated ${label}`);
  }
  return Object.freeze({
    value: bytes.subarray(offset, offset + count),
    next: offset + count,
  });
}

function u32(bytes, offset, label) {
  const part = take(bytes, offset, 4, label);
  return Object.freeze({ value: part.value.readUInt32LE(0), next: part.next });
}

function u64(bytes, offset, label) {
  const part = take(bytes, offset, 8, label);
  return Object.freeze({ value: part.value.readBigUInt64LE(0), next: part.next });
}

export function parseV2RawTransaction(rawTransactionHex) {
  if (
    typeof rawTransactionHex !== 'string' ||
    rawTransactionHex.length === 0 ||
    rawTransactionHex.length % 2 !== 0 ||
    !HEX.test(rawTransactionHex)
  ) {
    fail(
      'MALFORMED_TRANSACTION',
      'raw transaction must be nonempty lowercase even-length hex',
    );
  }
  const bytes = Buffer.from(rawTransactionHex, 'hex');
  let cursor = 0;
  let part = u32(bytes, cursor, 'transaction version');
  const version = part.value;
  cursor = part.next;
  let count = readCompactUint(bytes, cursor, 'input count');
  cursor = count.next;
  if (count.value === 0) {
    fail('MALFORMED_TRANSACTION', 'transaction must contain an input');
  }
  const inputs = [];
  for (let index = 0; index < count.value; index += 1) {
    part = take(bytes, cursor, 32, `input ${index} transaction id`);
    cursor = part.next;
    const previousTransactionId = Buffer.from(part.value)
      .reverse()
      .toString('hex');
    part = u32(bytes, cursor, `input ${index} output index`);
    cursor = part.next;
    const previousOutputIndex = part.value;
    const length = readCompactUint(
      bytes,
      cursor,
      `input ${index} unlocking bytecode length`,
    );
    cursor = length.next;
    part = take(
      bytes,
      cursor,
      length.value,
      `input ${index} unlocking bytecode`,
    );
    cursor = part.next;
    const unlockingBytecode = Buffer.from(part.value);
    part = u32(bytes, cursor, `input ${index} sequence`);
    cursor = part.next;
    inputs.push(
      Object.freeze({
        index,
        outpoint: Object.freeze({
          txid: previousTransactionId,
          vout: previousOutputIndex,
        }),
        sequence: part.value,
        unlockingBytecode,
        unlockingBytecodeBytes: unlockingBytecode.length,
      }),
    );
  }
  count = readCompactUint(bytes, cursor, 'output count');
  cursor = count.next;
  if (count.value === 0) {
    fail('MALFORMED_TRANSACTION', 'transaction must contain an output');
  }
  const outputs = [];
  for (let index = 0; index < count.value; index += 1) {
    const serializedOffset = cursor;
    part = u64(bytes, cursor, `output ${index} value`);
    cursor = part.next;
    if (part.value > MAX_MONEY_SATS) {
      fail('MALFORMED_TRANSACTION', `output ${index} value exceeds BCH supply`);
    }
    const valueSatoshis = part.value;
    const length = readCompactUint(
      bytes,
      cursor,
      `output ${index} locking bytecode length`,
    );
    cursor = length.next;
    part = take(
      bytes,
      cursor,
      length.value,
      `output ${index} locking bytecode`,
    );
    cursor = part.next;
    outputs.push(
      Object.freeze({
        index,
        valueSatoshis,
        lockingBytecode: Buffer.from(part.value),
        serializedHex: bytes
          .subarray(serializedOffset, cursor)
          .toString('hex'),
      }),
    );
  }
  part = u32(bytes, cursor, 'transaction locktime');
  cursor = part.next;
  if (cursor !== bytes.length) {
    fail('MALFORMED_TRANSACTION', 'trailing transaction bytes are forbidden');
  }
  return Object.freeze({
    bytes: Buffer.from(bytes),
    rawTransactionHex,
    sizeBytes: bytes.length,
    txid: transactionId(bytes),
    version,
    locktime: part.value,
    inputs: Object.freeze(inputs),
    outputs: Object.freeze(outputs),
  });
}

export function assertV2StandardTransactionEnvelope(
  transaction,
  { carrierCount = undefined } = {},
) {
  if (transaction.sizeBytes > V2_MAX_TRANSACTION_BYTES) {
    fail(
      'TRANSACTION_SIZE_LIMIT',
      `serialized transaction is ${transaction.sizeBytes} bytes; maximum is ${V2_MAX_TRANSACTION_BYTES}`,
    );
  }
  if (carrierCount !== undefined) {
    const expectedInputCount =
      createV2InputRoleLayout(carrierCount).length;
    if (transaction.inputs.length !== expectedInputCount) {
      fail(
        'INPUT_TOPOLOGY_MISMATCH',
        `carrierCount ${carrierCount} requires exactly ${expectedInputCount} inputs`,
      );
    }
  }
  const outpoints = new Set();
  for (const input of transaction.inputs) {
    const outpointKey = `${input.outpoint.txid}:${input.outpoint.vout}`;
    if (outpoints.has(outpointKey)) {
      fail(
        'DUPLICATE_INPUT_OUTPOINT',
        `input ${input.index} duplicates an earlier source outpoint`,
      );
    }
    outpoints.add(outpointKey);
    if (
      input.unlockingBytecodeBytes > V2_MAX_UNLOCKING_BYTECODE_BYTES
    ) {
      fail(
        'UNLOCKING_BYTECODE_LIMIT',
        `input ${input.index} unlocking bytecode is ${input.unlockingBytecodeBytes} bytes; maximum is ${V2_MAX_UNLOCKING_BYTECODE_BYTES}`,
      );
    }
  }
  return transaction;
}

export function parseSerializedSourceOutput(serializedHex) {
  if (
    typeof serializedHex !== 'string' ||
    serializedHex.length < 18 ||
    serializedHex.length % 2 !== 0 ||
    !HEX.test(serializedHex)
  ) {
    fail(
      'MALFORMED_SOURCE_OUTPUT',
      'source output must be canonical lowercase serialized hex',
    );
  }
  const bytes = Buffer.from(serializedHex, 'hex');
  const value = u64(bytes, 0, 'source output value');
  if (value.value > MAX_MONEY_SATS) {
    fail('MALFORMED_SOURCE_OUTPUT', 'source output value exceeds BCH supply');
  }
  const length = readCompactUint(
    bytes,
    value.next,
    'source output contents length',
  );
  const contents = take(
    bytes,
    length.next,
    length.value,
    'source output contents',
  );
  if (contents.next !== bytes.length) {
    fail(
      'MALFORMED_SOURCE_OUTPUT',
      'source output has trailing bytes',
    );
  }
  // Libauth decodes transaction hashes/categories using in-place reversal of
  // the provided view. Preserve the authenticated wire bytes before parsing.
  const rawContents = Buffer.from(contents.value);
  const tokenRead = readTokenPrefix({
    bin: Buffer.from(rawContents),
    index: 0,
  });
  if (typeof tokenRead === 'string') {
    fail('MALFORMED_SOURCE_OUTPUT', `invalid CashToken prefix: ${tokenRead}`);
  }
  const tokenValue = tokenRead.result.token;
  const token =
    tokenValue === undefined
      ? null
      : Object.freeze({
          categoryWire: Buffer.from(rawContents.subarray(1, 33)).toString(
            'hex',
          ),
          amount: tokenValue.amount.toString(),
          nft:
            tokenValue.nft === undefined
              ? null
              : Object.freeze({
                  capability: tokenValue.nft.capability,
                  commitmentHex: Buffer.from(
                    tokenValue.nft.commitment,
                  ).toString('hex'),
                }),
        });
  const lockingBytecode = Buffer.from(
    rawContents.subarray(tokenRead.position.index),
  );
  return Object.freeze({
    serializedHex,
    sha256: sha256Hex(bytes),
    valueSatoshis: value.value,
    lockingBytecode,
    lockingBytecodeHex: lockingBytecode.toString('hex'),
    tokenPrefixHex: rawContents
      .subarray(0, tokenRead.position.index)
      .toString('hex'),
    token,
  });
}

export function assertV2SourceOutputTopology({
  index,
  sourceOutput,
  instanceId,
  carrierCount,
}) {
  const role = createV2InputRoleLayout(carrierCount)[index];
  if (role === undefined) {
    fail('INPUT_TOPOLOGY_MISMATCH', `input ${index} has no V2 role`);
  }
  if (
    ['verifier', 'binding'].includes(role.kind) &&
    sourceOutput.token !== null
  ) {
    fail(
      'TOKEN_ROLE_MISMATCH',
      `${role.kind} source output must be tokenless`,
    );
  }
  if (role.kind === 'state') {
    const token = sourceOutput.token;
    if (
      token === null ||
      token.categoryWire !== instanceId ||
      token.amount !== '0' ||
      token.nft?.capability !== 'mutable' ||
      token.nft.commitmentHex.length !== 256
    ) {
      fail(
        'STATE_TOKEN_MISMATCH',
        'state input must carry the exact instance mutable NFT with a 128-byte commitment and no fungible amount',
      );
    }
  }
  if (role.kind === 'funding') {
    if (sourceOutput.token !== null) {
      fail('UNSAFE_FUNDING_INPUT', 'funding input must be tokenless');
    }
    if (
      !/^76a914[0-9a-f]{40}88ac$/.test(sourceOutput.lockingBytecodeHex)
    ) {
      fail('UNSAFE_FUNDING_INPUT', 'funding input must be canonical P2PKH');
    }
  }
  return role;
}
