import { createHash } from 'node:crypto';
import { encodeTransaction } from '@bitauth/libauth';
import { DENOMINATION_SATS } from '../action-packet/action-packet.mjs';

export const PREPARATION_TRANSACTION_WIRE_LIMIT_BYTES = 59_000;
export const PROJECT_P2S_LOCKING_LIMIT_BYTES = 190;
export const P2PKH_DUST_FLOOR_SATOSHIS = 546n;

const HEX = /^[0-9a-f]*$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class PreparationTransactionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PreparationTransactionError';
  }
}

const fail = (message) => {
  throw new PreparationTransactionError(message);
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

function decimal(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}

function hexBytes(value, length, label) {
  if (
    typeof value !== 'string'
    || !HEX.test(value)
    || value.length % 2 !== 0
    || (length !== undefined && value.length !== length * 2)
  ) {
    fail(`${label} must be canonical lowercase hexadecimal`);
  }
  return Buffer.from(value, 'hex');
}

function hash160(bytes) {
  const sha = createHash('sha256').update(bytes).digest();
  return createHash('ripemd160').update(sha).digest();
}

function hash256(bytes) {
  return createHash('sha256')
    .update(createHash('sha256').update(bytes).digest())
    .digest();
}

function p2pkhLock(publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    hash160(publicKey),
    Buffer.from([0x88, 0xac]),
  ]);
}

function schnorrUnlock(signature, publicKey) {
  return Buffer.concat([
    Buffer.from([0x41]),
    signature,
    Buffer.from([0x41, 0x21]),
    publicKey,
  ]);
}

function parsePlan(value) {
  exactKeys(value, 'preparation plan', [
    'bindingCarrierBaseValueSatoshis',
    'bindingLockingBytecode',
    'fundingOutpointIndex',
    'fundingOutpointTransactionHashWire',
    'fundingPublicKey',
    'fundingSourceValueSatoshis',
    'kind',
    'minimumFeeRateSatoshisPerByte',
    'settlementFeeFundingSatoshis',
  ]);
  if (!['deposit', 'transfer', 'withdrawal'].includes(value.kind)) {
    fail('kind is unsupported');
  }
  const bindingBase = decimal(
    value.bindingCarrierBaseValueSatoshis,
    MAX_U64,
    'bindingCarrierBaseValueSatoshis',
  );
  if (bindingBase === 0n) fail('binding carrier base value must be positive');
  const bindingLock = hexBytes(
    value.bindingLockingBytecode,
    undefined,
    'bindingLockingBytecode',
  );
  if (
    bindingLock.length === 0
    || bindingLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES
  ) {
    fail('binding locking bytecode must contain 1 to 190 bytes');
  }
  const outpointWire = hexBytes(
    value.fundingOutpointTransactionHashWire,
    32,
    'fundingOutpointTransactionHashWire',
  );
  const outpointIndex = decimal(
    value.fundingOutpointIndex,
    MAX_U32,
    'fundingOutpointIndex',
  );
  const publicKey = hexBytes(value.fundingPublicKey, 33, 'fundingPublicKey');
  if (![0x02, 0x03].includes(publicKey[0])) {
    fail('fundingPublicKey must be compressed');
  }
  const sourceValue = decimal(
    value.fundingSourceValueSatoshis,
    MAX_U64,
    'fundingSourceValueSatoshis',
  );
  const settlementFeeFunding = decimal(
    value.settlementFeeFundingSatoshis,
    MAX_U64,
    'settlementFeeFundingSatoshis',
  );
  if (settlementFeeFunding < P2PKH_DUST_FLOOR_SATOSHIS) {
    fail('settlement fee funding output is below the project P2PKH dust floor');
  }
  const minimumFeeRate = decimal(
    value.minimumFeeRateSatoshisPerByte,
    MAX_U64,
    'minimumFeeRateSatoshisPerByte',
  );
  if (minimumFeeRate === 0n) fail('minimum fee rate must be positive');
  return {
    kind: value.kind,
    bindingBase,
    bindingLock,
    outpointWire,
    outpointIndex: Number(outpointIndex),
    publicKey,
    sourceValue,
    settlementFeeFunding,
    minimumFeeRate,
  };
}

function transactionFor(parsed, signature, changeValue) {
  const feeLock = p2pkhLock(parsed.publicKey);
  const bindingValue = parsed.bindingBase
    + (parsed.kind === 'deposit' ? DENOMINATION_SATS : 0n);
  return {
    version: 2,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(parsed.outpointWire).reverse(),
      outpointIndex: parsed.outpointIndex,
      sequenceNumber: 0,
      unlockingBytecode: schnorrUnlock(signature, parsed.publicKey),
    }],
    outputs: [
      {
        valueSatoshis: bindingValue,
        lockingBytecode: parsed.bindingLock,
      },
      {
        valueSatoshis: parsed.settlementFeeFunding,
        lockingBytecode: feeLock,
      },
      {
        valueSatoshis: changeValue,
        lockingBytecode: feeLock,
      },
    ],
    locktime: 0,
  };
}

function derivePlan(parsed) {
  const placeholderSignature = Buffer.alloc(64);
  const sizing = Buffer.from(encodeTransaction(
    transactionFor(parsed, placeholderSignature, P2PKH_DUST_FLOOR_SATOSHIS),
  ));
  const wireBytes = sizing.length;
  if (wireBytes > PREPARATION_TRANSACTION_WIRE_LIMIT_BYTES) {
    fail(`preparation transaction is ${wireBytes} bytes, exceeding 59000`);
  }
  const fee = BigInt(wireBytes) * parsed.minimumFeeRate;
  const bindingValue = parsed.bindingBase
    + (parsed.kind === 'deposit' ? DENOMINATION_SATS : 0n);
  const required = bindingValue + parsed.settlementFeeFunding + fee;
  if (parsed.sourceValue < required + P2PKH_DUST_FLOOR_SATOSHIS) {
    fail('funding source cannot create canonical preparation change');
  }
  const change = parsed.sourceValue - required;
  const transaction = transactionFor(parsed, placeholderSignature, change);
  const encoded = Buffer.from(encodeTransaction(transaction));
  if (encoded.length !== wireBytes) fail('preparation sizing changed after fee calculation');
  return {
    bindingValue,
    change,
    fee,
    feeLock: p2pkhLock(parsed.publicKey),
    transaction,
    wireBytes,
  };
}

export function planPreparationTransaction(value) {
  const parsed = parsePlan(value);
  const plan = derivePlan(parsed);
  return Object.freeze({
    schema: 'shield.cash/preparation-transaction-plan/v1',
    kind: parsed.kind,
    unsignedTransaction: Object.freeze({
      ...plan.transaction,
      inputs: Object.freeze([Object.freeze({
        ...plan.transaction.inputs[0],
        unlockingBytecode: new Uint8Array(),
      })]),
      outputs: Object.freeze(plan.transaction.outputs.map(Object.freeze)),
    }),
    sourceOutput: Object.freeze({
      valueSatoshis: parsed.sourceValue,
      lockingBytecode: plan.feeLock,
    }),
    outputValues: Object.freeze({
      bindingSatoshis: plan.bindingValue.toString(),
      settlementFeeFundingSatoshis: parsed.settlementFeeFunding.toString(),
      preparationChangeSatoshis: plan.change.toString(),
    }),
    measurements: Object.freeze({
      plannedSignedWireBytes: plan.wireBytes,
      feeSatoshis: plan.fee.toString(),
      minimumFeeRateSatoshisPerByte: parsed.minimumFeeRate.toString(),
      signatureBytes: 64,
      finalUnlockingBytes: 100,
    }),
  });
}

export function finalizePreparationTransaction(value, signatureHex) {
  const parsed = parsePlan(value);
  const signature = hexBytes(signatureHex, 64, 'signature');
  const plan = derivePlan(parsed);
  const transaction = transactionFor(parsed, signature, plan.change);
  const encodedTransaction = Buffer.from(encodeTransaction(transaction));
  if (encodedTransaction.length !== plan.wireBytes) {
    fail('final signature changed the planned transaction size');
  }
  const transactionHashWire = hash256(encodedTransaction);
  return Object.freeze({
    schema: 'shield.cash/preparation-transaction/v1',
    kind: parsed.kind,
    transaction,
    encodedTransaction,
    transactionHex: encodedTransaction.toString('hex'),
    transactionId: Buffer.from(transactionHashWire).reverse().toString('hex'),
    settlementOutpoints: Object.freeze({
      binding: Object.freeze({
        outpointTransactionHashWire: transactionHashWire.toString('hex'),
        outpointIndex: '0',
      }),
      fee: Object.freeze({
        outpointTransactionHashWire: transactionHashWire.toString('hex'),
        outpointIndex: '1',
      }),
    }),
    sourceOutput: Object.freeze({
      valueSatoshis: parsed.sourceValue,
      lockingBytecode: plan.feeLock,
    }),
    outputValues: Object.freeze({
      bindingSatoshis: plan.bindingValue.toString(),
      settlementFeeFundingSatoshis: parsed.settlementFeeFunding.toString(),
      preparationChangeSatoshis: plan.change.toString(),
    }),
    measurements: Object.freeze({
      wireBytes: encodedTransaction.length,
      feeSatoshis: plan.fee.toString(),
      minimumFeeSatoshis: plan.fee.toString(),
      maximumUnlockingBytes: 100,
      completeTransactionWireLimitBytes: PREPARATION_TRANSACTION_WIRE_LIMIT_BYTES,
      percentageHeadroomRequired: false,
    }),
  });
}
