import { createHash } from 'node:crypto';
import {
  encodeDataPush,
  encodeTransaction,
  generateSigningSerializationBch,
  hash160,
  hash256,
  secp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';

import {
  encodeDirectV2BindingUnlock,
  verifyDirectV2BindingP2sh32Lock,
} from './binding-unlock.mjs';
import {
  hashDirectV2TransactionContext,
} from './context.mjs';
import {
  ACTION_PACKET_BYTES,
  decodeActionPacket,
} from './packet.mjs';
import {
  encodeStateNftCommitment,
  MAX_MONEY_SATS,
} from './state.mjs';
import {
  deriveV2RollingBaseSats,
} from './dust-policy.mjs';
import {
  DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES,
  resolveDirectV2VerifierTopology,
} from './topology.mjs';
import {
  validateDirectV2RollingBundle,
} from './rolling-bundle.mjs';
import {
  assertV2SourceOutputTopology,
  assertV2StandardTransactionEnvelope,
  parseSerializedSourceOutput,
  parseV2RawTransaction,
  transactionId,
  V2_MAX_TRANSACTION_BYTES,
  V2_MAX_UNLOCKING_BYTECODE_BYTES,
} from '../../kit/v2/transaction-policy.mjs';
import {
  canonicalizeV2Evidence,
  inspectV2LocalVmEvidence,
} from '../../kit/v2/vm-evidence.mjs';

export const PF11_CARRIER_COUNT = 11;
export const PF11_INPUT_COUNT = 14;
export const PF11_DEPOSIT_TRANSFER_OUTPUT_COUNT = 14;
export const PF11_WITHDRAWAL_OUTPUT_COUNT = 15;
export const PF11_TRANSACTION_VERSION = 2;
export const PF11_INPUT_SEQUENCE = 0;
export const PF11_LOCKTIME = 0;
export const PF11_DEFAULT_FEE_RATE_SATS_PER_BYTE = '1';
export const V2_MAX_FEE_RATE_SATS_PER_BYTE = MAX_MONEY_SATS.toString();
export const PF11_MAX_FEE_RATE_SATS_PER_BYTE =
  V2_MAX_FEE_RATE_SATS_PER_BYTE;
export const PF11_P2PKH_DUST_SATS = '546';
export const PF11_FUNDING_INPUT_INDEX = 13;
export const PF11_BINDING_INPUT_INDEX = 11;
export const PF11_STATE_INPUT_INDEX = 12;
export const V2_FUNDING_SIGHASH_TYPE =
  SigningSerializationTypeBch.allOutputsAllUtxos;
// Compatibility export for the PF11 semantic-oracle tests. Settlement
// construction derives the funding index from the signed topology, while the
// 0x61 signing contract is common to every supported direct-V2 topology.
export const PF11_SIGHASH_TYPE = V2_FUNDING_SIGHASH_TYPE;
export const PF11_PREPARED_SCHEMA =
  'shieldkit/v2-direct-settlement-prepared/v1';
export const PF11_ASSEMBLED_SCHEMA =
  'shieldkit/v2-direct-settlement-assembled/v1';
export const PF11_SIGNED_SCHEMA =
  'shieldkit/v2-direct-settlement-signed/v1';

export const PF11_VERIFIER_ROLES =
  DIRECT_V2_PF11_ORACLE_VERIFIER_ROLES;

const HEX = /^[0-9a-f]*$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const KINDS = new Set(['deposit', 'transfer', 'withdrawal']);
const PREPARE_KEYS = Object.freeze([
  'changeLockingBytecode',
  'denominationSats',
  'funding',
  'instanceId',
  'kind',
  'networkId',
  'payoutLockingBytecode',
  'pins',
  'postState',
  'preState',
  'previousBundleTransactionHex',
  'profileId',
  'unlockingBytecodeLengths',
]);
const OPTIONAL_PREPARE_KEYS = Object.freeze(['feeRateSatsPerByte']);

export class Pf11SettlementError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'Pf11SettlementError';
    this.code = code;
  }
}

const fail = (code, message, options) => {
  throw new Pf11SettlementError(code, message, options);
};

function exactKeys(value, label, expected, optional = []) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('INVALID_SETTLEMENT', `${label} must be a plain object`);
  }
  const allowed = new Set([...expected, ...optional]);
  const actual = Object.keys(value);
  if (
    expected.some((key) => !Object.hasOwn(value, key))
    || actual.some((key) => !allowed.has(key))
  ) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} has missing or unknown properties`,
    );
  }
  return value;
}

function decimal(value, maximum, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be a canonical unsigned decimal string`,
    );
  }
  const parsed = BigInt(value);
  if (parsed > maximum) {
    fail('INVALID_SETTLEMENT', `${label} exceeds its range`);
  }
  return parsed;
}

function integer(value, low, high, label) {
  if (!Number.isSafeInteger(value) || value < low || value > high) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be an integer from ${low} through ${high}`,
    );
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be 32 lowercase hexadecimal bytes`,
    );
  }
  return value;
}

function rawHex(value, label) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length % 2 !== 0
    || !HEX.test(value)
  ) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be nonempty lowercase even-length hexadecimal`,
    );
  }
  return value;
}

function exactHex(value, bytes, label) {
  if (
    typeof value !== 'string'
    || value.length !== bytes * 2
    || !HEX.test(value)
  ) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be ${bytes} lowercase hexadecimal bytes`,
    );
  }
  return value;
}

function bytecode(value, label, { allowEmpty = false } = {}) {
  if (
    !(value instanceof Uint8Array)
    || (!allowEmpty && value.length === 0)
    || value.length > V2_MAX_UNLOCKING_BYTECODE_BYTES
  ) {
    fail(
      'INVALID_SETTLEMENT',
      `${label} must be ${
        allowEmpty ? '' : 'nonempty '
      }bytecode of at most ${V2_MAX_UNLOCKING_BYTECODE_BYTES} bytes`,
    );
  }
  return Buffer.from(value);
}

function bytecodeHex(value, label, options) {
  if (
    typeof value !== 'string'
    || value.length % 2 !== 0
    || !HEX.test(value)
  ) {
    fail('INVALID_SETTLEMENT', `${label} must be lowercase bytecode hex`);
  }
  return bytecode(Buffer.from(value, 'hex'), label, options);
}

function canonicalBindingUnlock(packet, redeem, sourceLockingBytecode) {
  try {
    return encodeDirectV2BindingUnlock({
      packet: Buffer.from(packet),
      redeemScript: Buffer.from(redeem),
      sourceLockingBytecode: Buffer.from(sourceLockingBytecode),
    });
  } catch (error) {
    fail(
      /exceeds (?:10,000|10000) bytes/.test(
        error instanceof Error ? error.message : '',
      )
        ? 'UNLOCKING_SIZE_MISMATCH'
        : 'BINDING_REDEEM_MISMATCH',
      `binding unlock is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

function p2pkh(value, label) {
  const bytes = bytecode(value, label);
  if (
    bytes.length !== 25
    || bytes[0] !== 0x76
    || bytes[1] !== 0xa9
    || bytes[2] !== 0x14
    || bytes[23] !== 0x88
    || bytes[24] !== 0xac
  ) {
    fail(
      'INVALID_P2PKH',
      `${label} must be canonical P2PKH locking bytecode`,
    );
  }
  return bytes;
}

function publicKey(value, label) {
  const bytes = bytecode(value, label);
  if (bytes.length !== 33 || ![0x02, 0x03].includes(bytes[0])) {
    fail(
      'INVALID_FUNDING_PUBLIC_KEY',
      `${label} must be a compressed 33-byte secp256k1 public key`,
    );
  }
  if (!secp256k1.validatePublicKey(bytes)) {
    fail(
      'INVALID_FUNDING_PUBLIC_KEY',
      `${label} is not a valid secp256k1 public key`,
    );
  }
  return bytes;
}

function p2pkhForPublicKey(key) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(key)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function sha256(value) {
  return createHash('sha256').update(value).digest();
}

function sha256Hex(value) {
  return sha256(value).toString('hex');
}

function hashEnvelopePayload(payload) {
  return sha256Hex(Buffer.from(payload, 'utf8'));
}

function canonical(value) {
  return canonicalizeV2Evidence(value);
}

function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function sameState(left, right) {
  return canonical(left) === canonical(right);
}

function wireHash(displayTxid) {
  return Buffer.from(displayTxid, 'hex').reverse().toString('hex');
}

function role(kind, ordinal = 0) {
  return Object.freeze({ kind, ordinal: String(ordinal) });
}

function parsedTokenToBundle(token) {
  if (token === null) return null;
  if (token.nft === null) {
    fail(
      'UNSAFE_TOKEN_TOPOLOGY',
      'PF11 settlement roles may not carry fungible-only tokens',
    );
  }
  return {
    category: token.categoryWire,
    amount: token.amount,
    nft: {
      capability: token.nft.capability,
      commitment: Buffer.from(token.nft.commitmentHex, 'hex'),
    },
  };
}

function parsedOutputToLibauth(output) {
  const normalized = {
    valueSatoshis: output.valueSatoshis,
    lockingBytecode: Uint8Array.from(output.lockingBytecode),
  };
  if (output.token !== null) {
    normalized.token = {
      category: Uint8Array.from(
        Buffer.from(output.token.categoryWire, 'hex').reverse(),
      ),
      amount: BigInt(output.token.amount),
      ...(output.token.nft === null
        ? {}
        : {
            nft: {
              capability: output.token.nft.capability,
              commitment: Uint8Array.from(
                Buffer.from(output.token.nft.commitmentHex, 'hex'),
              ),
            },
          }),
    };
  }
  return normalized;
}

function bundleOutputToLibauth(output) {
  const normalized = {
    valueSatoshis: BigInt(output.valueSats),
    lockingBytecode: Uint8Array.from(output.lockingBytecode),
  };
  if (output.token !== null) {
    normalized.token = {
      // Bundle token categories are frozen in BCH token-prefix wire order.
      category: Uint8Array.from(
        Buffer.from(output.token.category, 'hex').reverse(),
      ),
      amount: BigInt(output.token.amount),
      nft: {
        capability: output.token.nft.capability,
        commitment: Uint8Array.from(output.token.nft.commitment),
      },
    };
  }
  return normalized;
}

function parseSourceTransaction(value, label) {
  try {
    return parseV2RawTransaction(rawHex(value, label));
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'MALFORMED_SOURCE_TRANSACTION',
      `${label} is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

function parseSourceOutput(transaction, index, label) {
  const serialized = transaction.outputs[index]?.serializedHex;
  if (serialized === undefined) {
    fail(
      'SOURCE_OUTPOINT_MISSING',
      `${label} does not contain output ${index}`,
    );
  }
  try {
    return parseSerializedSourceOutput(serialized);
  } catch (error) {
    fail(
      typeof error?.code === 'string' ? error.code : 'MALFORMED_SOURCE_OUTPUT',
      `${label} output ${index} is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

function normalizePins(value) {
  exactKeys(value, 'pins', [
    'bindingBaseSats',
    'bindingLockingBytecode',
    'bindingRedeemBytecode',
    'stateBaseSats',
    'stateLockingBytecode',
    'topologyId',
    'verifierCarriers',
    'verifierRoles',
  ]);
  let topology;
  try {
    topology = resolveDirectV2VerifierTopology({
      id: value.topologyId,
      verifierRoles: value.verifierRoles,
    });
  } catch (error) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `pins verifier topology is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    !Array.isArray(value.verifierCarriers)
    || value.verifierCarriers.length !== topology.carrierCount
  ) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `pins.verifierCarriers must contain exactly ${topology.carrierCount} entries`,
    );
  }
  const verifierCarriers = value.verifierCarriers.map((pin, index) => {
    exactKeys(pin, `pins.verifierCarriers[${index}]`, [
      'baseValueSats',
      'lockingBytecode',
    ]);
    const baseValue = decimal(
      pin.baseValueSats,
      MAX_MONEY_SATS,
      `pins.verifierCarriers[${index}].baseValueSats`,
    );
    if (baseValue === 0n) {
      fail(
        'INVALID_BASE_VALUE',
        `pins.verifierCarriers[${index}].baseValueSats must be nonzero`,
      );
    }
    return {
      baseValueSats: baseValue.toString(),
      lockingBytecodeHex: bytecode(
        pin.lockingBytecode,
        `pins.verifierCarriers[${index}].lockingBytecode`,
      ).toString('hex'),
    };
  });
  const bindingBase = decimal(
    value.bindingBaseSats,
    MAX_MONEY_SATS,
    'pins.bindingBaseSats',
  );
  const stateBase = decimal(
    value.stateBaseSats,
    MAX_MONEY_SATS,
    'pins.stateBaseSats',
  );
  if (bindingBase === 0n || stateBase === 0n) {
    fail(
      'INVALID_BASE_VALUE',
      'state and binding base values must be nonzero',
    );
  }
  const bindingRedeem = bytecode(
    value.bindingRedeemBytecode,
    'pins.bindingRedeemBytecode',
  );
  const bindingLock = bytecode(
    value.bindingLockingBytecode,
    'pins.bindingLockingBytecode',
  );
  try {
    verifyDirectV2BindingP2sh32Lock({
      redeemScript: bindingRedeem,
      sourceLockingBytecode: bindingLock,
    });
  } catch (error) {
    fail(
      'BINDING_REDEEM_MISMATCH',
      'pins.bindingLockingBytecode must be canonical P2SH32 for pins.bindingRedeemBytecode',
      { cause: error },
    );
  }
  return {
    topologyId: topology.id,
    verifierRoles: [...topology.verifierRoles],
    bindingBaseSats: bindingBase.toString(),
    bindingLockingBytecodeHex: bindingLock.toString('hex'),
    bindingRedeemBytecodeHex: bindingRedeem.toString('hex'),
    stateBaseSats: stateBase.toString(),
    stateLockingBytecodeHex: bytecode(
      value.stateLockingBytecode,
      'pins.stateLockingBytecode',
    ).toString('hex'),
    verifierCarriers,
  };
}

function normalizeUnlockingLengths(value, topology) {
  exactKeys(value, 'unlockingBytecodeLengths', ['state', 'verifier']);
  if (
    !Array.isArray(value.verifier)
    || value.verifier.length !== topology.carrierCount
  ) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `unlockingBytecodeLengths.verifier must contain exactly ${topology.carrierCount} lengths`,
    );
  }
  return {
    verifier: value.verifier.map((length, index) =>
      integer(
        length,
        0,
        V2_MAX_UNLOCKING_BYTECODE_BYTES,
        `unlockingBytecodeLengths.verifier[${index}]`,
      )),
    state: integer(
      value.state,
      0,
      V2_MAX_UNLOCKING_BYTECODE_BYTES,
      'unlockingBytecodeLengths.state',
    ),
  };
}

function normalizePrepareInput(value) {
  exactKeys(
    value,
    'PF11 settlement preparation',
    PREPARE_KEYS,
    OPTIONAL_PREPARE_KEYS,
  );
  if (!KINDS.has(value.kind)) {
    fail('INVALID_ACTION_KIND', 'kind must be deposit, transfer, or withdrawal');
  }
  const feeRate = decimal(
    value.feeRateSatsPerByte
      ?? PF11_DEFAULT_FEE_RATE_SATS_PER_BYTE,
    BigInt(V2_MAX_FEE_RATE_SATS_PER_BYTE),
    'feeRateSatsPerByte',
  );
  if (feeRate === 0n) {
    fail('INVALID_FEE_POLICY', 'feeRateSatsPerByte must be at least 1');
  }
  const denomination = decimal(
    value.denominationSats,
    MAX_MONEY_SATS,
    'denominationSats',
  );
  if (denomination === 0n) {
    fail('INVALID_SETTLEMENT', 'denominationSats must be nonzero');
  }
  if (![1, 2].includes(value.networkId)) {
    fail('INVALID_SETTLEMENT', 'networkId must be mainnet (1) or chipnet (2)');
  }
  const pins = normalizePins(value.pins);
  const topology = resolveDirectV2VerifierTopology({
    id: pins.topologyId,
    verifierRoles: pins.verifierRoles,
  });
  exactKeys(value.funding, 'funding', [
    'outpointIndex',
    'publicKey',
    'sourceTransactionHex',
  ]);
  const fundingKey = publicKey(value.funding.publicKey, 'funding.publicKey');
  const payout = value.payoutLockingBytecode === null
    ? null
    : p2pkh(value.payoutLockingBytecode, 'payoutLockingBytecode');
  if ((value.kind === 'withdrawal') !== (payout !== null)) {
    fail(
      'INVALID_WITHDRAWAL_OUTPUT',
      'payoutLockingBytecode must be canonical P2PKH only for withdrawal',
    );
  }
  return {
    changeLockingBytecodeHex: p2pkh(
      value.changeLockingBytecode,
      'changeLockingBytecode',
    ).toString('hex'),
    denominationSats: denomination.toString(),
    feeRateSatsPerByte: feeRate.toString(),
    funding: {
      outpointIndex: decimal(
        value.funding.outpointIndex,
        MAX_U32,
        'funding.outpointIndex',
      ).toString(),
      publicKeyHex: fundingKey.toString('hex'),
      sourceTransactionHex: rawHex(
        value.funding.sourceTransactionHex,
        'funding.sourceTransactionHex',
      ),
    },
    instanceId: identifier(value.instanceId, 'instanceId'),
    kind: value.kind,
    networkId: value.networkId,
    payoutLockingBytecodeHex: payout?.toString('hex') ?? null,
    pins,
    postState: value.postState,
    preState: value.preState,
    previousBundleTransactionHex: rawHex(
      value.previousBundleTransactionHex,
      'previousBundleTransactionHex',
    ),
    profileId: identifier(value.profileId, 'profileId'),
    unlockingBytecodeLengths: normalizeUnlockingLengths(
      value.unlockingBytecodeLengths,
      topology,
    ),
  };
}

function validateNormalizedIntent(value) {
  exactKeys(value, 'prepared payload', [
    'changeLockingBytecodeHex',
    'denominationSats',
    'feeRateSatsPerByte',
    'funding',
    'instanceId',
    'kind',
    'networkId',
    'payoutLockingBytecodeHex',
    'pins',
    'postState',
    'preState',
    'previousBundleTransactionHex',
    'profileId',
    'unlockingBytecodeLengths',
  ]);
  exactKeys(value.funding, 'prepared payload funding', [
    'outpointIndex',
    'publicKeyHex',
    'sourceTransactionHex',
  ]);
  exactKeys(value.pins, 'prepared payload pins', [
    'bindingBaseSats',
    'bindingLockingBytecodeHex',
    'bindingRedeemBytecodeHex',
    'stateBaseSats',
    'stateLockingBytecodeHex',
    'topologyId',
    'verifierCarriers',
    'verifierRoles',
  ]);
  let topology;
  try {
    topology = resolveDirectV2VerifierTopology({
      id: value.pins.topologyId,
      verifierRoles: value.pins.verifierRoles,
    });
  } catch (error) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `prepared verifier topology is invalid: ${error.message}`,
      { cause: error },
    );
  }
  if (
    !Array.isArray(value.pins.verifierCarriers)
    || value.pins.verifierCarriers.length !== topology.carrierCount
  ) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `prepared payload must contain exactly ${topology.carrierCount} verifier pins`,
    );
  }
  for (const [index, pin] of value.pins.verifierCarriers.entries()) {
    exactKeys(pin, `prepared payload verifier pin ${index}`, [
      'baseValueSats',
      'lockingBytecodeHex',
    ]);
  }
  const payout = value.payoutLockingBytecodeHex === null
    ? null
    : bytecodeHex(
        value.payoutLockingBytecodeHex,
        'payoutLockingBytecodeHex',
      );
  return normalizePrepareInput({
    changeLockingBytecode: bytecodeHex(
      value.changeLockingBytecodeHex,
      'changeLockingBytecodeHex',
    ),
    denominationSats: value.denominationSats,
    feeRateSatsPerByte: value.feeRateSatsPerByte,
    funding: {
      outpointIndex: value.funding.outpointIndex,
      publicKey: Buffer.from(
        exactHex(value.funding.publicKeyHex, 33, 'funding.publicKeyHex'),
        'hex',
      ),
      sourceTransactionHex: value.funding.sourceTransactionHex,
    },
    instanceId: value.instanceId,
    kind: value.kind,
    networkId: value.networkId,
    payoutLockingBytecode: payout,
    pins: {
      topologyId: value.pins.topologyId,
      verifierRoles: value.pins.verifierRoles,
      bindingBaseSats: value.pins.bindingBaseSats,
      bindingLockingBytecode: bytecodeHex(
        value.pins.bindingLockingBytecodeHex,
        'pins.bindingLockingBytecodeHex',
      ),
      bindingRedeemBytecode: bytecodeHex(
        value.pins.bindingRedeemBytecodeHex,
        'pins.bindingRedeemBytecodeHex',
      ),
      stateBaseSats: value.pins.stateBaseSats,
      stateLockingBytecode: bytecodeHex(
        value.pins.stateLockingBytecodeHex,
        'pins.stateLockingBytecodeHex',
      ),
      verifierCarriers: value.pins.verifierCarriers.map((pin, index) => ({
        baseValueSats: pin.baseValueSats,
        lockingBytecode: bytecodeHex(
          pin.lockingBytecodeHex,
          `pins.verifierCarriers[${index}].lockingBytecodeHex`,
        ),
      })),
    },
    postState: value.postState,
    preState: value.preState,
    previousBundleTransactionHex: value.previousBundleTransactionHex,
    profileId: value.profileId,
    unlockingBytecodeLengths: value.unlockingBytecodeLengths,
  });
}

function topologyForIntent(intent) {
  return resolveDirectV2VerifierTopology({
    id: intent.pins.topologyId,
    verifierRoles: intent.pins.verifierRoles,
  });
}

function requireSettlementTopology(topology, requiredId, operation) {
  if (topology.id === requiredId) {
    return;
  }
  if (
    requiredId === DIRECT_V2_PF10_FUSED_TOPOLOGY_ID
    && topology.id === DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID
  ) {
    fail(
      'PF11_SEMANTIC_ORACLE_ONLY',
      `${operation} refuses the PF11 semantic oracle; use the explicitly named PF11 oracle API`,
    );
  }
  if (requiredId === DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `${operation} requires the signed PF11 oracle topology`,
    );
  }
  fail(
    'VERIFIER_TOPOLOGY_MISMATCH',
    `${operation} requires verifier topology ${requiredId}`,
  );
}

function assertExactRollingBaseValues(intent) {
  for (const [index, pin] of intent.pins.verifierCarriers.entries()) {
    const expected = deriveV2RollingBaseSats({
      lockingBytecode: Buffer.from(pin.lockingBytecodeHex, 'hex'),
    });
    if (BigInt(pin.baseValueSats) !== expected) {
      fail(
        'INVALID_BASE_VALUE',
        `pins.verifierCarriers[${index}].baseValueSats must equal the exact dust-derived value ${expected}`,
      );
    }
  }
  const bindingExpected = deriveV2RollingBaseSats({
    lockingBytecode: Buffer.from(intent.pins.bindingLockingBytecodeHex, 'hex'),
  });
  if (BigInt(intent.pins.bindingBaseSats) !== bindingExpected) {
    fail(
      'INVALID_BASE_VALUE',
      `pins.bindingBaseSats must equal the exact dust-derived value ${bindingExpected}`,
    );
  }
  let postCommitment;
  try {
    postCommitment = encodeStateNftCommitment(intent.postState, {
      denominationSats: intent.denominationSats,
    });
  } catch (error) {
    fail(
      'INVALID_SETTLEMENT',
      `postState cannot encode the finalized state output: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  const stateExpected = deriveV2RollingBaseSats({
    lockingBytecode: Buffer.from(intent.pins.stateLockingBytecodeHex, 'hex'),
    token: {
      category: Buffer.from(intent.instanceId, 'hex'),
      amount: 0n,
      nft: {
        capability: 'mutable',
        commitment: postCommitment,
      },
    },
  });
  if (BigInt(intent.pins.stateBaseSats) !== stateExpected) {
    fail(
      'INVALID_BASE_VALUE',
      `pins.stateBaseSats must equal the exact dust-derived value ${stateExpected}`,
    );
  }
}

function makeInput({
  index,
  output,
  outpointDisplayTxid,
  outpointIndex,
  topology,
}) {
  const kind = index < topology.carrierCount
    ? 'verifier'
    : index === topology.bindingInputIndex
      ? 'binding'
      : index === topology.stateInputIndex
        ? 'state'
        : 'funding';
  return {
    role: role(kind, kind === 'verifier' ? index : 0),
    // The V2 context ABI commits outpoints in BCH serialized wire order.
    outpointTransactionHash: wireHash(outpointDisplayTxid),
    outpointIndex: String(outpointIndex),
    sequence: String(PF11_INPUT_SEQUENCE),
    valueSats: output.valueSatoshis.toString(),
    lockingBytecode: Buffer.from(output.lockingBytecode),
    token: parsedTokenToBundle(output.token),
  };
}

function makeOutputs(intent, postCommitment, changeSats) {
  const outputs = [
    {
      role: role('state'),
      valueSats: (
        BigInt(intent.pins.stateBaseSats)
        + BigInt(intent.postState.reserveSats)
      ).toString(),
      lockingBytecode: Buffer.from(
        intent.pins.stateLockingBytecodeHex,
        'hex',
      ),
      token: {
        category: intent.instanceId,
        amount: '0',
        nft: {
          capability: 'mutable',
          commitment: Buffer.from(postCommitment),
        },
      },
    },
    ...intent.pins.verifierCarriers.map((pin, ordinal) => ({
      role: role('verifier', ordinal),
      valueSats: pin.baseValueSats,
      lockingBytecode: Buffer.from(pin.lockingBytecodeHex, 'hex'),
      token: null,
    })),
    {
      role: role('binding'),
      valueSats: intent.pins.bindingBaseSats,
      lockingBytecode: Buffer.from(
        intent.pins.bindingLockingBytecodeHex,
        'hex',
      ),
      token: null,
    },
  ];
  if (intent.kind === 'withdrawal') {
    outputs.push({
      role: role('withdrawal'),
      valueSats: intent.denominationSats,
      lockingBytecode: Buffer.from(
        intent.payoutLockingBytecodeHex,
        'hex',
      ),
      token: null,
    });
  }
  outputs.push({
    role: role('change'),
    valueSats: changeSats.toString(),
    lockingBytecode: Buffer.from(
      intent.changeLockingBytecodeHex,
      'hex',
    ),
    token: null,
  });
  return outputs;
}

function makeRollingDescriptor({
  intent,
  inputs,
  previousBundleHashWire,
  feeSats,
  changeSats,
}) {
  const topology = topologyForIntent(intent);
  const postCommitment = encodeStateNftCommitment(intent.postState, {
    denominationSats: intent.denominationSats,
  });
  return {
    carrierCount: topology.carrierCount,
    denominationSats: intent.denominationSats,
    feeSats: feeSats.toString(),
    inputs,
    instanceId: intent.instanceId,
    kind: intent.kind,
    locktime: String(PF11_LOCKTIME),
    networkId: intent.networkId,
    outputs: makeOutputs(intent, postCommitment, changeSats),
    pins: {
      bindingBaseSats: intent.pins.bindingBaseSats,
      bindingLockingBytecode: Buffer.from(
        intent.pins.bindingLockingBytecodeHex,
        'hex',
      ),
      previousBundleTransactionHash: previousBundleHashWire,
      stateBaseSats: intent.pins.stateBaseSats,
      stateLockingBytecode: Buffer.from(
        intent.pins.stateLockingBytecodeHex,
        'hex',
      ),
      verifierCarriers: intent.pins.verifierCarriers.map((pin) => ({
        baseValueSats: pin.baseValueSats,
        lockingBytecode: Buffer.from(pin.lockingBytecodeHex, 'hex'),
      })),
    },
    postState: intent.postState,
    preState: intent.preState,
    profileId: intent.profileId,
    transactionVersion: String(PF11_TRANSACTION_VERSION),
  };
}

function transactionFromModel(model, outputs, unlockingBytecodes) {
  return {
    version: PF11_TRANSACTION_VERSION,
    inputs: model.context.inputs.map((input, index) => ({
      // Context hashes are wire order; Libauth takes display order and reverses.
      outpointTransactionHash: Uint8Array.from(
        Buffer.from(input.outpointTransactionHash, 'hex').reverse(),
      ),
      outpointIndex: Number(input.outpointIndex),
      sequenceNumber: Number(input.sequence),
      unlockingBytecode: Uint8Array.from(unlockingBytecodes[index]),
    })),
    outputs: model.context.outputs.map((_, index) =>
      bundleOutputToLibauth(outputs[index])),
    locktime: PF11_LOCKTIME,
  };
}

function validateModel(descriptor) {
  try {
    return validateDirectV2RollingBundle(descriptor);
  } catch (error) {
    fail(
      'ROLLING_BUNDLE_INVALID',
      `V2 rolling bundle is invalid: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

function sourceOutputsFromParsed(outputs) {
  return outputs.map(parsedOutputToLibauth);
}

function assertEnvelope(rawTransactionHex, topology) {
  try {
    return assertV2StandardTransactionEnvelope(
      parseV2RawTransaction(rawTransactionHex),
      { carrierCount: topology.carrierCount },
    );
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'TRANSACTION_POLICY_REJECTED',
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
}

function derivePrepared(normalizedIntent) {
  const intent = validateNormalizedIntent(normalizedIntent);
  assertExactRollingBaseValues(intent);
  const topology = topologyForIntent(intent);
  const previous = parseSourceTransaction(
    intent.previousBundleTransactionHex,
    'previousBundleTransactionHex',
  );
  const fundingTransaction = parseSourceTransaction(
    intent.funding.sourceTransactionHex,
    'funding.sourceTransactionHex',
  );
  if (fundingTransaction.txid === previous.txid) {
    fail(
      'FUNDING_NOT_INDEPENDENT',
      `funding input ${topology.fundingInputIndex} must use an independent source transaction`,
    );
  }
  const fundingIndex = Number(BigInt(intent.funding.outpointIndex));
  const previousOutputs = Array.from(
    { length: topology.stateInputIndex + 1 },
    (_, index) => parseSourceOutput(
      previous,
      index === topology.stateInputIndex ? 0 : index + 1,
      'previousBundleTransactionHex',
    ),
  );
  // Reorder the common parent outputs from [vout 1..12, vout 0].
  const commonRoleOutputs = [
    ...previousOutputs.slice(0, topology.stateInputIndex),
    previousOutputs[topology.stateInputIndex],
  ];
  const fundingOutput = parseSourceOutput(
    fundingTransaction,
    fundingIndex,
    'funding.sourceTransactionHex',
  );
  const sourceOutputs = [...commonRoleOutputs, fundingOutput];
  for (const [index, output] of sourceOutputs.entries()) {
    try {
      assertV2SourceOutputTopology({
        index,
        sourceOutput: output,
        instanceId: intent.instanceId,
        carrierCount: topology.carrierCount,
      });
    } catch (error) {
      fail(
        typeof error?.code === 'string'
          ? error.code
          : 'SOURCE_TOPOLOGY_MISMATCH',
        error instanceof Error ? error.message : String(error),
        { cause: error },
      );
    }
  }
  const expectedFundingLock = p2pkhForPublicKey(
    Buffer.from(intent.funding.publicKeyHex, 'hex'),
  );
  if (
    !expectedFundingLock.equals(Buffer.from(fundingOutput.lockingBytecode))
  ) {
    fail(
      'FUNDING_KEY_MISMATCH',
      `funding public key does not match input ${topology.fundingInputIndex} P2PKH source lock`,
    );
  }
  const inputs = [
    ...commonRoleOutputs.map((output, index) =>
      makeInput({
        index,
        output,
        outpointDisplayTxid: previous.txid,
        outpointIndex: index === topology.stateInputIndex ? 0 : index + 1,
        topology,
      })),
    makeInput({
      index: topology.fundingInputIndex,
      output: fundingOutput,
      outpointDisplayTxid: fundingTransaction.txid,
      outpointIndex: fundingIndex,
      topology,
    }),
  ];
  const boundaryFunding = intent.kind === 'deposit'
    ? BigInt(intent.denominationSats)
    : 0n;
  const fundingValue = fundingOutput.valueSatoshis;
  if (fundingValue <= boundaryFunding) {
    fail(
      'INSUFFICIENT_FUNDING',
      'funding input cannot cover the action boundary value',
    );
  }
  const provisionalChange = fundingValue - boundaryFunding;
  const previousHashWire = wireHash(previous.txid);
  const provisionalDescriptor = makeRollingDescriptor({
    intent,
    inputs,
    previousBundleHashWire: previousHashWire,
    feeSats: 0n,
    changeSats: provisionalChange,
  });
  const provisionalModel = validateModel(provisionalDescriptor);
  const sizingPacket = Buffer.alloc(ACTION_PACKET_BYTES);
  sizingPacket.write('SDA2', 0, 'ascii');
  const plannedBindingUnlock = canonicalBindingUnlock(
    sizingPacket,
    Buffer.from(intent.pins.bindingRedeemBytecodeHex, 'hex'),
    Buffer.from(intent.pins.bindingLockingBytecodeHex, 'hex'),
  );
  const plannedUnlockingBytecodes = [
    ...intent.unlockingBytecodeLengths.verifier.map((length) =>
      Buffer.alloc(length)),
    plannedBindingUnlock,
    Buffer.alloc(intent.unlockingBytecodeLengths.state),
    // Canonical 64-byte Schnorr signature + 0x61 and compressed public key.
    Buffer.alloc(100),
  ];
  const sizingTransaction = transactionFromModel(
    provisionalModel,
    provisionalDescriptor.outputs,
    plannedUnlockingBytecodes,
  );
  const provisionalSize = encodeTransaction(sizingTransaction).length;
  const feeSats =
    BigInt(provisionalSize) * BigInt(intent.feeRateSatsPerByte);
  if (fundingValue < boundaryFunding + feeSats) {
    fail(
      'INSUFFICIENT_FUNDING',
      'funding input cannot cover the exact serialized fee',
    );
  }
  const changeSats = fundingValue - boundaryFunding - feeSats;
  if (changeSats < BigInt(PF11_P2PKH_DUST_SATS)) {
    fail(
      'DUST_CHANGE',
      `change must be at least ${PF11_P2PKH_DUST_SATS} satoshis`,
    );
  }
  const descriptor = makeRollingDescriptor({
    intent,
    inputs,
    previousBundleHashWire: previousHashWire,
    feeSats,
    changeSats,
  });
  const model = validateModel(descriptor);
  const exactSizingTransaction = transactionFromModel(
    model,
    descriptor.outputs,
    plannedUnlockingBytecodes,
  );
  const sizingRaw = Buffer.from(encodeTransaction(exactSizingTransaction));
  if (sizingRaw.length !== provisionalSize) {
    fail(
      'INTERNAL_SETTLEMENT_ERROR',
      'fee-dependent change altered the serialized transaction size',
    );
  }
  assertEnvelope(sizingRaw.toString('hex'), topology);
  const contextHash = hashDirectV2TransactionContext(model.context, {
    carrierCount: topology.carrierCount,
  }).toString('hex');
  return {
    intent,
    descriptor,
    model,
    sourceOutputs,
    sourceTransactionHexes: Object.freeze([
      ...Array(topology.stateInputIndex + 1).fill(
        intent.previousBundleTransactionHex,
      ),
      intent.funding.sourceTransactionHex,
    ]),
    contextHash,
    previousBundleTransactionId: previous.txid,
    previousBundleTransactionHashWire: previousHashWire,
    fundingTransactionId: fundingTransaction.txid,
    feeSats,
    changeSats,
    signedSizeBytes: sizingRaw.length,
  };
}

function preparedEnvelope(derived, payload) {
  const topology = topologyForIntent(derived.intent);
  return deepFreeze({
    schema: PF11_PREPARED_SCHEMA,
    stage: 'prepared',
    payload,
    payloadHash: hashEnvelopePayload(payload),
    contextHash: derived.contextHash,
    topology: {
      id: topology.id,
      inputCount: topology.inputCount,
      outputCount: derived.intent.kind === 'withdrawal'
        ? topology.withdrawalOutputCount
        : topology.depositTransferOutputCount,
      verifierRoles: [...topology.verifierRoles],
      commonParentInputRange: `0..${topology.stateInputIndex}`,
      commonParentTransactionHashWire:
        derived.previousBundleTransactionHashWire,
      commonParentOutputIndices: [
        ...Array.from(
          { length: topology.stateInputIndex },
          (_, index) => index + 1,
        ),
        0,
      ],
      fundingInputIndex: topology.fundingInputIndex,
      fundingTransactionHashWire: wireHash(
        derived.fundingTransactionId,
      ),
    },
    measurements: {
      changeSats: derived.changeSats.toString(),
      dustFloorSats: PF11_P2PKH_DUST_SATS,
      feeRateSatsPerByte: derived.intent.feeRateSatsPerByte,
      feeSats: derived.feeSats.toString(),
      signedSizeBytes: derived.signedSizeBytes,
    },
  });
}

function inspectPrepared(value) {
  exactKeys(value, 'prepared settlement', [
    'contextHash',
    'measurements',
    'payload',
    'payloadHash',
    'schema',
    'stage',
    'topology',
  ]);
  if (
    value.schema !== PF11_PREPARED_SCHEMA
    || value.stage !== 'prepared'
    || typeof value.payload !== 'string'
    || value.payloadHash !== hashEnvelopePayload(value.payload)
  ) {
    fail(
      'PREPARED_SETTLEMENT_MUTATED',
      'prepared settlement schema, stage, or payload hash is invalid',
    );
  }
  let normalized;
  try {
    normalized = JSON.parse(value.payload);
  } catch (error) {
    fail(
      'PREPARED_SETTLEMENT_MUTATED',
      'prepared settlement payload is not JSON',
      { cause: error },
    );
  }
  if (canonical(normalized) !== value.payload) {
    fail(
      'PREPARED_SETTLEMENT_MUTATED',
      'prepared settlement payload is not canonical',
    );
  }
  const derived = derivePrepared(normalized);
  const expected = preparedEnvelope(derived, value.payload);
  if (canonical(expected) !== canonical(value)) {
    fail(
      'PREPARED_SETTLEMENT_MUTATED',
      'prepared settlement differs from its re-derived frozen context',
    );
  }
  return derived;
}

/**
 * Freeze exact signed-topology sources, successors, fee, change, and
 * transaction context.
 *
 * The caller supplies only authenticated source transactions, pinned locks/base
 * values, action state, destination locks, and exact future unlock lengths.
 * No proof, signature, network request, or broadcast occurs in this stage.
 */
function prepareSettlementForTopology(value, requiredTopologyId, operation) {
  const normalized = normalizePrepareInput(value);
  const payload = canonical(normalized);
  const derived = derivePrepared(normalized);
  requireSettlementTopology(
    topologyForIntent(derived.intent),
    requiredTopologyId,
    operation,
  );
  return preparedEnvelope(derived, payload);
}

export function prepareV2DirectSettlement(value) {
  return prepareSettlementForTopology(
    value,
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    'prepareV2DirectSettlement',
  );
}

export function preparePf11Settlement(value) {
  return prepareSettlementForTopology(
    value,
    DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
    'preparePf11Settlement',
  );
}

function normalizeAssemblyInput(value, topology) {
  exactKeys(value, 'V2 settlement assembly', [
    'actionPacket',
    'stateUnlockingBytecode',
    'verifierUnlockingBytecodes',
  ]);
  if (
    !Array.isArray(value.verifierUnlockingBytecodes)
    || value.verifierUnlockingBytecodes.length !== topology.carrierCount
  ) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      `verifierUnlockingBytecodes must contain exactly ${topology.carrierCount} entries`,
    );
  }
  const packet = bytecode(value.actionPacket, 'actionPacket');
  if (packet.length !== ACTION_PACKET_BYTES) {
    fail(
      'INVALID_ACTION_PACKET',
      `actionPacket must contain exactly ${ACTION_PACKET_BYTES} bytes`,
    );
  }
  return {
    actionPacketHex: packet.toString('hex'),
    stateUnlockingBytecodeHex: bytecode(
      value.stateUnlockingBytecode,
      'stateUnlockingBytecode',
      { allowEmpty: true },
    ).toString('hex'),
    verifierUnlockingBytecodesHex: value.verifierUnlockingBytecodes.map(
      (unlockingBytecode, index) =>
        bytecode(
          unlockingBytecode,
          `verifierUnlockingBytecodes[${index}]`,
          { allowEmpty: true },
        ).toString('hex'),
    ),
  };
}

function validatePacket(derived, packetBytes) {
  let packet;
  try {
    packet = decodeActionPacket(packetBytes, {
      denominationSats: derived.intent.denominationSats,
    });
  } catch (error) {
    fail(
      'INVALID_ACTION_PACKET',
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
  if (
    packet.kind !== derived.intent.kind
    || packet.networkId !== derived.intent.networkId
    || packet.instanceId !== derived.intent.instanceId
    || !sameState(packet.preState, derived.model.preState)
    || !sameState(packet.postState, derived.model.postState)
  ) {
    fail(
      'ACTION_PACKET_MISMATCH',
      'action packet identity, kind, network, or state differs from preparation',
    );
  }
  if (packet.transactionContextHash !== derived.contextHash) {
    fail(
      'TRANSACTION_CONTEXT_MISMATCH',
      'action packet does not bind the exact frozen signed-topology transaction context',
    );
  }
  if (derived.intent.kind === 'withdrawal') {
    const payoutHash = sha256Hex(
      Buffer.from(derived.intent.payoutLockingBytecodeHex, 'hex'),
    );
    if (packet.withdrawalLockingBytecodeHash !== payoutHash) {
      fail(
        'WITHDRAWAL_BINDING_MISMATCH',
        `action packet payout hash differs from exact output ${
          topologyForIntent(derived.intent).withdrawalOutputIndex
        }`,
      );
    }
  }
  return packet;
}

function assemblyPayload(prepared, normalizedAssembly) {
  return canonical({
    actionPacketHex: normalizedAssembly.actionPacketHex,
    preparedPayload: prepared.payload,
    preparedPayloadHash: prepared.payloadHash,
    stateUnlockingBytecodeHex:
      normalizedAssembly.stateUnlockingBytecodeHex,
    verifierUnlockingBytecodesHex:
      normalizedAssembly.verifierUnlockingBytecodesHex,
  });
}

function validateAssemblyPayload(value) {
  exactKeys(value, 'assembled payload', [
    'actionPacketHex',
    'preparedPayload',
    'preparedPayloadHash',
    'stateUnlockingBytecodeHex',
    'verifierUnlockingBytecodesHex',
  ]);
  if (
    typeof value.preparedPayload !== 'string'
    || value.preparedPayloadHash
      !== hashEnvelopePayload(value.preparedPayload)
  ) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'embedded prepared settlement payload hash is invalid',
    );
  }
  let normalizedIntent;
  try {
    normalizedIntent = JSON.parse(value.preparedPayload);
  } catch (error) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'embedded prepared settlement payload is not JSON',
      { cause: error },
    );
  }
  if (canonical(normalizedIntent) !== value.preparedPayload) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'embedded prepared settlement payload is not canonical',
    );
  }
  const derived = derivePrepared(normalizedIntent);
  const packetBytes = Buffer.from(
    exactHex(value.actionPacketHex, ACTION_PACKET_BYTES, 'actionPacketHex'),
    'hex',
  );
  validatePacket(derived, packetBytes);
  if (
    !Array.isArray(value.verifierUnlockingBytecodesHex)
    || value.verifierUnlockingBytecodesHex.length
      !== derived.intent.pins.verifierCarriers.length
  ) {
    fail(
      'VERIFIER_TOPOLOGY_MISMATCH',
      'assembled verifier unlock list differs from the signed topology',
    );
  }
  const verifierUnlocks = value.verifierUnlockingBytecodesHex.map(
    (unlockHex, index) => {
      const bytes = bytecodeHex(
        unlockHex,
        `verifierUnlockingBytecodesHex[${index}]`,
        { allowEmpty: true },
      );
      if (
        bytes.length
        !== derived.intent.unlockingBytecodeLengths.verifier[index]
      ) {
        fail(
          'UNLOCKING_SIZE_MISMATCH',
          `verifier input ${index} unlocking bytecode length differs from preparation`,
        );
      }
      return bytes;
    },
  );
  const stateUnlock = bytecodeHex(
    value.stateUnlockingBytecodeHex,
    'stateUnlockingBytecodeHex',
    { allowEmpty: true },
  );
  if (
    stateUnlock.length
    !== derived.intent.unlockingBytecodeLengths.state
  ) {
    fail(
      'UNLOCKING_SIZE_MISMATCH',
      `state input ${
        topologyForIntent(derived.intent).stateInputIndex
      } unlocking bytecode length differs from preparation`,
    );
  }
  const bindingUnlock = canonicalBindingUnlock(
    packetBytes,
    Buffer.from(
      derived.intent.pins.bindingRedeemBytecodeHex,
      'hex',
    ),
    Buffer.from(
      derived.intent.pins.bindingLockingBytecodeHex,
      'hex',
    ),
  );
  const unsignedUnlocks = [
    ...verifierUnlocks,
    bindingUnlock,
    stateUnlock,
    Buffer.alloc(0),
  ];
  const unsignedTransaction = transactionFromModel(
    derived.model,
    derived.descriptor.outputs,
    unsignedUnlocks,
  );
  const unsignedRaw = Buffer.from(encodeTransaction(unsignedTransaction));
  const topology = topologyForIntent(derived.intent);
  assertEnvelope(unsignedRaw.toString('hex'), topology);
  const sourceOutputs = sourceOutputsFromParsed(derived.sourceOutputs);
  const signingSerialization = Buffer.from(
    generateSigningSerializationBch(
      {
        inputIndex: topology.fundingInputIndex,
        sourceOutputs,
        transaction: unsignedTransaction,
      },
      {
        coveredBytecode:
          sourceOutputs[topology.fundingInputIndex].lockingBytecode,
        signingSerializationType: Uint8Array.of(V2_FUNDING_SIGHASH_TYPE),
      },
    ),
  );
  const signingDigest = Buffer.from(hash256(signingSerialization));
  return {
    derived,
    packetBytes,
    verifierUnlocks,
    bindingUnlock,
    stateUnlock,
    unsignedUnlocks,
    unsignedTransaction,
    unsignedRaw,
    sourceOutputs,
    signingSerialization,
    signingDigest,
  };
}

function assembledEnvelope(built, payload) {
  const topology = topologyForIntent(built.derived.intent);
  return deepFreeze({
    schema: PF11_ASSEMBLED_SCHEMA,
    stage: 'assembled',
    payload,
    assemblyHash: hashEnvelopePayload(payload),
    contextHash: built.derived.contextHash,
    unsignedTransactionHex: built.unsignedRaw.toString('hex'),
    signingRequest: {
      algorithm: 'BCH_SCHNORR_SECP256K1',
      contextHash: built.derived.contextHash,
      digestHex: built.signingDigest.toString('hex'),
      fundingInputIndex: topology.fundingInputIndex,
      publicKeyHex: built.derived.intent.funding.publicKeyHex,
      sighashContract: 'SIGHASH_ALL|UTXOS|FORKID',
      sighashType: V2_FUNDING_SIGHASH_TYPE,
      signingSerializationHex: built.signingSerialization.toString('hex'),
    },
    measurements: {
      changeSats: built.derived.changeSats.toString(),
      feeSats: built.derived.feeSats.toString(),
      signedSizeBytes: built.derived.signedSizeBytes,
      unsignedSizeBytes: built.unsignedRaw.length,
    },
  });
}

function inspectAssembled(value) {
  exactKeys(value, 'assembled settlement', [
    'assemblyHash',
    'contextHash',
    'measurements',
    'payload',
    'schema',
    'signingRequest',
    'stage',
    'unsignedTransactionHex',
  ]);
  if (
    value.schema !== PF11_ASSEMBLED_SCHEMA
    || value.stage !== 'assembled'
    || typeof value.payload !== 'string'
    || value.assemblyHash !== hashEnvelopePayload(value.payload)
  ) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'assembled settlement schema, stage, or payload hash is invalid',
    );
  }
  let payload;
  try {
    payload = JSON.parse(value.payload);
  } catch (error) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'assembled settlement payload is not JSON',
      { cause: error },
    );
  }
  if (canonical(payload) !== value.payload) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'assembled settlement payload is not canonical',
    );
  }
  const built = validateAssemblyPayload(payload);
  const expected = assembledEnvelope(built, value.payload);
  if (canonical(expected) !== canonical(value)) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'assembled settlement differs from re-derived proof and context',
    );
  }
  return built;
}

/**
 * Install every signed-topology verifier unlock, the exact 552-byte action
 * packet, the pinned binding redeem script, and the state-helper unlock. The
 * binding input is assembled as exactly two minimal pushes:
 * PUSHDATA2(552)||packet followed by the P2SH32 redeem program; no additional
 * stack items or fallback are added.
 */
function assembleSettlementForTopology(
  prepared,
  value,
  requiredTopologyId,
  operation,
) {
  const derived = inspectPrepared(prepared);
  const topology = topologyForIntent(derived.intent);
  requireSettlementTopology(topology, requiredTopologyId, operation);
  const normalized = normalizeAssemblyInput(
    value,
    topology,
  );
  const payload = assemblyPayload(prepared, normalized);
  const built = validateAssemblyPayload(JSON.parse(payload));
  return assembledEnvelope(built, payload);
}

export function assembleV2DirectSettlement(prepared, value) {
  return assembleSettlementForTopology(
    prepared,
    value,
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    'assembleV2DirectSettlement',
  );
}

export function assemblePf11Settlement(prepared, value) {
  return assembleSettlementForTopology(
    prepared,
    value,
    DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
    'assemblePf11Settlement',
  );
}

function exactSignerOptions(value) {
  exactKeys(value, 'V2 signing options', [
    'createLocalVmEvidence',
    'signFunding',
  ]);
  if (typeof value.signFunding !== 'function') {
    fail(
      'FUNDING_SIGNER_REQUIRED',
      'signFunding must be an injected signing callback',
    );
  }
  if (typeof value.createLocalVmEvidence !== 'function') {
    fail(
      'LOCAL_VM_EVIDENCE_PRODUCER_REQUIRED',
      'createLocalVmEvidence must be an injected local BCH VM evidence callback',
    );
  }
  return value;
}

function normalizeSignature(value) {
  if (!(value instanceof Uint8Array) || value.length !== 64) {
    fail(
      'INVALID_FUNDING_SIGNATURE',
      'signFunding must return exactly one 64-byte Schnorr signature',
    );
  }
  return Buffer.from(value);
}

/**
 * Sign only the topology-derived funding input under the exact
 * SIGHASH_ALL|UTXOS|FORKID (0x61)
 * contract, then require fresh all-input BCH_2026 VM evidence for the exact
 * serialized transaction. The callbacks are injected; this module has no
 * wallet, RPC, sponsor, faucet, preparation-transaction, or broadcast path.
 */
async function signSettlementForTopology(
  assembled,
  value,
  requiredTopologyId,
  operation,
) {
  const options = exactSignerOptions(value);
  const built = inspectAssembled(assembled);
  const topology = topologyForIntent(built.derived.intent);
  requireSettlementTopology(topology, requiredTopologyId, operation);
  const assemblyHashBefore = hashEnvelopePayload(assembled.payload);
  let signatureValue;
  try {
    signatureValue = await options.signFunding(
      deepFreeze({ ...assembled.signingRequest }),
    );
  } catch (error) {
    fail(
      'FUNDING_SIGNER_FAILED',
      `funding signer failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (
    assemblyHashBefore !== hashEnvelopePayload(assembled.payload)
    || assemblyHashBefore !== assembled.assemblyHash
  ) {
    fail(
      'ASSEMBLED_SETTLEMENT_MUTATED',
      'assembled proof or context changed while funding signature was requested',
    );
  }
  const signature = normalizeSignature(signatureValue);
  const fundingKey = Buffer.from(
    built.derived.intent.funding.publicKeyHex,
    'hex',
  );
  if (
    !secp256k1.verifySignatureSchnorr(
      signature,
      fundingKey,
      built.signingDigest,
    )
  ) {
    fail(
      'INVALID_FUNDING_SIGNATURE',
      'funding signature does not verify for the frozen 0x61 digest',
    );
  }
  const signatureWithType = Buffer.concat([
    signature,
    Buffer.from([V2_FUNDING_SIGHASH_TYPE]),
  ]);
  const fundingUnlock = Buffer.concat([
    Buffer.from(encodeDataPush(signatureWithType)),
    Buffer.from(encodeDataPush(fundingKey)),
  ]);
  if (
    fundingUnlock.length !== 100
    || fundingUnlock[0] !== 0x41
    || fundingUnlock[65] !== V2_FUNDING_SIGHASH_TYPE
    || fundingUnlock[66] !== 0x21
  ) {
    fail(
      'INTERNAL_SETTLEMENT_ERROR',
      'funding signature did not encode as canonical 100-byte P2PKH unlock',
    );
  }
  const signedUnlocks = [...built.unsignedUnlocks];
  signedUnlocks[topology.fundingInputIndex] = fundingUnlock;
  const transaction = transactionFromModel(
    built.derived.model,
    built.derived.descriptor.outputs,
    signedUnlocks,
  );
  const encoded = Buffer.from(encodeTransaction(transaction));
  const rawTransactionHex = encoded.toString('hex');
  const parsed = assertEnvelope(rawTransactionHex, topology);
  if (
    encoded.length !== built.derived.signedSizeBytes
    || encoded.length > V2_MAX_TRANSACTION_BYTES
    || parsed.inputs.some(
      (input) =>
        input.unlockingBytecodeBytes
        > V2_MAX_UNLOCKING_BYTECODE_BYTES,
    )
  ) {
    fail(
      'TRANSACTION_POLICY_REJECTED',
      'signed transaction differs from exact size/unlocking policy preparation',
    );
  }
  const expectedFee =
    BigInt(encoded.length)
    * BigInt(built.derived.intent.feeRateSatsPerByte);
  if (expectedFee !== built.derived.feeSats) {
    fail(
      'FEE_MISMATCH',
      'signed transaction fee differs from exact fee-rate policy',
    );
  }
  const vmRequest = deepFreeze({
    carrierCount: topology.carrierCount,
    inputs: built.derived.sourceTransactionHexes.map(
      (sourceTransactionHex) => ({ sourceTransactionHex }),
    ),
    instanceId: built.derived.intent.instanceId,
    rawTransactionHex,
  });
  let evidenceBytes;
  try {
    evidenceBytes = await options.createLocalVmEvidence(vmRequest);
  } catch (error) {
    fail(
      'LOCAL_VM_EVIDENCE_FAILED',
      `local BCH VM evidence producer failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
  if (!(evidenceBytes instanceof Uint8Array) || evidenceBytes.length === 0) {
    fail(
      'LOCAL_VM_EVIDENCE_REQUIRED',
      'local VM evidence callback must return nonempty evidence bytes',
    );
  }
  let evidence;
  try {
    evidence = inspectV2LocalVmEvidence(evidenceBytes);
  } catch (error) {
    fail(
      typeof error?.code === 'string'
        ? error.code
        : 'INVALID_VM_EVIDENCE',
      error instanceof Error ? error.message : String(error),
      { cause: error },
    );
  }
  const txid = transactionId(encoded);
  if (
    evidence.carrierCount !== topology.carrierCount
    || evidence.instanceId !== built.derived.intent.instanceId
    || evidence.transaction.rawTransactionHex !== rawTransactionHex
    || evidence.transaction.txid !== txid
    || evidence.transaction.serializedBytes !== encoded.length
    || evidence.transaction.inputCount !== topology.inputCount
    || evidence.allInputsAccepted !== true
    || evidence.inputs.length !== topology.inputCount
    || evidence.tool.profileId !== built.derived.intent.profileId
  ) {
    fail(
      'VM_EVIDENCE_BINDING_MISMATCH',
      'VM evidence does not prove 100% acceptance of this exact signed-topology transaction and profile',
    );
  }
  return deepFreeze({
    schema: PF11_SIGNED_SCHEMA,
    stage: 'signed',
    rawTransactionHex,
    txid,
    contextHash: built.derived.contextHash,
    actionPacketHex: built.packetBytes.toString('hex'),
    localVmEvidenceHex: Buffer.from(evidenceBytes).toString('hex'),
    evidenceHash: evidence.evidenceHash,
    measurements: {
      changeSats: built.derived.changeSats.toString(),
      feeRateSatsPerByte: built.derived.intent.feeRateSatsPerByte,
      feeSats: built.derived.feeSats.toString(),
      inputCount: parsed.inputs.length,
      outputCount: parsed.outputs.length,
      sizeBytes: parsed.sizeBytes,
      maximumTransactionBytes: V2_MAX_TRANSACTION_BYTES,
      maximumUnlockingBytecodeBytes:
        V2_MAX_UNLOCKING_BYTECODE_BYTES,
      acceptedInputCount: evidence.inputs.length,
      acceptancePercent: 100,
    },
    claims: {
      exactTransactionEnvelopeQualified: true,
      localBch2026AllInputsAccepted: true,
      verifierArtifactProvenanceQualified: false,
      broadcasted: false,
    },
  });
}

export async function signV2DirectSettlement(assembled, value) {
  return signSettlementForTopology(
    assembled,
    value,
    DIRECT_V2_PF10_FUSED_TOPOLOGY_ID,
    'signV2DirectSettlement',
  );
}

export async function signPf11Settlement(assembled, value) {
  return signSettlementForTopology(
    assembled,
    value,
    DIRECT_V2_PF11_ORACLE_TOPOLOGY_ID,
    'signPf11Settlement',
  );
}
