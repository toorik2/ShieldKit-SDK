import { createHash } from 'node:crypto';
import {
  buildPacketOnlyBindingLock,
  buildStateSettlementHelper,
  buildStateTrampolineLock,
  buildStateTrampolineUnlock,
} from '../../bch/g2-compressed-covenants/compressed-covenants.mjs';

export const PF7_CARRIER_SOURCE_ENCODING = 'libauth-transaction-outputs-v1';
export const PF7_CARRIER_ROLES = Object.freeze([
  'exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal',
]);
export const PF7_SETTLEMENT_CONSTANTS = Object.freeze({
  bindingCarrierBaseSatoshis: 1_000n,
  denominationSatoshis: 10_000_000n,
  feeRateSatoshisPerByte: 1n,
  stateCarrierBaseSatoshis: 1_080n,
});

const HASH_ID = /^sha256:[0-9a-f]{64}$/;
const LOWER_HEX = /^(?:[0-9a-f]{2})+$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class Pf7AuthorityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'Pf7AuthorityError';
  }
}

const fail = (message) => {
  throw new Pf7AuthorityError(message);
};

const exactKeys = (value, label, keys) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown properties`);
  }
};

const sha256 = (value) => createHash('sha256').update(value).digest();
const sha256d = (value) => sha256(sha256(value));
const canonicalJson = (value) => {
  if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
};
const measured = (value) => Object.freeze({
  bytes: value.length,
  sha256: `sha256:${sha256(value).toString('hex')}`,
});

function parseCarrier(script, index) {
  exactKeys(
    script,
    `PF7 carrier ${index}`,
    ['lockingBytecodeHex', 'name', 'redeemBytecodeHex', 'sourceValueSatoshis'],
  );
  if (script.name !== PF7_CARRIER_ROLES[index]) {
    fail(`PF7 carrier ${index} has the wrong role`);
  }
  if (
    typeof script.lockingBytecodeHex !== 'string'
    || !LOWER_HEX.test(script.lockingBytecodeHex)
  ) {
    fail(`PF7 carrier ${index} locking bytecode must be canonical lowercase hex`);
  }
  if (
    typeof script.redeemBytecodeHex !== 'string'
    || !LOWER_HEX.test(script.redeemBytecodeHex)
  ) {
    fail(`PF7 carrier ${index} redeem bytecode must be canonical lowercase hex`);
  }
  const lockingBytecode = Buffer.from(script.lockingBytecodeHex, 'hex');
  const redeemBytecode = Buffer.from(script.redeemBytecodeHex, 'hex');
  if (
    lockingBytecode.length !== 35
    || lockingBytecode[0] !== 0xaa
    || lockingBytecode[1] !== 0x20
    || lockingBytecode[34] !== 0x87
    || !sha256d(redeemBytecode).equals(lockingBytecode.subarray(2, 34))
  ) {
    fail(`PF7 carrier ${index} is not an exact P2SH32 source/redeem pair`);
  }
  if (
    typeof script.sourceValueSatoshis !== 'string'
    || !/^[1-9][0-9]*$/.test(script.sourceValueSatoshis)
  ) {
    fail(`PF7 carrier ${index} value must be a canonical positive decimal u64`);
  }
  const valueSatoshis = BigInt(script.sourceValueSatoshis);
  if (valueSatoshis > MAX_U64) {
    fail(`PF7 carrier ${index} value exceeds u64`);
  }
  return Object.freeze({
    role: script.name,
    lockingBytecode,
    redeemBytecode,
    valueSatoshis,
  });
}

/**
 * Serialize the exact tokenless PF7 carrier authority:
 * CompactSize(7) || (u64le(value) || CompactSize(35) || P2SH32) * 7.
 */
export function encodeCanonicalPf7CarrierSourceSet(carriers) {
  if (!Array.isArray(carriers) || carriers.length !== PF7_CARRIER_ROLES.length) {
    fail('PF7 carrier authority must contain exactly seven roles');
  }
  const outputs = carriers.map((carrier, index) => {
    const parsed = Object.hasOwn(carrier, 'role')
      ? carrier
      : parseCarrier(carrier, index);
    if (
      parsed.role !== PF7_CARRIER_ROLES[index]
      || typeof parsed.valueSatoshis !== 'bigint'
      || parsed.valueSatoshis <= 0n
      || parsed.valueSatoshis > MAX_U64
      || !(parsed.lockingBytecode instanceof Uint8Array)
      || parsed.lockingBytecode.length !== 35
    ) {
      fail(`PF7 carrier ${index} cannot be canonically serialized`);
    }
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(parsed.valueSatoshis);
    return Buffer.concat([value, Buffer.of(35), Buffer.from(parsed.lockingBytecode)]);
  });
  return Buffer.concat([Buffer.of(PF7_CARRIER_ROLES.length), ...outputs]);
}

/**
 * Derive the exact pre-profile settlement kernel from PF7 carrier authority.
 * No profile, instance, category, reserve cap, proof, or transaction bytes
 * enter this derivation, avoiding an identity cycle.
 */
export function derivePf7SettlementKernelAuthority(carriers) {
  if (!Array.isArray(carriers) || carriers.length !== PF7_CARRIER_ROLES.length) {
    fail('PF7 settlement kernel requires exactly seven carriers');
  }
  const bindingLock = Buffer.from(buildPacketOnlyBindingLock());
  const stateHelper = Buffer.from(buildStateSettlementHelper({
    bindingLock,
    pf7Locks: carriers.map((carrier) => Buffer.from(carrier.lockingBytecode)),
    pf7Values: carriers.map((carrier) => carrier.valueSatoshis),
    bindingCarrierBaseSatoshis: Number(PF7_SETTLEMENT_CONSTANTS.bindingCarrierBaseSatoshis),
  }));
  const stateHelperUnlock = Buffer.from(buildStateTrampolineUnlock(stateHelper));
  const stateLock = Buffer.from(buildStateTrampolineLock({ helper: stateHelper, bindingLock }));
  const artifact = Object.freeze({
    algorithm: 'shield.cash/g2-compressed-settlement-kernel/v1',
    artifacts: Object.freeze({
      bindingLock: measured(bindingLock),
      stateHelper: measured(stateHelper),
      stateHelperUnlock: measured(stateHelperUnlock),
      stateLock: measured(stateLock),
    }),
    constants: Object.freeze(Object.fromEntries(
      Object.entries(PF7_SETTLEMENT_CONSTANTS).map(([key, value]) => [key, value.toString()]),
    )),
    limits: Object.freeze({
      maximumCompleteTransactionBytes: 59_000,
      maximumContingencyTransactionBytes: 65_000,
      maximumInputUnlockingBytes: 10_000,
      maximumP2sLockingBytes: 190,
    }),
    schema: 'shield.cash/pf7-settlement-kernel/v1',
    topology: Object.freeze({
      preparationOutputs: 10,
      settlementInputs: 10,
      verifierInputs: 7,
    }),
  });
  return Object.freeze({
    artifact,
    bindingLock,
    stateHelper,
    stateHelperUnlock,
    stateLock,
  });
}

/**
 * Validate and independently authenticate a profile's seven PF7 carriers.
 * Full ten-output verifier context artifacts are deliberately outside this
 * authority; only the canonical seven tokenless outputs are hashed here.
 */
export function parsePf7CarrierAuthority(record) {
  if (record === null || Array.isArray(record) || typeof record !== 'object') {
    fail('PF7 verifier-set artifact must be an object');
  }
  if (record.schema !== 'shield.cash/bch-verifier-set/v1') {
    fail('PF7 verifier-set schema is unsupported');
  }
  exactKeys(
    record.sourceSet,
    'PF7 sourceSet',
    ['carrierCount', 'encoding', 'sha256'],
  );
  if (
    record.sourceSet.encoding !== PF7_CARRIER_SOURCE_ENCODING
    || record.sourceSet.carrierCount !== PF7_CARRIER_ROLES.length
    || typeof record.sourceSet.sha256 !== 'string'
    || !HASH_ID.test(record.sourceSet.sha256)
  ) {
    fail('PF7 sourceSet authority is malformed');
  }
  if (!Array.isArray(record.scripts) || record.scripts.length !== PF7_CARRIER_ROLES.length) {
    fail('PF7 verifier-set must contain exactly seven carrier scripts');
  }
  const carriers = Object.freeze(record.scripts.map(parseCarrier));
  const serialization = encodeCanonicalPf7CarrierSourceSet(carriers);
  const sha256Identifier = `sha256:${sha256(serialization).toString('hex')}`;
  if (sha256Identifier !== record.sourceSet.sha256) {
    fail('PF7 sourceSet hash does not match canonical carrier outputs');
  }
  const settlementKernel = derivePf7SettlementKernelAuthority(carriers);
  if (
    record.settlementKernel === null
    || Array.isArray(record.settlementKernel)
    || typeof record.settlementKernel !== 'object'
    || canonicalJson(record.settlementKernel) !== canonicalJson(settlementKernel.artifact)
  ) {
    fail('PF7 settlement kernel does not match the canonical carrier authority');
  }
  return Object.freeze({
    carriers,
    serialization,
    settlementKernel,
    sha256: sha256Identifier,
  });
}
