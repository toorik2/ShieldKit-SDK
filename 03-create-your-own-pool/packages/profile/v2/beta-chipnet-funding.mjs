/**
 * Offline construction of the one-input BCHN Chipnet bootstrap-funding
 * transaction for a V2 beta pool. This module has no filesystem, RPC, or
 * broadcast dependency: callers must authenticate the source UTXO first.
 */
import {
  createVirtualMachineBch2026,
  decodeTransaction,
  encodeDataPush,
  encodeTransaction,
  generateSigningSerializationBch,
  hash160,
  hash256,
  secp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';

export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SCHEMA =
  'shieldkit-v2-beta-chipnet-bootstrap-funding-v1';
export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE =
  SigningSerializationTypeBch.allOutputs;
export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_FEE_RATE_SATS_PER_BYTE = '1';
export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DUST_SATS = '546';
export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS =
  Object.freeze([1, 2, 3, 4, 5]);
export const V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS =
  Object.freeze([6, 7, 8, 9, 10]);

const HEX = /^[0-9a-f]*$/u;
const HASH = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const MAX_MONEY_SATS = 2_100_000_000_000_000n;
const DUST_SATS = BigInt(V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DUST_SATS);

export class V2BetaChipnetFundingError extends Error {
  constructor(code, message, options = undefined) {
    super(message, options);
    this.name = 'V2BetaChipnetFundingError';
    this.code = code;
  }
}

const fail = (code, message, options = undefined) => {
  throw new V2BetaChipnetFundingError(code, message, options);
};

function exact(value, keys, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail('BOOTSTRAP_FUNDING_INVALID', `${label} must be a plain object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail('BOOTSTRAP_FUNDING_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}

function hex(value, bytes, label) {
  if (
    typeof value !== 'string'
    || value.length !== bytes * 2
    || !HEX.test(value)
  ) {
    fail('BOOTSTRAP_FUNDING_INVALID', `${label} must be ${bytes} lowercase hexadecimal bytes`);
  }
  return Buffer.from(value, 'hex');
}

function amount(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) {
    fail('BOOTSTRAP_FUNDING_INVALID', `${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed < DUST_SATS || parsed > MAX_MONEY_SATS) {
    fail('BOOTSTRAP_FUNDING_INVALID', `${label} must be in [${DUST_SATS}, ${MAX_MONEY_SATS}]`);
  }
  return parsed;
}

function p2pkhLock(publicKey) {
  return Buffer.concat([
    Buffer.from([0x76, 0xa9, 0x14]),
    Buffer.from(hash160(publicKey)),
    Buffer.from([0x88, 0xac]),
  ]);
}

function publicKey(value) {
  const key = hex(value, 33, 'fundingPublicKeyHex');
  if (![0x02, 0x03].includes(key[0]) || !secp256k1.validatePublicKey(key)) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'fundingPublicKeyHex must be a valid compressed secp256k1 key');
  }
  return key;
}

function privateKey(value, expectedPublicKey) {
  const key = hex(value, 32, 'fundingPrivateKeyHex');
  if (!secp256k1.validatePrivateKey(key)) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'fundingPrivateKeyHex must be a valid secp256k1 private key');
  }
  const derived = secp256k1.derivePublicKeyCompressed(key);
  if (!(derived instanceof Uint8Array) || !Buffer.from(derived).equals(expectedPublicKey)) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'funding private and public keys do not match');
  }
  return key;
}

function walletLock(value, expectedPublicKey) {
  const lock = hex(value, 25, 'walletLockingBytecodeHex');
  if (
    lock[0] !== 0x76
    || lock[1] !== 0xa9
    || lock[2] !== 0x14
    || lock[23] !== 0x88
    || lock[24] !== 0xac
    || !lock.equals(p2pkhLock(expectedPublicKey))
  ) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'walletLockingBytecodeHex must be the supplied public key P2PKH lock');
  }
  return lock;
}

function source(value, expectedLock) {
  exact(value, [
    'lockingBytecodeHex',
    'outputIndex',
    'token',
    'transactionId',
    'valueSats',
  ], 'source');
  if (typeof value.transactionId !== 'string' || !HASH.test(value.transactionId)) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'source.transactionId must be lowercase 32-byte hex');
  }
  if (
    !Number.isSafeInteger(value.outputIndex)
    || value.outputIndex < 0
    || value.outputIndex > 0xffff_ffff
  ) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'source.outputIndex must be a u32');
  }
  if (value.token !== null) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'source must be tokenless');
  }
  const lockingBytecode = walletLock(value.lockingBytecodeHex, expectedLock.publicKey);
  if (!lockingBytecode.equals(expectedLock.lockingBytecode)) {
    fail('BOOTSTRAP_FUNDING_INVALID', 'source locking bytecode is not owned by the supplied wallet');
  }
  return Object.freeze({
    transactionId: value.transactionId,
    outputIndex: value.outputIndex,
    valueSats: amount(value.valueSats, 'source.valueSats'),
    lockingBytecode,
  });
}

function normalize(value) {
  exact(value, [
    'depositReserveSats',
    'fundingPrivateKeyHex',
    'fundingPublicKeyHex',
    'genesisSourceSats',
    'source',
    'walletLockingBytecodeHex',
    'withdrawalReserveSats',
  ], 'bootstrap funding input');
  const fundingPublicKey = publicKey(value.fundingPublicKeyHex);
  const fundingPrivateKey = privateKey(
    value.fundingPrivateKeyHex,
    fundingPublicKey,
  );
  const lockingBytecode = walletLock(
    value.walletLockingBytecodeHex,
    fundingPublicKey,
  );
  const expectedLock = Object.freeze({ publicKey: fundingPublicKey, lockingBytecode });
  return Object.freeze({
    fundingPrivateKey,
    fundingPublicKey,
    lockingBytecode,
    source: source(value.source, expectedLock),
    genesisSourceSats: amount(value.genesisSourceSats, 'genesisSourceSats'),
    depositReserveSats: amount(value.depositReserveSats, 'depositReserveSats'),
    withdrawalReserveSats: amount(value.withdrawalReserveSats, 'withdrawalReserveSats'),
  });
}

function output(valueSatoshis, lockingBytecode) {
  return Object.freeze({
    valueSatoshis,
    lockingBytecode: Uint8Array.from(lockingBytecode),
  });
}

function transactionFor(intent, changeSats, unlockingBytecode) {
  return {
    version: 2,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(
        // Libauth's transaction object uses display-order txid bytes here;
        // encodeTransaction performs the wire-order reversal itself.
        Buffer.from(intent.source.transactionId, 'hex'),
      ),
      outpointIndex: intent.source.outputIndex,
      sequenceNumber: 0xffff_ffff,
      unlockingBytecode: Uint8Array.from(unlockingBytecode),
    }],
    outputs: [
      output(intent.genesisSourceSats, intent.lockingBytecode),
      ...V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS.map(() =>
        output(intent.depositReserveSats, intent.lockingBytecode)),
      ...V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS.map(() =>
        output(intent.withdrawalReserveSats, intent.lockingBytecode)),
      output(changeSats, intent.lockingBytecode),
    ],
    locktime: 0,
  };
}

function decodedTransactionForVm(rawTransaction) {
  const decoded = decodeTransaction(Uint8Array.from(rawTransaction));
  if (typeof decoded === 'string') {
    fail('BOOTSTRAP_FUNDING_INTERNAL', `could not decode signed funding transaction: ${decoded}`);
  }
  return {
    version: decoded.version,
    inputs: decoded.inputs.map((input) => ({
      outpointTransactionHash: Uint8Array.from(input.outpointTransactionHash),
      outpointIndex: input.outpointIndex,
      sequenceNumber: input.sequenceNumber,
      unlockingBytecode: Uint8Array.from(input.unlockingBytecode),
    })),
    outputs: decoded.outputs.map((entry) => ({
      valueSatoshis: entry.valueSatoshis,
      lockingBytecode: Uint8Array.from(entry.lockingBytecode),
      ...(entry.token === undefined ? {} : { token: entry.token }),
    })),
    locktime: decoded.locktime,
  };
}

function canonicalUnlock(signature, publicKeyValue) {
  const signatureWithType = Buffer.concat([
    Buffer.from(signature),
    Buffer.from([V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE]),
  ]);
  const unlock = Buffer.concat([
    Buffer.from(encodeDataPush(signatureWithType)),
    Buffer.from(encodeDataPush(publicKeyValue)),
  ]);
  if (
    unlock.length !== 100
    || unlock[0] !== 0x41
    || unlock[65] !== V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE
    || unlock[66] !== 0x21
  ) {
    fail('BOOTSTRAP_FUNDING_INTERNAL', 'funding signature did not encode as canonical P2PKH unlocking bytecode');
  }
  return unlock;
}

function fixedPointSizing(intent) {
  const placeholder = canonicalUnlock(Buffer.alloc(64), intent.fundingPublicKey);
  const fixedOutputs = intent.genesisSourceSats
    + (intent.depositReserveSats * 5n)
    + (intent.withdrawalReserveSats * 5n);
  const provisional = transactionFor(intent, DUST_SATS, placeholder);
  const serializedBytes = Buffer.from(encodeTransaction(provisional)).length;
  const feeSats = BigInt(serializedBytes);
  const changeSats = intent.source.valueSats - fixedOutputs - feeSats;
  if (changeSats < DUST_SATS) {
    fail(
      'BOOTSTRAP_FUNDING_INSUFFICIENT',
      `source cannot fund ${fixedOutputs} sats of bootstrap reserves, ${feeSats} sats fee, and ${DUST_SATS} sats dust-safe change`,
    );
  }
  const exact = transactionFor(intent, changeSats, placeholder);
  if (Buffer.from(encodeTransaction(exact)).length !== serializedBytes) {
    fail('BOOTSTRAP_FUNDING_INTERNAL', 'transaction size changed after exact fee sizing');
  }
  return Object.freeze({ fixedOutputs, serializedBytes, feeSats, changeSats });
}

function sign(intent, sizing) {
  const unsigned = transactionFor(intent, sizing.changeSats, Buffer.alloc(0));
  const sourceOutputs = [{
    valueSatoshis: intent.source.valueSats,
    lockingBytecode: Uint8Array.from(intent.source.lockingBytecode),
  }];
  const serialization = Buffer.from(generateSigningSerializationBch(
    { inputIndex: 0, sourceOutputs, transaction: unsigned },
    {
      coveredBytecode: intent.source.lockingBytecode,
      signingSerializationType: Uint8Array.of(
        V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE,
      ),
    },
  ));
  const digest = Buffer.from(hash256(serialization));
  const signature = secp256k1.signMessageHashSchnorr(intent.fundingPrivateKey, digest);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    fail('BOOTSTRAP_FUNDING_SIGNING_FAILED', 'BCH Schnorr signing did not return one 64-byte signature');
  }
  return Object.freeze({
    transaction: transactionFor(intent, sizing.changeSats, canonicalUnlock(signature, intent.fundingPublicKey)),
    sourceOutputs,
  });
}

function validateFinal(intent, sizing, signed) {
  const raw = Buffer.from(encodeTransaction(signed.transaction));
  if (raw.length !== sizing.serializedBytes) {
    fail('BOOTSTRAP_FUNDING_INTERNAL', 'signed transaction differs from fixed-point serialized size');
  }
  const outputValue = signed.transaction.outputs.reduce(
    (total, entry) => total + entry.valueSatoshis,
    0n,
  );
  const feeSats = intent.source.valueSats - outputValue;
  if (feeSats !== sizing.feeSats || feeSats !== BigInt(raw.length)) {
    fail('BOOTSTRAP_FUNDING_INTERNAL', 'source value conservation or one-sat-per-byte fee failed');
  }
  const vm = createVirtualMachineBch2026(true);
  const verdict = vm.verify({
    sourceOutputs: signed.sourceOutputs,
    transaction: signed.transaction,
  });
  const roundTripVerdict = vm.verify({
    sourceOutputs: signed.sourceOutputs,
    transaction: decodedTransactionForVm(raw),
  });
  if (roundTripVerdict !== true) {
    fail('BOOTSTRAP_FUNDING_INTERNAL', `serialized funding transaction failed BCH_2026_STANDARD validation: ${roundTripVerdict}`);
  }
  if (verdict !== true) {
    fail('BOOTSTRAP_FUNDING_VM_REJECTED', `BCH_2026_STANDARD rejected bootstrap funding: ${verdict}`);
  }
  return Object.freeze({ raw, feeSats });
}

/**
 * Construct, sign, and locally execute one offline bootstrap-funding
 * transaction. The returned record contains no private key material.
 */
export function buildV2BetaChipnetBootstrapFunding(value) {
  const intent = normalize(value);
  const sizing = fixedPointSizing(intent);
  const signed = sign(intent, sizing);
  const checked = validateFinal(intent, sizing, signed);
  const transactionId = Buffer.from(hash256(checked.raw)).reverse().toString('hex');
  const lockHex = intent.lockingBytecode.toString('hex');
  const reserve = (outputIndex, purpose, valueSats) => Object.freeze({
    outputIndex,
    purpose,
    valueSats: valueSats.toString(),
    lockingBytecodeHex: lockHex,
  });
  return Object.freeze({
    schema: V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SCHEMA,
    transactionVersion: 2,
    locktime: 0,
    input: Object.freeze({
      transactionId: intent.source.transactionId,
      outputIndex: intent.source.outputIndex,
      valueSats: intent.source.valueSats.toString(),
      lockingBytecodeHex: lockHex,
      token: null,
      sequence: 0xffff_ffff,
      sighashType: V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_SIGHASH_TYPE,
      sighashContract: 'SIGHASH_ALL|FORKID',
    }),
    rawTransactionHex: checked.raw.toString('hex'),
    transactionId,
    serializedBytes: checked.raw.length,
    feeSats: checked.feeSats.toString(),
    feeRateSatsPerByte: V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_FEE_RATE_SATS_PER_BYTE,
    sourceOutput: reserve(0, 'category-genesis-source', intent.genesisSourceSats),
    actionFunding: Object.freeze({
      deposits: Object.freeze(V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_DEPOSIT_OUTPUTS.map(
        (outputIndex) => reserve(outputIndex, 'deposit', intent.depositReserveSats),
      )),
      withdrawals: Object.freeze(V2_BETA_CHIPNET_BOOTSTRAP_FUNDING_WITHDRAWAL_OUTPUTS.map(
        (outputIndex) => reserve(outputIndex, 'withdrawal', intent.withdrawalReserveSats),
      )),
    }),
    change: reserve(11, 'change', sizing.changeSats),
  });
}
