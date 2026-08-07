// Offline-only construction of the category-creating Chipnet genesis
// transaction. This module has no wallet, network, broadcaster, or private-key
// API: callers receive exact signing bytes and supply only a final signature.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  createVirtualMachineBch2026,
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { loadVerifierProfileBundle, parseStrictJson } from './load.mjs';
import { parsePf7CarrierAuthority } from '../prove/authority.mjs';
import { createShieldedTransitionReference } from '../action/transition.mjs';
import { encodeStateNftCommitment } from '../action/state.mjs';

/** Fixed protocol fee rate: exactly 1 satoshi per serialized byte. */
export const CHIPNET_GENESIS_FEE_RATE_SATOSHIS_PER_BYTE = 1n;
/** Alias — same rate for all networks. */
export const PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE = CHIPNET_GENESIS_FEE_RATE_SATOSHIS_PER_BYTE;
export const PROJECT_P2S_LOCKING_LIMIT_BYTES = 190;
// Libauth BCH-2026 standardness rejects the P2S state output below 1,080 sats.
export const MINIMUM_STATE_CARRIER_SATOSHIS = 1_080n;

const HEX = /^[0-9a-f]*$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

export class ChipnetGenesisError extends Error {
  constructor(message) { super(message); this.name = 'ChipnetGenesisError'; }
}

const fail = (message) => { throw new ChipnetGenesisError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const hash160 = (bytes) => createHash('ripemd160').update(sha256(bytes)).digest();
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const exactKeys = (value, label, expected) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
};
const decimal = (value, label, minimum = 0n) => {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed > MAX_U64 || parsed < minimum) fail(`${label} is outside its allowed range`);
  return parsed;
};
const bytes = (value, length, label) => {
  if (typeof value !== 'string' || !HEX.test(value) || value.length % 2 !== 0 || (length !== undefined && value.length !== length * 2)) fail(`${label} must be canonical lowercase hexadecimal`);
  return Buffer.from(value, 'hex');
};
const p2pkh = (publicKey) => Buffer.concat([Buffer.of(0x76, 0xa9, 0x14), hash160(publicKey), Buffer.of(0x88, 0xac)]);
const schnorrUnlock = (signature, publicKey) => Buffer.concat([Buffer.of(0x41), signature, Buffer.of(0x41, 0x21), publicKey]);

function outputJson(output) {
  return Object.freeze({
    valueSatoshis: output.valueSatoshis.toString(),
    lockingBytecode: hex(output.lockingBytecode),
    token: output.token === undefined ? null : Object.freeze({
      category: hex(output.token.category), amount: output.token.amount.toString(),
      nft: Object.freeze({ capability: output.token.nft.capability, commitment: hex(output.token.nft.commitment) }),
    }),
  });
}

async function loadProfile(value) {
  if (typeof value.bundleDirectory !== 'string' || value.bundleDirectory.length === 0) fail('bundleDirectory must name an authenticated profile bundle');
  if (value.expectedProfile === null || typeof value.expectedProfile !== 'object' || Array.isArray(value.expectedProfile)) fail('expectedProfile must atomically bind network, profile, and instance');
  let bundle;
  try { bundle = await loadVerifierProfileBundle(value.bundleDirectory, value.expectedProfile); }
  catch (error) { fail(`authenticated profile bundle rejected: ${error.message}`); }
  const { manifest } = bundle;
  const net = manifest.network?.name || manifest.network;
  const genesisNet = manifest.genesis?.network?.name || manifest.genesis?.network;
  if ((net !== 'chipnet' && net !== 'mainnet') || (genesisNet !== undefined && genesisNet !== net)) {
    fail('profile network must be chipnet or mainnet and must match genesis.network when set');
  }
  if (manifest.setup?.mode !== 'development-only'
    && manifest.setup?.mode !== 'local-contribution-simulation') {
    fail('profile setup mode is unsupported');
  }
  // SCAR wire networkId is pin-fixed (circuit hardcodes 2); BCH chain is `net`.
  const networkId = 2;
  return Object.freeze({
    bundle,
    network: net,
    networkId,
    profileId: Buffer.from(bundle.profileId.slice('sha256:'.length), 'hex'),
    instanceId: Buffer.from(bundle.instanceId.slice('sha256:'.length), 'hex'),
    stateCategory: Buffer.from(manifest.genesis.stateNftCategory, 'hex'),
    reserveCapSatoshis: manifest.genesis.reserveCapSatoshis,
  });
}

async function loadPf7Locks(profile) {
  const artifact = profile.bundle.manifest.artifacts.find((entry) => entry.kind === 'bch-verifier-set');
  if (artifact === undefined) fail('authenticated profile has no bch-verifier-set artifact');
  const filename = path.resolve(profile.bundle.root, ...artifact.path.split('/'));
  let source;
  try { source = Buffer.from(await readFile(filename)); } catch { fail('bch-verifier-set cannot be read'); }
  if (`sha256:${sha256(source).toString('hex')}` !== artifact.sha256) fail('bch-verifier-set hash drifted after profile load');
  let record;
  try { record = parseStrictJson(source); } catch { fail('bch-verifier-set is not strict JSON'); }
  let authority;
  try { authority = parsePf7CarrierAuthority(record); }
  catch (error) { fail(`bch-verifier-set carrier authority is invalid: ${error.message}`); }
  return Object.freeze({
    locks: Object.freeze(authority.carriers.map((carrier) => Buffer.from(carrier.lockingBytecode))),
    values: Object.freeze(authority.carriers.map((carrier) => carrier.valueSatoshis)),
    settlementKernel: authority.settlementKernel,
  });
}

function parseRequest(value) {
  exactKeys(value, 'genesis request', [
    'bindingCarrierBaseSatoshis', 'bundleDirectory', 'categoryInput', 'expectedProfile',
    'minimumFeeRateSatoshisPerByte', 'stateCarrierBaseSatoshis',
  ]);
  exactKeys(value.categoryInput, 'categoryInput', [
    'lockingBytecode', 'outpointIndex', 'outpointTransactionHashWire', 'publicKey', 'token', 'valueSatoshis',
  ]);
  if (value.categoryInput.outpointIndex !== '0') fail('categoryInput must spend vout 0 to create the state NFT category');
  const outpointWire = bytes(value.categoryInput.outpointTransactionHashWire, 32, 'categoryInput.outpointTransactionHashWire');
  const publicKey = bytes(value.categoryInput.publicKey, 33, 'categoryInput.publicKey');
  if (![0x02, 0x03].includes(publicKey[0])) fail('categoryInput.publicKey must be compressed');
  const lockingBytecode = bytes(value.categoryInput.lockingBytecode, 25, 'categoryInput.lockingBytecode');
  if (!lockingBytecode.equals(p2pkh(publicKey))) fail('categoryInput locking bytecode must be the declared canonical P2PKH key lock');
  if (value.categoryInput.token !== null) fail('categoryInput must be tokenless; genesis creates the sole state NFT');
  const sourceValue = decimal(value.categoryInput.valueSatoshis, 'categoryInput.valueSatoshis');
  const stateCarrier = decimal(value.stateCarrierBaseSatoshis, 'stateCarrierBaseSatoshis', MINIMUM_STATE_CARRIER_SATOSHIS);
  const bindingCarrier = decimal(value.bindingCarrierBaseSatoshis, 'bindingCarrierBaseSatoshis', 1n);
  if (bindingCarrier !== 1_000n || stateCarrier !== MINIMUM_STATE_CARRIER_SATOSHIS) fail('carrier bases must match the authenticated settlement kernel');
  if (decimal(value.minimumFeeRateSatoshisPerByte, 'minimumFeeRateSatoshisPerByte') !== CHIPNET_GENESIS_FEE_RATE_SATOSHIS_PER_BYTE) fail('minimumFeeRateSatoshisPerByte must equal the fixed protocol rate of 1');
  return Object.freeze({ outpointWire, publicKey, lockingBytecode, sourceValue, stateCarrier, bindingCarrier });
}

function categoryInputForProfile(parsed, profile) {
  const expectedWire = Buffer.from(profile.stateCategory).reverse();
  if (!parsed.outpointWire.equals(expectedWire)) fail('categoryInput outpoint does not match the profile-bound category input transaction');
}

function transactionFor(parsed, stateLock, stateToken, signature, changeValue) {
  return {
    version: 2,
    inputs: [{
      outpointTransactionHash: Uint8Array.from(parsed.outpointWire).reverse(), outpointIndex: 0,
      sequenceNumber: 0, unlockingBytecode: schnorrUnlock(signature, parsed.publicKey),
    }],
    outputs: [
      { valueSatoshis: parsed.stateCarrier, lockingBytecode: stateLock, token: stateToken },
      { valueSatoshis: changeValue, lockingBytecode: parsed.lockingBytecode },
    ],
    locktime: 0,
  };
}

async function derive(value) {
  const parsed = parseRequest(value); const profile = await loadProfile(value); categoryInputForProfile(parsed, profile);
  const pf7 = await loadPf7Locks(profile);
  const {
    bindingLock, stateHelper: helper, stateLock, stateHelperUnlock: stateUnlock,
  } = pf7.settlementKernel;
  if (bindingLock.length === 0 || bindingLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES || stateLock.length === 0 || stateLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES) fail('state or binding P2S lock exceeds the 190-byte project limit');
  const reference = await createShieldedTransitionReference();
  const initialState = reference.emptyState({ profileId: hex(profile.profileId), instanceId: hex(profile.instanceId), maximumReserve: profile.reserveCapSatoshis });
  const stateToken = {
    category: Uint8Array.from(profile.stateCategory), amount: 0n,
    nft: { capability: 'mutable', commitment: encodeStateNftCommitment({
      networkId: profile.networkId,
      instanceId: hex(profile.instanceId),
      stateCommitment: initialState.stateCommitment,
      actionSequence: initialState.actionSequence,
    }) },
  };
  const sizing = transactionFor(parsed, stateLock, stateToken, Buffer.alloc(64), 1n);
  const wireBytes = Buffer.from(encodeTransaction(sizing)).length;
  const fee = BigInt(wireBytes) * CHIPNET_GENESIS_FEE_RATE_SATOSHIS_PER_BYTE;
  const change = parsed.sourceValue - parsed.stateCarrier - fee;
  if (change <= 0n) fail('categoryInput cannot fund the state carrier and exact one-satoshi-per-byte fee');
  const transaction = transactionFor(parsed, stateLock, stateToken, Buffer.alloc(64), change);
  if (Buffer.from(encodeTransaction(transaction)).length !== wireBytes) fail('genesis sizing changed after fixed-point fee calculation');
  const sourceOutput = { valueSatoshis: parsed.sourceValue, lockingBytecode: parsed.lockingBytecode };
  const signingSerialization = Buffer.from(generateSigningSerializationBch({ inputIndex: 0, sourceOutputs: [sourceOutput], transaction }, {
    coveredBytecode: parsed.lockingBytecode,
    signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  }));
  return Object.freeze({ parsed, profile, bindingLock, helper, stateLock, stateUnlock, initialState, stateToken, transaction, sourceOutput, signingSerialization, wireBytes, fee, change });
}

/** Plan an exact offline-only Chipnet genesis. No wallet secret is accepted. */
export async function planChipnetGenesisTransaction(value) {
  const plan = await derive(value);
  return Object.freeze({
    schema: 'shield.cash/chipnet-genesis-plan/v1',
    qualification: plan.profile.bundle.manifest.setup.mode === 'development-only' ? 'development-only offline construction only; no broadcast or qualification claim' : 'offline construction only; no broadcast or qualification claim',
    unsignedTransaction: Object.freeze({ ...plan.transaction, inputs: Object.freeze([{ ...plan.transaction.inputs[0], unlockingBytecode: new Uint8Array() }]), outputs: Object.freeze(plan.transaction.outputs.map(Object.freeze)) }),
    sourceOutput: Object.freeze(outputJson(plan.sourceOutput)),
    profile: Object.freeze({ profileId: plan.profile.bundle.profileId, instanceId: plan.profile.bundle.instanceId, stateNftCategory: hex(plan.profile.stateCategory), reserveCapSatoshis: plan.profile.reserveCapSatoshis }),
    initialState: Object.freeze(initialStateJson(plan.initialState)),
    settlementConstants: Object.freeze({ bindingCarrierBaseSatoshis: plan.parsed.bindingCarrier.toString(), stateCarrierBaseSatoshis: plan.parsed.stateCarrier.toString(), bindingLockingBytecode: hex(plan.bindingLock), stateLockingBytecode: hex(plan.stateLock), stateHelperSha256: hex(sha256(plan.helper)), stateHelperUnlockSha256: hex(sha256(plan.stateUnlock)), stateHelperUnlockingBytes: plan.stateUnlock.length }),
    signing: Object.freeze({ algorithm: 'schnorr-bch-all-forkid', sighashType: '41', signingSerializationHex: hex(plan.signingSerialization), signingDigestHex: hex(hash256(plan.signingSerialization)) }),
    measurements: Object.freeze({ wireBytes: plan.wireBytes, feeSatoshis: plan.fee.toString(), feeRateSatoshisPerByte: '1', stateNftCommitmentBytes: plan.stateToken.nft.commitment.length, stateLockingBytecodeBytes: plan.stateLock.length, bindingLockingBytecodeBytes: plan.bindingLock.length }),
    blockers: Object.freeze([]),
  });
}

function initialStateJson(state) {
  return Object.fromEntries(Object.entries(state));
}

/** Finalize using a caller-provided 64-byte Schnorr signature; validate the actual BCH-2026 P2PKH execution. */
export async function finalizeChipnetGenesisTransaction(value, signatureHex) {
  const signature = bytes(signatureHex, 64, 'signature'); const plan = await derive(value);
  const transaction = transactionFor(plan.parsed, plan.stateLock, plan.stateToken, signature, plan.change);
  const encodedTransaction = Buffer.from(encodeTransaction(transaction));
  if (encodedTransaction.length !== plan.wireBytes) fail('final signature changed the planned transaction size');
  const vm = createVirtualMachineBch2026(true);
  const verdict = vm.verify({ sourceOutputs: [plan.sourceOutput], transaction });
  if (verdict !== true) fail(`categoryInput transaction is not accepted by the standard BCH-2026 VM: ${verdict}`);
  const fee = plan.parsed.sourceValue - transaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
  if (fee !== BigInt(encodedTransaction.length)) fail('final genesis fee is not exactly one satoshi per serialized byte');
  const hashWire = Buffer.from(hash256(encodedTransaction));
  return Object.freeze({
    schema: 'shield.cash/chipnet-genesis-transaction/v1', qualification: 'offline construction only; no broadcast, relay, inclusion, or qualification claim',
    transaction, encodedTransaction, transactionHex: hex(encodedTransaction), transactionId: hex(Buffer.from(hashWire).reverse()),
    sourceOutput: Object.freeze(outputJson(plan.sourceOutput)), profile: Object.freeze({ profileId: plan.profile.bundle.profileId, instanceId: plan.profile.bundle.instanceId, stateNftCategory: hex(plan.profile.stateCategory), reserveCapSatoshis: plan.profile.reserveCapSatoshis }),
    initialState: Object.freeze(initialStateJson(plan.initialState)),
    settlementConstants: Object.freeze({ bindingCarrierBaseSatoshis: plan.parsed.bindingCarrier.toString(), stateCarrierBaseSatoshis: plan.parsed.stateCarrier.toString(), bindingLockingBytecode: hex(plan.bindingLock), stateLockingBytecode: hex(plan.stateLock), stateHelperSha256: hex(sha256(plan.helper)), stateHelperUnlockSha256: hex(sha256(plan.stateUnlock)), stateHelperUnlockingBytes: plan.stateUnlock.length }),
    measurements: Object.freeze({ wireBytes: encodedTransaction.length, feeSatoshis: fee.toString(), feeRateSatoshisPerByte: '1', stateNftCommitmentBytes: plan.stateToken.nft.commitment.length, stateLockingBytecodeBytes: plan.stateLock.length, bindingLockingBytecodeBytes: plan.bindingLock.length, bch2026StandardP2pkhVmAccepted: true }),
    blockers: Object.freeze([]),
  });
}
