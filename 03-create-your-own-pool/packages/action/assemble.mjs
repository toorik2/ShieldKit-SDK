// Complete ten-input construction for the frozen G2 experiment. This module
// deliberately consumes already-proved PF7 unlocks; it never substitutes a
// digest-only proof or fabricates a verifier acceptance.
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import {
  createVirtualMachineBch2026,
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { ACTION_PACKET_BYTES, decodeActionPacket } from './packet.mjs';
import { generateFreshWitnessInputs } from './witness.mjs';
import { loadVerifierProfileBundle, parseStrictJson } from '../profile/load.mjs';
import { parsePf7CarrierAuthority } from '../prove/authority.mjs';
import { encodeSettlementContext } from './context.mjs';
import { encodeStateNftCommitment } from './state.mjs';

export const PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE = 1n;
export const COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES = 59_000;
export const INPUT_UNLOCKING_LIMIT_BYTES = 10_000;
export const PROJECT_P2S_LOCKING_LIMIT_BYTES = 190;

export class SettlementAssemblerError extends Error {}
const fail = (message) => { throw new SettlementAssemblerError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const hash160 = (bytes) => createHash('ripemd160').update(sha256(bytes)).digest();
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const HEX = /^[0-9a-f]*$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;
const bytes = (value, length, label) => {
  if (!(value instanceof Uint8Array)) fail(`${label} must be a Uint8Array`);
  const result = Buffer.from(value);
  if (length !== undefined && result.length !== length) fail(`${label} must be ${length} bytes`);
  return result;
};
const canonicalHexBytes = (value, length, label) => {
  if (typeof value !== 'string' || !HEX.test(value) || value.length % 2 !== 0 || (length !== undefined && value.length !== length * 2)) {
    fail(`${label} must be canonical lowercase hexadecimal${length === undefined ? '' : ` with ${length} bytes`}`);
  }
  return Buffer.from(value, 'hex');
};
const binaryOrHex = (value, length, label) => (
  typeof value === 'string' ? canonicalHexBytes(value, length, label) : bytes(value, length, label)
);
// The preparation API serializes transaction hashes in wire order as canonical
// lowercase hexadecimal. Accept that direct hand-off as well as an internal
// Uint8Array, never a UTF-8 string interpreted as bytes.
const wireHash = (value, label) => binaryOrHex(value, 32, label);
const p2pkh = (publicKey) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash160(publicKey), Buffer.from([0x88, 0xac])]);
const schnorrUnlock = (signature, publicKey) => Buffer.concat([Buffer.of(0x41), signature, Buffer.of(0x41, 0x21), publicKey]);
const packetUnlock = (packet) => Buffer.concat([Buffer.of(0x4d, 0xf0, 0x02), packet]);
const noToken = undefined;
const decimal = (value, label) => {
  const parsed = typeof value === 'bigint'
    ? value
    : typeof value === 'string' && DECIMAL.test(value) ? BigInt(value) : undefined;
  if (parsed === undefined || parsed < 0n || parsed > MAX_U64) fail(`${label} must be a canonical nonnegative u64 bigint or decimal string`);
  return parsed;
};
const u32 = (value, label) => {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > 0xffff_ffff) fail(`${label} must be a canonical u32 number`);
  return value;
};

// Load the complete hash-verified bundle at the public API boundary. Raw
// manifests are intentionally not accepted: they could be forged while
// preserving plausible-looking profile/genesis strings.
async function manifestGenesis(value) {
  if (typeof value.bundleDirectory !== 'string' || value.bundleDirectory.length === 0) fail('bundleDirectory must name an authenticated verifier-profile bundle');
  if (value.expectedProfile === null || typeof value.expectedProfile !== 'object' || Array.isArray(value.expectedProfile)) fail('expectedProfile must be an exact profile binding');
  let loaded;
  try { loaded = await loadVerifierProfileBundle(value.bundleDirectory, value.expectedProfile); }
  catch (error) { fail(`authenticated profile bundle rejected: ${error.message}`); }
  const manifest = loaded.manifest;
  const genesis = manifest.genesis;
  if (genesis === null || typeof genesis !== 'object' || Array.isArray(genesis)) fail('profileManifest.genesis is required');
  const required = ['categoryInputOutpoint', 'instanceId', 'network', 'profileId', 'reserveCapSatoshis', 'stateNftCategory'];
  const keys = Object.keys(genesis).sort();
  if (keys.length !== required.length || keys.some((key, index) => key !== required[index])) fail('profileManifest.genesis has missing or unknown properties');
  if (
    (genesis.network !== 'chipnet' && genesis.network !== 'mainnet')
    || manifest.network?.name !== genesis.network
  ) {
    fail('profileManifest genesis network must be chipnet or mainnet and match profile network');
  }
  if (typeof genesis.profileId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(genesis.profileId)) fail('profileManifest.genesis.profileId is invalid');
  if (typeof genesis.instanceId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(genesis.instanceId)) fail('profileManifest.genesis.instanceId is invalid');
  if (typeof genesis.stateNftCategory !== 'string' || !/^[0-9a-f]{64}$/.test(genesis.stateNftCategory)) fail('profileManifest.genesis.stateNftCategory is invalid');
  if (manifest.identity?.profileId !== genesis.profileId) fail('profileManifest identity does not match genesis profile');
  if (!['development-only', 'local-contribution-simulation'].includes(manifest.setup?.mode)) fail('profileManifest setup mode is unsupported');
  return Object.freeze({
    bundle: loaded,
    genesis,
    profileId: Buffer.from(genesis.profileId.slice('sha256:'.length), 'hex'),
    instanceId: Buffer.from(genesis.instanceId.slice('sha256:'.length), 'hex'),
    stateCategory: Buffer.from(genesis.stateNftCategory, 'hex'),
    maximumReserveSatoshis: genesis.reserveCapSatoshis,
    setupMode: manifest.setup.mode,
  });
}

async function profilePf7Roles(profile) {
  const artifact = profile.bundle.manifest.artifacts.find((entry) => entry.kind === 'bch-verifier-set');
  if (artifact === undefined) fail('authenticated profile has no bch-verifier-set artifact');
  const filename = path.resolve(profile.bundle.root, ...artifact.path.split('/'));
  let source;
  try { source = Buffer.from(await readFile(filename)); }
  catch { fail('authenticated profile bch-verifier-set artifact cannot be read'); }
  if (`sha256:${sha256(source).toString('hex')}` !== artifact.sha256) fail('authenticated profile bch-verifier-set artifact hash drifted');
  let record;
  try { record = parseStrictJson(source); }
  catch { fail('authenticated profile bch-verifier-set artifact is invalid JSON'); }
  let authority;
  try { authority = parsePf7CarrierAuthority(record); }
  catch (error) { fail(`authenticated profile bch-verifier-set carrier authority is invalid: ${error.message}`); }
  return Object.freeze({
    roles: Object.freeze(authority.carriers.map((carrier) => Object.freeze({
      lockingBytecode: Buffer.from(carrier.lockingBytecode),
      valueSatoshis: carrier.valueSatoshis,
    }))),
    settlementKernel: authority.settlementKernel,
  });
}

function stateToken(category, instanceId, state, networkId) {
  return {
    category: Uint8Array.from(category), amount: 0n,
    nft: {
      capability: 'mutable',
      commitment: encodeStateNftCommitment({
        networkId,
        instanceId: hex(instanceId),
        stateCommitment: state.stateCommitment,
        actionSequence: state.actionSequence,
      }),
    },
  };
}

function outputJson(output) {
  return {
    valueSatoshis: output.valueSatoshis.toString(), lockingBytecode: hex(output.lockingBytecode),
    token: output.token === undefined ? null : {
      category: hex(output.token.category), amount: output.token.amount.toString(),
      nft: { capability: output.token.nft.capability, commitment: hex(output.token.nft.commitment) },
    },
  };
}

function inputMetadata(input) {
  return {
    outpointTransactionHashWire: hex(Buffer.from(input.outpointTransactionHash).reverse()),
    outpointIndex: String(input.outpointIndex), sequenceNumber: String(input.sequenceNumber),
  };
}

async function requirePf7(value, expectedRoles) {
  if (!Array.isArray(value) || value.length !== 7) fail('pf7 must contain exactly the seven retained verifier roles');
  return value.map((row, index) => {
    if (row === null || typeof row !== 'object') fail(`pf7[${index}] must be an object`);
    const lock = binaryOrHex(row.lockingBytecode, 35, `pf7[${index}].lockingBytecode`);
    if (lock[0] !== 0xaa || lock[1] !== 0x20 || lock[34] !== 0x87) fail(`pf7[${index}] is not P2SH32`);
    if (!lock.equals(expectedRoles[index].lockingBytecode)) fail(`pf7[${index}] locking bytecode does not match authenticated profile verifier role`);
    const unlockingBytecode = binaryOrHex(row.unlockingBytecode, undefined, `pf7[${index}].unlockingBytecode`);
    if (unlockingBytecode.length === 0 || unlockingBytecode.length > INPUT_UNLOCKING_LIMIT_BYTES) fail(`pf7[${index}] unlocking bytecode is outside the 1..10000 byte limit`);
    const valueSatoshis = decimal(row.valueSatoshis, `pf7[${index}].valueSatoshis`);
    if (valueSatoshis !== expectedRoles[index].valueSatoshis) fail(`pf7[${index}] value does not match authenticated profile verifier carrier`);
    return {
      lockingBytecode: lock, unlockingBytecode,
      // Libauth's encoder uses Uint8Array#slice().reverse(). A Buffer's
      // slice is a view, so retaining Buffer here would let serialization
      // mutate the in-memory outpoint after the fee signature is made.
      outpointTransactionHash: Uint8Array.from(
        wireHash(row.outpointTransactionHashWire, `pf7[${index}].outpointTransactionHashWire`),
      ).reverse(),
      outpointIndex: u32(row.outpointIndex, `pf7[${index}].outpointIndex`), sequenceNumber: 0, valueSatoshis,
    };
  });
}

function sourceFor(input, token = noToken) {
  return { valueSatoshis: input.valueSatoshis, lockingBytecode: input.lockingBytecode, ...(token === undefined ? {} : { token }) };
}

function checkedPacket(value, profileId, instanceId) {
  const packet = bytes(value, ACTION_PACKET_BYTES, 'actionPacket');
  const decoded = decodeActionPacket(packet);
  if (decoded.preState.profileId !== hex(profileId) || decoded.preState.instanceId !== hex(instanceId)) fail('action packet identity differs from assembler identity');
  return { packet, decoded };
}

function fixedPointTransaction({ kind, inputs, sources, stateLock, postToken, stateValue, withdrawalLock, totalInputValue }) {
  const outputBase = [{ valueSatoshis: stateValue, lockingBytecode: stateLock, token: postToken }];
  if (kind === 'withdrawal') outputBase.push({ valueSatoshis: 10_000_000n, lockingBytecode: withdrawalLock });
  const changeLock = sources[9].lockingBytecode;
  let change = 1n;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    const transaction = { version: 2, locktime: 0, inputs, outputs: [...outputBase, { valueSatoshis: change, lockingBytecode: changeLock }] };
    const wireBytes = Buffer.from(encodeTransaction(transaction)).length;
    const nextChange = totalInputValue - outputBase.reduce((sum, output) => sum + output.valueSatoshis, 0n) - BigInt(wireBytes);
    if (nextChange <= 0n) fail('fee source cannot fund the exact one-sat-per-byte settlement fee');
    if (nextChange === change) return { transaction, wireBytes };
    change = nextChange;
  }
  fail('exact-fee transaction sizing did not converge');
}

/**
 * Assemble and sign one exact ten-input action. `pf7` must come from a real
 * PF7 build for this exact packet: the function checks the full context and
 * then the caller should run `verifyCompleteSettlementVm` over all ten inputs.
 */
async function constructCompleteG2Settlement(value, requirePacketContext) {
  if (value === null || typeof value !== 'object') fail('assembler input must be an object');
  const { kind } = value;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) fail('unsupported action kind');
  if (value.minimumFeeRateSatoshisPerByte !== PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE) fail('protocol fee rate is fixed at exactly 1 satoshi per byte');
  const profile = await manifestGenesis(value);
  const { profileId, instanceId, stateCategory } = profile;
  // Fee auth policy A: feePrivateKey in-process.
  // Fee auth policy B: feePublicKey + feeSignature (caller-signed; no private key in assembler).
  const hasFeeKey = value.feePrivateKey !== undefined && value.feePrivateKey !== null;
  const hasFeePub = value.feePublicKey !== undefined && value.feePublicKey !== null;
  if (hasFeeKey === hasFeePub) fail('exactly one of feePrivateKey (policy A) or feePublicKey (policy B) is required');
  const authority = await profilePf7Roles(profile);
  const pf7 = await requirePf7(value.pf7, authority.roles);
  const { packet, decoded } = checkedPacket(value.actionPacket, profileId, instanceId);
  if (decoded.kind !== kind) fail('action packet kind differs from assembler kind');
  const bindingCarrierBaseSatoshis = decimal(value.bindingCarrierBaseSatoshis, 'bindingCarrierBaseSatoshis');
  const stateCarrierBaseSatoshis = decimal(value.stateCarrierBaseSatoshis, 'stateCarrierBaseSatoshis');
  if (bindingCarrierBaseSatoshis !== 1_000n) fail('bindingCarrierBaseSatoshis does not match the authenticated settlement kernel');
  if (stateCarrierBaseSatoshis !== 1_080n) fail('stateCarrierBaseSatoshis does not match the authenticated settlement kernel');
  const feeSourceValueSatoshis = decimal(value.feeSourceValueSatoshis, 'feeSourceValueSatoshis');
  const stateOutpointTransactionHash = Uint8Array.from(
    wireHash(value.stateOutpointTransactionHashWire, 'stateOutpointTransactionHashWire'),
  ).reverse();
  const stateOutpointIndex = u32(value.stateOutpointIndex, 'stateOutpointIndex');
  const prepHash = wireHash(value.preparationTransactionHashWire, 'preparationTransactionHashWire');
  const preparationParent = Uint8Array.from(prepHash).reverse();
  for (let index = 0; index < pf7.length; index += 1) {
    if (
      !Buffer.from(pf7[index].outpointTransactionHash).equals(preparationParent)
      || pf7[index].outpointIndex !== index
    ) {
      fail(`pf7[${index}] must spend preparation output ${index}`);
    }
  }
  const withdrawalLock = kind === 'withdrawal' ? binaryOrHex(value.withdrawalLockingBytecode, undefined, 'withdrawalLockingBytecode') : undefined;
  if (kind === 'withdrawal' && hex(sha256(withdrawalLock)) !== decoded.withdrawalScriptHash) fail('withdrawal lock does not match packet hash');

  const {
    bindingLock, stateHelper: helper, stateHelperUnlock: stateUnlock, stateLock,
  } = authority.settlementKernel;
  if (bindingLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES || stateLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES) fail('P2S locking-bytecode limit exceeded');
  if (stateUnlock.length > INPUT_UNLOCKING_LIMIT_BYTES) fail('state helper unlocking-bytecode limit exceeded');

  const secp256k1 = await instantiateSecp256k1();
  let privateKey = null;
  let publicKey;
  if (hasFeeKey) {
    privateKey = bytes(value.feePrivateKey, 32, 'feePrivateKey');
    publicKey = secp256k1.derivePublicKeyCompressed(privateKey);
    if (typeof publicKey === 'string') fail('fee private key is invalid');
  } else {
    publicKey = binaryOrHex(value.feePublicKey, 33, 'feePublicKey');
  }
  const feeLock = p2pkh(publicKey);
  const sources = [
    ...pf7.map((row) => sourceFor(row)),
    { valueSatoshis: bindingCarrierBaseSatoshis + (kind === 'deposit' ? 10_000_000n : 0n), lockingBytecode: bindingLock },
    { valueSatoshis: stateCarrierBaseSatoshis + BigInt(decoded.preState.reserveSats), lockingBytecode: stateLock, token: stateToken(stateCategory, instanceId, decoded.preState, decoded.networkId) },
    { valueSatoshis: feeSourceValueSatoshis, lockingBytecode: feeLock },
  ];
  const inputs = [
    ...pf7.map((row) => ({ ...row })),
    { outpointTransactionHash: preparationParent, outpointIndex: 7, sequenceNumber: 0, unlockingBytecode: packetUnlock(packet) },
    { outpointTransactionHash: stateOutpointTransactionHash, outpointIndex: stateOutpointIndex, sequenceNumber: 0, unlockingBytecode: stateUnlock },
    { outpointTransactionHash: preparationParent, outpointIndex: 8, sequenceNumber: 0, unlockingBytecode: schnorrUnlock(Buffer.alloc(64), publicKey) },
  ];
  const totalInputValue = sources.reduce((sum, source) => sum + source.valueSatoshis, 0n);
  const { transaction: unsignedTransaction, wireBytes: unsignedWireBytes } = fixedPointTransaction({
    kind, inputs, sources, stateLock, postToken: stateToken(stateCategory, instanceId, decoded.postState, decoded.networkId),
    stateValue: stateCarrierBaseSatoshis + BigInt(decoded.postState.reserveSats), withdrawalLock, totalInputValue,
  });
  const provisionalContext = encodeSettlementContext({
    kind, profileId: hex(profileId), instanceId: hex(instanceId), sourceOutputs: sources.map(outputJson),
    transaction: { version: '2', locktime: '0', inputs: unsignedTransaction.inputs.map(inputMetadata), outputs: unsignedTransaction.outputs.map(outputJson) },
  });
  if (requirePacketContext && provisionalContext.digestHex !== decoded.transactionContextDigest) fail('action packet context digest does not bind this exact settlement');
  const signingSerialization = generateSigningSerializationBch({ inputIndex: 9, sourceOutputs: sources, transaction: unsignedTransaction }, {
    coveredBytecode: feeLock, signingSerializationType: Uint8Array.of(SigningSerializationTypeBch.allOutputs),
  });
  const signingDigest = hash256(signingSerialization);
  let signature;
  if (privateKey) {
    signature = secp256k1.signMessageHashSchnorr(privateKey, signingDigest);
    if (typeof signature === 'string') fail('unable to create fee signature');
  } else if (value.feeSignature !== undefined && value.feeSignature !== null) {
    signature = binaryOrHex(value.feeSignature, 64, 'feeSignature');
    // Validate policy-B signature against the exact settlement fee digest.
    if (secp256k1.verifySignatureSchnorr(signature, publicKey, signingDigest) !== true) {
      fail('feeSignature does not verify for feePublicKey over settlement fee sighash');
    }
  } else if (requirePacketContext) {
    fail('assemble requires feePrivateKey (A) or feePublicKey+feeSignature (B)');
  } else {
    // plan-only: dummy unlock; SCCT excludes unlocking bytecode so digest is stable
    signature = Buffer.alloc(64);
  }
  unsignedTransaction.inputs[9].unlockingBytecode = schnorrUnlock(signature, publicKey);
  const encodedTransaction = Buffer.from(encodeTransaction(unsignedTransaction));
  const feeSatoshis = totalInputValue - unsignedTransaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
  if (encodedTransaction.length !== unsignedWireBytes || feeSatoshis !== BigInt(encodedTransaction.length)) fail('exact one-satoshi-per-byte fee invariant failed');
  if (encodedTransaction.length > COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES) fail('complete transaction exceeds 59000 bytes');
  if (Math.max(...unsignedTransaction.inputs.map((input) => input.unlockingBytecode.length)) > INPUT_UNLOCKING_LIMIT_BYTES) fail('per-input unlocking-bytecode limit exceeded');
  return Object.freeze({
    schema: 'shield.cash/g2-complete-settlement/v1', kind,
    qualification: profile.setupMode === 'development-only' ? 'development-only' : 'ceremony-profile-unqualified',
    transaction: unsignedTransaction,
    sourceOutputs: sources, encodedTransaction, actionPacket: packet,
    context: provisionalContext,
    feeSigning: Object.freeze({
      algorithm: 'schnorr-bch-all-forkid',
      inputIndex: 9,
      publicKeyHex: hex(publicKey),
      signingSerializationHex: hex(signingSerialization),
      signingDigestHex: hex(signingDigest),
      policy: privateKey ? 'A-in-process-key' : (value.feeSignature ? 'B-presigned' : 'plan-unsigned'),
    }),
    locks: Object.freeze({ bindingLock, stateLock, stateHelper: helper }),
    measurements: Object.freeze({ wireBytes: encodedTransaction.length, feeSatoshis, feeRateSatoshisPerByte: PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE, maximumUnlockingBytes: Math.max(...unsignedTransaction.inputs.map((input) => input.unlockingBytecode.length)), bindingLockBytes: bindingLock.length, stateLockBytes: stateLock.length, stateUnlockBytes: stateUnlock.length }),
  });
}

/**
 * Produce the exact context commitment a prover must put in a fresh packet.
 * This returns no transaction: the temporary packet supplied for state fields
 * is explicitly not authorized for broadcast until `assemble...` rechecks it.
 */
export async function planCompleteSettlement(value) {
  const constructed = await constructCompleteG2Settlement(value, false);
  return Object.freeze({
    schema: 'shield.cash/g2-complete-settlement-plan/v1', kind: constructed.kind,
    qualification: constructed.qualification,
    context: constructed.context,
    feeSigning: constructed.feeSigning,
    expectedWireBytes: constructed.measurements.wireBytes,
    expectedFeeSatoshis: constructed.measurements.feeSatoshis,
    lockBytes: Object.freeze({ binding: constructed.measurements.bindingLockBytes, state: constructed.measurements.stateLockBytes }),
    unlockingBytes: Object.freeze({ maximum: constructed.measurements.maximumUnlockingBytes, state: constructed.measurements.stateUnlockBytes }),
  });
}

export async function assembleCompleteSettlement(value) {
  return constructCompleteG2Settlement(value, true);
}

/**
 * Bind fixed-point settlement contexts to the authenticated fresh-witness
 * pipeline without fabricating a proof. The first witness pass has zero
 * context digests solely to obtain the immutable action state fields; SCCT
 * intentionally excludes unlocking bytecode, so its derived digest is
 * independent of that temporary packet field. The second pass receives the
 * derived digests and yields the only packets eligible for real proving/PF7.
 *
 * `settlements[kind]` must contain real seven-role PF7 material from the
 * current profile-bound corpus. This routine does not substitute it and does
 * not claim a complete transaction until `assemble...` succeeds afterwards.
 */
export async function generateWitnessBoundSettlementPlans(value) {
  if (value === null || typeof value !== 'object') fail('witness-bound plan input must be an object');
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== 'settlements' || keys[1] !== 'witness') fail('witness-bound plan input must contain only settlements and witness');
  if (value.settlements === null || typeof value.settlements !== 'object' || Array.isArray(value.settlements)) fail('settlements must be an object');
  const kinds = ['deposit', 'transfer', 'withdrawal'];
  if (Object.keys(value.settlements).sort().join(',') !== kinds.join(',')) fail('settlements must contain deposit, transfer, and withdrawal');
  const zeroContexts = Object.freeze(Object.fromEntries(kinds.map((kind) => [kind, '00'.repeat(32)])));
  const seed = await generateFreshWitnessInputs({ ...value.witness, transactionContextDigests: zeroContexts });
  const planFor = async (kind, packet) => {
    const supplied = value.settlements[kind];
    if (supplied === null || typeof supplied !== 'object' || Array.isArray(supplied)) fail(`settlements.${kind} must be an object`);
    if (supplied.kind !== kind) fail(`settlements.${kind}.kind mismatch`);
    return planCompleteSettlement({
      ...supplied,
      bundleDirectory: value.witness.bundleDirectory,
      expectedProfile: value.witness.expectedProfile,
      actionPacket: packet,
    });
  };
  const initialPlans = Object.fromEntries(await Promise.all(kinds.map(async (kind) => [kind, await planFor(kind, seed.actions[kind].actionPacket)])));
  const exactContexts = Object.freeze(Object.fromEntries(kinds.map((kind) => [kind, initialPlans[kind].context.digestHex])));
  const witness = await generateFreshWitnessInputs({ ...value.witness, transactionContextDigests: exactContexts });
  const plans = Object.fromEntries(await Promise.all(kinds.map(async (kind) => [kind, await planFor(kind, witness.actions[kind].actionPacket)])));
  for (const kind of kinds) {
    if (plans[kind].context.digestHex !== exactContexts[kind]) fail(`${kind} SCCT digest changed across witness fixed point`);
  }
  return Object.freeze({
    schema: 'shield.cash/g2-witness-bound-settlement-plans/v1',
    qualification: 'development-only fixed-point planning; requires fresh real proof/PF7 corpus and complete VM verification',
    profile: seed.profile,
    witness,
    plans: Object.freeze(plans),
  });
}

/** Execute every role separately in the unmodified Libauth BCH-2026 VM. */
export function verifyCompleteSettlementVm(candidate, standard = true) {
  const vm = createVirtualMachineBch2026(standard);
  return candidate.transaction.inputs.map((_, inputIndex) => vm.evaluate({ inputIndex, sourceOutputs: candidate.sourceOutputs, transaction: candidate.transaction }));
}

/** Classify every one of the ten independent BCH-VM role evaluations. */
export function classifyCompleteSettlementVm(candidate, standard = true) {
  const results = verifyCompleteSettlementVm(candidate, standard);
  const failedInputIndexes = results.flatMap((result, inputIndex) => (
    result.error === undefined && result.stack.length === 1 && result.stack[0].some((byte) => byte !== 0)
      ? [] : [inputIndex]
  ));
  return Object.freeze({
    standard,
    inputCount: results.length,
    accepted: failedInputIndexes.length === 0,
    failedInputIndexes: Object.freeze(failedInputIndexes),
    results: Object.freeze(results),
  });
}
