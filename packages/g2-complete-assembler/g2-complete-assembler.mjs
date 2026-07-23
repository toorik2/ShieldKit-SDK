// Complete ten-input construction for the frozen G2 experiment. This module
// deliberately consumes already-proved PF7 unlocks; it never substitutes a
// digest-only proof or fabricates a verifier acceptance.
import { createHash } from 'node:crypto';
import {
  createVirtualMachineBch2026,
  encodeTransaction,
  generateSigningSerializationBch,
  hash256,
  instantiateSecp256k1,
  SigningSerializationTypeBch,
} from '@bitauth/libauth';
import { ACTION_PACKET_BYTES, CHIPNET_NETWORK_ID, decodeActionPacket } from '../action-packet/action-packet.mjs';
import { encodeSettlementContext } from '../settlement-context/settlement-context.mjs';
import { encodeStateNftCommitment } from '../state-nft/state-nft.mjs';
import {
  buildPacketOnlyBindingLock,
  buildStateSettlementHelper,
  buildStateTrampolineLock,
  buildStateTrampolineUnlock,
} from '../../bch/g2-compressed-covenants/compressed-covenants.mjs';

export const PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE = 1n;
export const COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES = 59_000;
export const INPUT_UNLOCKING_LIMIT_BYTES = 10_000;
export const PROJECT_P2S_LOCKING_LIMIT_BYTES = 190;

export class G2CompleteAssemblerError extends Error {}
const fail = (message) => { throw new G2CompleteAssemblerError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest();
const hash160 = (bytes) => createHash('ripemd160').update(sha256(bytes)).digest();
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const bytes = (value, length, label) => {
  const result = Buffer.from(value);
  if (length !== undefined && result.length !== length) fail(`${label} must be ${length} bytes`);
  return result;
};
const wireHash = (value, label) => bytes(value, 32, label);
const p2pkh = (publicKey) => Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), hash160(publicKey), Buffer.from([0x88, 0xac])]);
const schnorrUnlock = (signature, publicKey) => Buffer.concat([Buffer.of(0x41), signature, Buffer.of(0x41, 0x21), publicKey]);
const packetUnlock = (packet) => Buffer.concat([Buffer.of(0x4d, 0xf0, 0x02), packet]);
const noToken = undefined;
const decimal = (value, label) => {
  if (typeof value !== 'bigint' || value < 0n) fail(`${label} must be a nonnegative bigint`);
  return value;
};

// The caller supplies the genesis object from its already-validated profile
// manifest. The assembler deliberately derives every identity/cap fact below
// from that object; it must not construct a parallel set of genesis facts.
function manifestGenesis(value) {
  const manifest = value.profileManifest;
  if (manifest === null || typeof manifest !== 'object' || Array.isArray(manifest)) fail('profileManifest must be an authenticated verifier-profile manifest object');
  const genesis = manifest.genesis;
  if (genesis === null || typeof genesis !== 'object' || Array.isArray(genesis)) fail('profileManifest.genesis is required');
  const required = ['categoryInputOutpoint', 'instanceId', 'network', 'profileId', 'reserveCapSatoshis', 'stateNftCategory'];
  const keys = Object.keys(genesis).sort();
  if (keys.length !== required.length || keys.some((key, index) => key !== required[index])) fail('profileManifest.genesis has missing or unknown properties');
  if (genesis.network !== 'chipnet' || manifest.network?.name !== 'chipnet') fail('profileManifest genesis must be a Chipnet binding');
  if (typeof genesis.profileId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(genesis.profileId)) fail('profileManifest.genesis.profileId is invalid');
  if (typeof genesis.instanceId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(genesis.instanceId)) fail('profileManifest.genesis.instanceId is invalid');
  if (typeof genesis.stateNftCategory !== 'string' || !/^[0-9a-f]{64}$/.test(genesis.stateNftCategory)) fail('profileManifest.genesis.stateNftCategory is invalid');
  if (manifest.identity?.profileId !== genesis.profileId) fail('profileManifest identity does not match genesis profile');
  return Object.freeze({
    genesis,
    profileId: Buffer.from(genesis.profileId.slice('sha256:'.length), 'hex'),
    instanceId: Buffer.from(genesis.instanceId.slice('sha256:'.length), 'hex'),
    stateCategory: Buffer.from(genesis.stateNftCategory, 'hex'),
    maximumReserveSatoshis: genesis.reserveCapSatoshis,
  });
}

function stateToken(category, profileId, state) {
  return {
    category: Uint8Array.from(category), amount: 0n,
    nft: {
      capability: 'mutable',
      commitment: encodeStateNftCommitment({
        networkId: CHIPNET_NETWORK_ID,
        profileId: hex(profileId),
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

function requirePf7(value) {
  if (!Array.isArray(value) || value.length !== 7) fail('pf7 must contain exactly the seven retained verifier roles');
  return value.map((row, index) => {
    if (row === null || typeof row !== 'object') fail(`pf7[${index}] must be an object`);
    const lock = bytes(row.lockingBytecode, 35, `pf7[${index}].lockingBytecode`);
    if (lock[0] !== 0xaa || lock[1] !== 0x20 || lock[34] !== 0x87) fail(`pf7[${index}] is not P2SH32`);
    const unlockingBytecode = Buffer.from(row.unlockingBytecode);
    if (unlockingBytecode.length === 0 || unlockingBytecode.length > INPUT_UNLOCKING_LIMIT_BYTES) fail(`pf7[${index}] unlocking bytecode is outside the 1..10000 byte limit`);
    return {
      lockingBytecode: lock, unlockingBytecode,
      outpointTransactionHash: wireHash(row.outpointTransactionHashWire, `pf7[${index}].outpointTransactionHashWire`).reverse(),
      outpointIndex: Number(row.outpointIndex), sequenceNumber: 0, valueSatoshis: decimal(row.valueSatoshis, `pf7[${index}].valueSatoshis`),
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
 * then the caller should run `verifyCompleteG2Vm` over all ten inputs.
 */
async function constructCompleteG2Settlement(value, requirePacketContext) {
  if (value === null || typeof value !== 'object') fail('assembler input must be an object');
  const { kind } = value;
  if (!['deposit', 'transfer', 'withdrawal'].includes(kind)) fail('unsupported action kind');
  if (value.minimumFeeRateSatoshisPerByte !== PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE) fail('protocol fee rate is fixed at exactly 1 satoshi per byte');
  const profile = manifestGenesis(value);
  const { profileId, instanceId, stateCategory } = profile;
  const privateKey = bytes(value.feePrivateKey, 32, 'feePrivateKey');
  const pf7 = requirePf7(value.pf7);
  const { packet, decoded } = checkedPacket(value.actionPacket, profileId, instanceId);
  if (decoded.kind !== kind) fail('action packet kind differs from assembler kind');
  const bindingCarrierBaseSatoshis = decimal(value.bindingCarrierBaseSatoshis, 'bindingCarrierBaseSatoshis');
  const stateCarrierBaseSatoshis = decimal(value.stateCarrierBaseSatoshis, 'stateCarrierBaseSatoshis');
  const feeSourceValueSatoshis = decimal(value.feeSourceValueSatoshis, 'feeSourceValueSatoshis');
  const stateOutpointTransactionHash = wireHash(value.stateOutpointTransactionHashWire, 'stateOutpointTransactionHashWire').reverse();
  const stateOutpointIndex = Number(value.stateOutpointIndex);
  const prepHash = wireHash(value.preparationTransactionHashWire, 'preparationTransactionHashWire');
  const withdrawalLock = kind === 'withdrawal' ? bytes(value.withdrawalLockingBytecode, undefined, 'withdrawalLockingBytecode') : undefined;
  if (kind === 'withdrawal' && hex(sha256(withdrawalLock)) !== decoded.withdrawalScriptHash) fail('withdrawal lock does not match packet hash');

  const bindingLock = Buffer.from(buildPacketOnlyBindingLock());
  if (bindingCarrierBaseSatoshis > BigInt(Number.MAX_SAFE_INTEGER)) fail('binding carrier base exceeds VM-number range');
  const helper = Buffer.from(buildStateSettlementHelper({
    bindingLock, pf7Locks: pf7.map((row) => row.lockingBytecode),
    profileId, instanceId, stateCategory,
    maximumReserveSatoshis: profile.maximumReserveSatoshis,
    genesis: profile.genesis,
    bindingCarrierBaseSatoshis: Number(bindingCarrierBaseSatoshis),
  }));
  const stateLock = Buffer.from(buildStateTrampolineLock({ helper, bindingLock }));
  const stateUnlock = Buffer.from(buildStateTrampolineUnlock(helper));
  if (bindingLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES || stateLock.length > PROJECT_P2S_LOCKING_LIMIT_BYTES) fail('P2S locking-bytecode limit exceeded');
  if (stateUnlock.length > INPUT_UNLOCKING_LIMIT_BYTES) fail('state helper unlocking-bytecode limit exceeded');

  const secp256k1 = await instantiateSecp256k1();
  const publicKey = secp256k1.derivePublicKeyCompressed(privateKey);
  if (typeof publicKey === 'string') fail('fee private key is invalid');
  const feeLock = p2pkh(publicKey);
  const sources = [
    ...pf7.map((row) => sourceFor(row)),
    { valueSatoshis: bindingCarrierBaseSatoshis + (kind === 'deposit' ? 10_000_000n : 0n), lockingBytecode: bindingLock },
    { valueSatoshis: stateCarrierBaseSatoshis + BigInt(decoded.preState.reserveSats), lockingBytecode: stateLock, token: stateToken(stateCategory, profileId, decoded.preState) },
    { valueSatoshis: feeSourceValueSatoshis, lockingBytecode: feeLock },
  ];
  const inputs = [
    ...pf7.map((row) => ({ ...row })),
    { outpointTransactionHash: Buffer.from(prepHash).reverse(), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: packetUnlock(packet) },
    { outpointTransactionHash: stateOutpointTransactionHash, outpointIndex: stateOutpointIndex, sequenceNumber: 0, unlockingBytecode: stateUnlock },
    { outpointTransactionHash: Buffer.from(prepHash).reverse(), outpointIndex: 1, sequenceNumber: 0, unlockingBytecode: schnorrUnlock(Buffer.alloc(64), publicKey) },
  ];
  const totalInputValue = sources.reduce((sum, source) => sum + source.valueSatoshis, 0n);
  const { transaction: unsignedTransaction, wireBytes: unsignedWireBytes } = fixedPointTransaction({
    kind, inputs, sources, stateLock, postToken: stateToken(stateCategory, profileId, decoded.postState),
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
  const signature = secp256k1.signMessageHashSchnorr(privateKey, hash256(signingSerialization));
  if (typeof signature === 'string') fail('unable to create fee signature');
  unsignedTransaction.inputs[9].unlockingBytecode = schnorrUnlock(signature, publicKey);
  const encodedTransaction = Buffer.from(encodeTransaction(unsignedTransaction));
  const feeSatoshis = totalInputValue - unsignedTransaction.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
  if (encodedTransaction.length !== unsignedWireBytes || feeSatoshis !== BigInt(encodedTransaction.length)) fail('exact one-satoshi-per-byte fee invariant failed');
  if (encodedTransaction.length > COMPLETE_TRANSACTION_WIRE_LIMIT_BYTES) fail('complete transaction exceeds 59000 bytes');
  if (Math.max(...unsignedTransaction.inputs.map((input) => input.unlockingBytecode.length)) > INPUT_UNLOCKING_LIMIT_BYTES) fail('per-input unlocking-bytecode limit exceeded');
  return Object.freeze({
    schema: 'shield.cash/g2-complete-settlement/v1', kind, transaction: unsignedTransaction,
    sourceOutputs: sources, encodedTransaction, actionPacket: packet,
    context: provisionalContext,
    locks: Object.freeze({ bindingLock, stateLock, stateHelper: helper }),
    measurements: Object.freeze({ wireBytes: encodedTransaction.length, feeSatoshis, feeRateSatoshisPerByte: PROTOCOL_FEE_RATE_SATOSHIS_PER_BYTE, maximumUnlockingBytes: Math.max(...unsignedTransaction.inputs.map((input) => input.unlockingBytecode.length)), bindingLockBytes: bindingLock.length, stateLockBytes: stateLock.length, stateUnlockBytes: stateUnlock.length }),
  });
}

/**
 * Produce the exact context commitment a prover must put in a fresh packet.
 * This returns no transaction: the temporary packet supplied for state fields
 * is explicitly not authorized for broadcast until `assemble...` rechecks it.
 */
export async function planCompleteG2Settlement(value) {
  const constructed = await constructCompleteG2Settlement(value, false);
  return Object.freeze({
    schema: 'shield.cash/g2-complete-settlement-plan/v1', kind: constructed.kind,
    context: constructed.context,
    expectedWireBytes: constructed.measurements.wireBytes,
    expectedFeeSatoshis: constructed.measurements.feeSatoshis,
    lockBytes: Object.freeze({ binding: constructed.measurements.bindingLockBytes, state: constructed.measurements.stateLockBytes }),
    unlockingBytes: Object.freeze({ maximum: constructed.measurements.maximumUnlockingBytes, state: constructed.measurements.stateUnlockBytes }),
  });
}

export async function assembleCompleteG2Settlement(value) {
  return constructCompleteG2Settlement(value, true);
}

/** Execute every role separately in the unmodified Libauth BCH-2026 VM. */
export function verifyCompleteG2Vm(candidate, standard = true) {
  const vm = createVirtualMachineBch2026(standard);
  return candidate.transaction.inputs.map((_, inputIndex) => vm.evaluate({ inputIndex, sourceOutputs: candidate.sourceOutputs, transaction: candidate.transaction }));
}
