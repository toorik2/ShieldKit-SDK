// Local-only closure checks for the PF7 -> SCCT -> exact-fee cycle.
//
// This module deliberately does not prove or verify Groth16, run a BCH VM,
// contact a node, or accept a boolean proof-validity assertion. It consumes
// raw, already-built PF7 unlocking bytecodes and makes an integration supply
// its own PF7 compatibility predicate after every independently derivable
// byte, context, and fee invariant has closed.
import { decodeTransactionBch, encodeTransaction } from '@bitauth/libauth';
import {
  ACTION_PACKET_BYTES,
  actionPacketPublicLimbs,
  decodeActionPacket,
} from '../action/packet.mjs';
import {
  encodeSettlementContext,
  validateSettlementContext,
} from '../action/context.mjs';

export const PF7_FIXED_POINT_SCHEMA = 'shield.cash/pf7-fixed-point/v1';
export const PF7_INPUT_COUNT = 7;
export const SETTLEMENT_INPUT_COUNT = 10;
export const PF7_UNLOCKING_BYTE_LIMIT = 10_000;
export const COMPLETE_SETTLEMENT_WIRE_LIMIT = 59_000;
export const FEE_RATE_SATOSHIS_PER_BYTE = 1n;

export class Pf7FixedPointError extends Error {
  constructor(message) {
    super(message);
    this.name = 'Pf7FixedPointError';
  }
}

const fail = (message) => { throw new Pf7FixedPointError(message); };
const HEX = /^[0-9a-f]*$/;
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

function exactKeys(value, label, expected) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${label} has missing or unknown properties`);
  }
}

function bytes(value, label, length = undefined) {
  if (!(value instanceof Uint8Array) || (length !== undefined && value.length !== length)) {
    fail(`${label} must be a Uint8Array${length === undefined ? '' : ` of ${length} bytes`}`);
  }
  return Buffer.from(value);
}

function hexBytes(value, label, length = undefined) {
  if (typeof value !== 'string' || !HEX.test(value) || value.length % 2 !== 0 || (length !== undefined && value.length !== length * 2)) {
    fail(`${label} must be canonical lowercase hexadecimal${length === undefined ? '' : ` of ${length} bytes`}`);
  }
  return Buffer.from(value, 'hex');
}

function decimal(value, label) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed > MAX_U64) fail(`${label} exceeds u64`);
  return parsed;
}

function u32(value, label) {
  const parsed = decimal(value, label);
  if (parsed > 0xffff_ffffn) fail(`${label} exceeds u32`);
  return Number(parsed);
}

function byteEqual(left, right) {
  return Buffer.from(left).equals(Buffer.from(right));
}

function tokenFromJson(value, label) {
  if (value === null) return undefined;
  exactKeys(value, label, ['amount', 'category', 'nft']);
  const amount = decimal(value.amount, `${label}.amount`);
  const category = Uint8Array.from(hexBytes(value.category, `${label}.category`, 32));
  if (value.nft === null) {
    if (amount === 0n) fail(`${label} must use null for no token`);
    return { amount, category };
  }
  exactKeys(value.nft, `${label}.nft`, ['capability', 'commitment']);
  if (!['none', 'mutable', 'minting'].includes(value.nft.capability)) fail(`${label}.nft.capability is invalid`);
  const commitment = Uint8Array.from(hexBytes(value.nft.commitment, `${label}.nft.commitment`));
  if (commitment.length > 128) fail(`${label}.nft.commitment exceeds BCH consensus limit`);
  return { amount, category, nft: { capability: value.nft.capability, commitment } };
}

function transactionFromContextMaterials(materials, decoded) {
  if (materials === null || typeof materials !== 'object' || Array.isArray(materials)) fail('settlementContextMaterials must be an object');
  if (decoded.inputs.length !== SETTLEMENT_INPUT_COUNT) fail('encoded transaction must contain exactly ten inputs');
  if (!Array.isArray(materials.transaction?.inputs) || materials.transaction.inputs.length !== SETTLEMENT_INPUT_COUNT) {
    fail('settlementContextMaterials must describe exactly ten inputs');
  }
  if (!Array.isArray(materials.transaction?.outputs) || materials.transaction.outputs.length !== decoded.outputs.length) {
    fail('settlementContextMaterials outputs do not match the encoded transaction');
  }
  const transaction = {
    version: u32(materials.transaction.version, 'settlementContextMaterials.transaction.version'),
    locktime: u32(materials.transaction.locktime, 'settlementContextMaterials.transaction.locktime'),
    inputs: materials.transaction.inputs.map((input, index) => {
      exactKeys(input, `settlementContextMaterials.transaction.inputs[${index}]`, ['outpointIndex', 'outpointTransactionHashWire', 'sequenceNumber']);
      return {
        outpointTransactionHash: Uint8Array.from(hexBytes(input.outpointTransactionHashWire, `settlementContextMaterials.transaction.inputs[${index}].outpointTransactionHashWire`, 32)).reverse(),
        outpointIndex: u32(input.outpointIndex, `settlementContextMaterials.transaction.inputs[${index}].outpointIndex`),
        sequenceNumber: u32(input.sequenceNumber, `settlementContextMaterials.transaction.inputs[${index}].sequenceNumber`),
        unlockingBytecode: Uint8Array.from(decoded.inputs[index].unlockingBytecode),
      };
    }),
    outputs: materials.transaction.outputs.map((output, index) => {
      exactKeys(output, `settlementContextMaterials.transaction.outputs[${index}]`, ['lockingBytecode', 'token', 'valueSatoshis']);
      return {
        valueSatoshis: decimal(output.valueSatoshis, `settlementContextMaterials.transaction.outputs[${index}].valueSatoshis`),
        lockingBytecode: Uint8Array.from(hexBytes(output.lockingBytecode, `settlementContextMaterials.transaction.outputs[${index}].lockingBytecode`)),
        ...(output.token === null ? {} : { token: tokenFromJson(output.token, `settlementContextMaterials.transaction.outputs[${index}].token`) }),
      };
    }),
  };
  const canonical = Buffer.from(encodeTransaction(transaction));
  return { transaction, canonical };
}

function parsePf7Rows(value) {
  if (!Array.isArray(value) || value.length !== PF7_INPUT_COUNT) fail('actualPf7UnlockRows must contain exactly seven rows');
  return value.map((row, index) => {
    exactKeys(row, `actualPf7UnlockRows[${index}]`, ['inputIndex', 'unlockingBytecode']);
    if (row.inputIndex !== index) fail(`actualPf7UnlockRows[${index}].inputIndex must equal ${index}`);
    const unlockingBytecode = bytes(row.unlockingBytecode, `actualPf7UnlockRows[${index}].unlockingBytecode`);
    if (unlockingBytecode.length === 0 || unlockingBytecode.length > PF7_UNLOCKING_BYTE_LIMIT) {
      fail(`actualPf7UnlockRows[${index}] is outside the 1..${PF7_UNLOCKING_BYTE_LIMIT} byte PF7 limit`);
    }
    return Object.freeze({ inputIndex: index, unlockingBytecode });
  });
}

function parseContextClaim(value) {
  exactKeys(value, 'planned.transactionContext', ['digestHex', 'preimageHex', 'publicInputLimbs']);
  if (!HEX_32.test(value.digestHex) || typeof value.preimageHex !== 'string' || !HEX.test(value.preimageHex) || value.preimageHex.length % 2 !== 0) {
    fail('planned.transactionContext must use canonical hexadecimal');
  }
  if (!Array.isArray(value.publicInputLimbs) || value.publicInputLimbs.length !== 2 || value.publicInputLimbs.some((limb) => typeof limb !== 'string' || !DECIMAL.test(limb))) {
    fail('planned.transactionContext.publicInputLimbs must contain two canonical decimal limbs');
  }
  return value;
}

function parsePlan(value) {
  exactKeys(value, 'planned', ['expectedFeeSatoshis', 'expectedPf7UnlockingByteLengths', 'expectedPf7UnlockingBytes', 'expectedWireBytes', 'transactionContext']);
  if (!Number.isSafeInteger(value.expectedWireBytes) || value.expectedWireBytes <= 0) fail('planned.expectedWireBytes must be a positive safe integer');
  const expectedFeeSatoshis = decimal(value.expectedFeeSatoshis, 'planned.expectedFeeSatoshis');
  if (!Number.isSafeInteger(value.expectedPf7UnlockingBytes) || value.expectedPf7UnlockingBytes <= 0) fail('planned.expectedPf7UnlockingBytes must be a positive safe integer');
  if (!Array.isArray(value.expectedPf7UnlockingByteLengths) || value.expectedPf7UnlockingByteLengths.length !== PF7_INPUT_COUNT || value.expectedPf7UnlockingByteLengths.some((length) => !Number.isSafeInteger(length) || length <= 0 || length > PF7_UNLOCKING_BYTE_LIMIT)) {
    fail('planned.expectedPf7UnlockingByteLengths must contain seven valid PF7 lengths');
  }
  return Object.freeze({ ...value, expectedFeeSatoshis, transactionContext: parseContextClaim(value.transactionContext) });
}

function parsePacketPublicInputLimbs(value) {
  if (!Array.isArray(value) || value.length !== 2 || value.some((limb) => typeof limb !== 'string' || !DECIMAL.test(limb))) {
    fail('packetPublicInputLimbs must contain exactly two canonical decimal limbs');
  }
  return Object.freeze([...value]);
}

function publicResult(measurement) {
  return Object.freeze({
    actionPacketHex: measurement.actionPacket.toString('hex'),
    packetPublicInputLimbs: measurement.packetPublicInputLimbs,
    transactionHex: measurement.encodedTransaction.toString('hex'),
    transactionContext: Object.freeze({
      digestHex: measurement.context.digestHex,
      preimageHex: measurement.context.preimageHex,
      publicInputLimbs: measurement.context.publicInputLimbs,
    }),
    measurements: measurement.measurements,
    pf7UnlockRows: Object.freeze(measurement.pf7Rows.map((row) => Object.freeze({
      inputIndex: row.inputIndex,
      unlockingBytecodeHex: row.unlockingBytecode.toString('hex'),
    }))),
  });
}

/**
 * Decode the final wire transaction and derive the only sizes, fee and SCCT
 * commitment this helper will report. It does not assert PF7 proof validity.
 */
export function measurePf7FixedPointCandidate(value) {
  exactKeys(value, 'fixed-point measurement', ['actionPacket', 'actualPf7UnlockRows', 'encodedTransaction', 'settlementContextMaterials']);
  const actionPacket = bytes(value.actionPacket, 'actionPacket', ACTION_PACKET_BYTES);
  const decodedPacket = decodeActionPacket(actionPacket);
  const encodedTransaction = bytes(value.encodedTransaction, 'encodedTransaction');
  let decoded;
  try { decoded = decodeTransactionBch(encodedTransaction); }
  catch (error) { fail(`encodedTransaction cannot be decoded as BCH: ${error.message}`); }
  const reencoded = Buffer.from(encodeTransaction(decoded));
  if (!reencoded.equals(encodedTransaction)) fail('encodedTransaction is not a canonical complete BCH encoding');
  const pf7Rows = parsePf7Rows(value.actualPf7UnlockRows);
  if (decoded.inputs.length !== SETTLEMENT_INPUT_COUNT) fail('encoded transaction must contain exactly ten inputs');
  for (const row of pf7Rows) {
    if (!byteEqual(decoded.inputs[row.inputIndex].unlockingBytecode, row.unlockingBytecode)) {
      fail(`actualPf7UnlockRows[${row.inputIndex}] does not match the decoded complete transaction`);
    }
  }
  let context;
  try {
    context = encodeSettlementContext(value.settlementContextMaterials);
    validateSettlementContext({ preimageHex: context.preimageHex, digestHex: context.digestHex, publicInputLimbs: [...context.publicInputLimbs] }, value.settlementContextMaterials);
  } catch (error) {
    fail(`settlement context materials are invalid: ${error.message}`);
  }
  const { canonical } = transactionFromContextMaterials(value.settlementContextMaterials, decoded);
  if (!canonical.equals(encodedTransaction)) fail('settlement context materials do not reconstruct the exact complete transaction');
  if (decodedPacket.transactionContextDigest !== context.digestHex) fail('action packet transactionContextDigest does not bind the exact complete transaction');
  const inputValue = value.settlementContextMaterials.sourceOutputs.reduce((sum, output, index) => sum + decimal(output.valueSatoshis, `settlementContextMaterials.sourceOutputs[${index}].valueSatoshis`), 0n);
  const outputValue = decoded.outputs.reduce((sum, output) => sum + output.valueSatoshis, 0n);
  if (outputValue > inputValue) fail('complete transaction outputs exceed committed source values');
  const feeSatoshis = inputValue - outputValue;
  const wireBytes = encodedTransaction.length;
  if (wireBytes > COMPLETE_SETTLEMENT_WIRE_LIMIT) fail(`complete transaction exceeds ${COMPLETE_SETTLEMENT_WIRE_LIMIT} serialized bytes`);
  if (feeSatoshis !== BigInt(wireBytes) * FEE_RATE_SATOSHIS_PER_BYTE) fail('complete transaction does not pay exactly one satoshi per serialized byte');
  const pf7UnlockingByteLengths = Object.freeze(pf7Rows.map((row) => row.unlockingBytecode.length));
  const pf7UnlockingBytes = pf7UnlockingByteLengths.reduce((sum, length) => sum + length, 0);
  const maximumUnlockingBytecodeBytes = Math.max(...decoded.inputs.map((input) => input.unlockingBytecode.length));
  if (maximumUnlockingBytecodeBytes > PF7_UNLOCKING_BYTE_LIMIT) fail(`complete transaction input exceeds ${PF7_UNLOCKING_BYTE_LIMIT} unlocking bytes`);
  return Object.freeze({
    schema: PF7_FIXED_POINT_SCHEMA,
    qualification: 'local fixed-point measurement only; it does not establish Groth16/PF7 proof validity, BCH VM acceptance, relay, confirmation, or Chipnet qualification',
    actionPacket,
    packetPublicInputLimbs: actionPacketPublicLimbs(actionPacket),
    encodedTransaction,
    context,
    pf7Rows,
    measurements: Object.freeze({
      wireBytes,
      feeSatoshis,
      feeRateSatoshisPerByte: FEE_RATE_SATOSHIS_PER_BYTE,
      pf7UnlockingByteLengths,
      pf7UnlockingBytes,
      maximumUnlockingBytecodeBytes,
    }),
  });
}

/**
 * Fail closed unless the packet/public-input evaluator, SCCT, exact one-sat
 * fee, actual PF7 unlock rows, and a caller-owned PF7 compatibility predicate
 * all agree on the same final wire transaction.
 */
export async function verifyPf7FixedPointCandidate(value) {
  exactKeys(value, 'fixed-point candidate', ['actionPacket', 'actualPf7UnlockRows', 'encodedTransaction', 'packetPublicInputLimbs', 'pf7Compatibility', 'planned', 'settlementContextMaterials']);
  if (typeof value.pf7Compatibility !== 'function') fail('pf7Compatibility must be a mandatory caller-supplied function');
  const measurement = measurePf7FixedPointCandidate({
    actionPacket: value.actionPacket,
    actualPf7UnlockRows: value.actualPf7UnlockRows,
    encodedTransaction: value.encodedTransaction,
    settlementContextMaterials: value.settlementContextMaterials,
  });
  const plan = parsePlan(value.planned);
  const packetPublicInputLimbs = parsePacketPublicInputLimbs(value.packetPublicInputLimbs);
  if (packetPublicInputLimbs.some((limb, index) => limb !== measurement.packetPublicInputLimbs[index])) fail('packetPublicInputLimbs do not match the exact action packet');
  if (plan.expectedWireBytes !== measurement.measurements.wireBytes) fail('planned expectedWireBytes does not match the exact complete transaction');
  if (plan.expectedFeeSatoshis !== measurement.measurements.feeSatoshis) fail('planned expectedFeeSatoshis does not match the exact complete transaction fee');
  if (plan.expectedPf7UnlockingBytes !== measurement.measurements.pf7UnlockingBytes) fail('planned PF7 unlock total does not match actual post-build rows');
  if (plan.expectedPf7UnlockingByteLengths.some((length, index) => length !== measurement.measurements.pf7UnlockingByteLengths[index])) fail('planned PF7 unlock lengths do not match actual post-build rows');
  if (plan.transactionContext.digestHex !== measurement.context.digestHex || plan.transactionContext.preimageHex !== measurement.context.preimageHex || plan.transactionContext.publicInputLimbs.some((limb, index) => limb !== measurement.context.publicInputLimbs[index])) {
    fail('planned transaction context does not match the exact complete transaction');
  }
  let compatible;
  try { compatible = await value.pf7Compatibility(publicResult(measurement)); }
  catch (error) { fail(`pf7Compatibility threw: ${error.message}`); }
  if (compatible !== true) fail('pf7Compatibility did not affirm the exact packet, public inputs, and PF7 rows');
  return Object.freeze({
    ...measurement,
    fixedPoint: true,
    qualification: 'local fixed-point closure only; Groth16/PF7 proof validity, BCH VM acceptance, relay, confirmation, and Chipnet qualification remain separate gates',
  });
}

function parseSeedCandidates(value) {
  if (!Array.isArray(value) || value.length === 0) fail('seedCandidates must be a non-empty array');
  const seen = new Set();
  return value.map((seedHex, index) => {
    if (!HEX_32.test(seedHex)) fail(`seedCandidates[${index}] must be a canonical 32-byte lowercase hexadecimal seed`);
    if (seen.has(seedHex)) fail(`seedCandidates[${index}] duplicates an earlier seed`);
    seen.add(seedHex);
    return seedHex;
  });
}

function parsePacketEvaluation(value) {
  exactKeys(value, 'packet/public-input evaluation', ['actionPacket', 'packetPublicInputLimbs']);
  const actionPacket = bytes(value.actionPacket, 'packet/public-input evaluation.actionPacket', ACTION_PACKET_BYTES);
  decodeActionPacket(actionPacket);
  const packetPublicInputLimbs = parsePacketPublicInputLimbs(value.packetPublicInputLimbs);
  const actual = actionPacketPublicLimbs(actionPacket);
  if (packetPublicInputLimbs.some((limb, index) => limb !== actual[index])) fail('packet/public-input evaluator returned mismatched packet limbs');
  return Object.freeze({ actionPacket, packetPublicInputLimbs });
}

/**
 * Enumerate caller-provided 32-byte seed candidates sequentially and in exact
 * input order. Rejected attempts are reported but never promoted; only an
 * exact closure returned by verifyPf7FixedPointCandidate appears in accepted.
 */
export async function enumeratePf7FixedPointCandidates(value) {
  exactKeys(value, 'fixed-point enumeration', ['buildCandidate', 'evaluatePacketPublicInputs', 'pf7Compatibility', 'seedCandidates']);
  if (typeof value.evaluatePacketPublicInputs !== 'function') fail('evaluatePacketPublicInputs must be a function');
  if (typeof value.buildCandidate !== 'function') fail('buildCandidate must be a function');
  if (typeof value.pf7Compatibility !== 'function') fail('pf7Compatibility must be a function');
  const seeds = parseSeedCandidates(value.seedCandidates);
  const accepted = [];
  const rejected = [];
  for (const seedHex of seeds) {
    try {
      const packet = parsePacketEvaluation(await value.evaluatePacketPublicInputs(Object.freeze({ seedHex })));
      const candidate = await value.buildCandidate(Object.freeze({
        seedHex,
        actionPacket: Buffer.from(packet.actionPacket),
        packetPublicInputLimbs: packet.packetPublicInputLimbs,
      }));
      exactKeys(candidate, 'buildCandidate result', ['actualPf7UnlockRows', 'encodedTransaction', 'planned', 'settlementContextMaterials']);
      const closed = await verifyPf7FixedPointCandidate({
        actionPacket: packet.actionPacket,
        packetPublicInputLimbs: packet.packetPublicInputLimbs,
        actualPf7UnlockRows: candidate.actualPf7UnlockRows,
        encodedTransaction: candidate.encodedTransaction,
        planned: candidate.planned,
        settlementContextMaterials: candidate.settlementContextMaterials,
        pf7Compatibility: async (publicCandidate) => value.pf7Compatibility(Object.freeze({ seedHex, ...publicCandidate })),
      });
      accepted.push(Object.freeze({ seedHex, candidate: closed }));
    } catch (error) {
      rejected.push(Object.freeze({ seedHex, reason: error instanceof Error ? error.message : String(error) }));
    }
  }
  return Object.freeze({
    schema: PF7_FIXED_POINT_SCHEMA,
    qualification: 'deterministic local candidate enumeration only; accepted entries are fixed-point closures, not proof, VM, relay, or Chipnet acceptance claims',
    accepted: Object.freeze(accepted),
    rejected: Object.freeze(rejected),
  });
}
