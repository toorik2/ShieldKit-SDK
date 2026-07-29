import {
  BABYJUB_SUBGROUP_ORDER,
  babyJubMul,
  bytesToHex,
  hexToBytes,
  unpackBabyJubPoint,
} from '../../recover/portable-core.mjs';
import {
  ACTION_PACKET_BYTES,
  actionPacketPublicLimbs,
  decodeActionPacket,
} from './packet.mjs';
import { frFromCanonicalHex } from './poseidon.mjs';
import {
  DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA,
} from './proving-transition.mjs';

export const BABYJUB_INV8 = 2_394_026_564_107_420_727_433_200_628_387_514_462_817_212_225_638_746_351_800_188_703_329_891_451_411n;

const ZERO_FIELD = '0';
const ZERO_PATH = Object.freeze(Array(32).fill(ZERO_FIELD));
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const TOP_KEYS = Object.freeze([
  'noteTree',
  'nullifierTree',
  'packet',
  'packetDigest',
  'publicInputs',
  'state',
  'witness',
]);
const PERSISTENT_TOP_KEYS = Object.freeze([
  'expectedTip',
  'packet',
  'packetDigest',
  'publicInputs',
  'schema',
  'state',
  'witness',
]);
const SPEND_KEYS = Object.freeze([
  'encryptedRecord',
  'incomingViewPublicKey',
  'r',
  'rho',
  'spendSecret',
]);
const OUTPUT_KEYS = Object.freeze(['public', 'witness']);
const OUTPUT_PUBLIC_KEYS = Object.freeze([
  'encryptedRecord',
  'noteCommitment',
  'outputNoteLeaf',
]);
const OUTPUT_WITNESS_KEYS = Object.freeze([
  'authority',
  'ephemeralScalar',
  'incomingViewPublicKey',
  'r',
  'rho',
  'rhoBlind',
  'spendPublicKey',
]);

export class DirectV2CircuitWitnessError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2CircuitWitnessError';
  }
}

const fail = (message) => {
  throw new DirectV2CircuitWitnessError(message);
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

function exactBytes(value, length, label) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Object.freeze([...value]);
}

function field(value, label) {
  try {
    return frFromCanonicalHex(value, label).toString();
  } catch (error) {
    fail(`${label} is invalid: ${error.message}`);
  }
}

function point(value, label) {
  let decoded;
  try {
    decoded = unpackBabyJubPoint(hexToBytes(value, label));
  } catch (error) {
    fail(`${label} is invalid: ${error.message}`);
  }
  const preimage = babyJubMul(decoded, BABYJUB_INV8);
  const recomputed = babyJubMul(preimage, 8n);
  if (recomputed[0] !== decoded[0] || recomputed[1] !== decoded[1]) {
    fail(`${label} cofactor preimage does not reconstruct the point`);
  }
  return Object.freeze({
    x: decoded[0].toString(),
    y: decoded[1].toString(),
    qx: preimage[0].toString(),
    qy: preimage[1].toString(),
  });
}

function scalar(value, label) {
  const parsed = BigInt(field(value, label));
  if (parsed === 0n || parsed >= BABYJUB_SUBGROUP_ORDER) {
    fail(`${label} must be a nonzero BabyJub subgroup scalar`);
  }
  return parsed.toString();
}

function path(value, label) {
  if (!Array.isArray(value) || value.length !== 32) {
    fail(`${label} must contain exactly 32 field elements`);
  }
  return Object.freeze(value.map((entry, index) => {
    if (typeof entry !== 'bigint') fail(`${label}[${index}] must be a bigint`);
    return field(entry.toString(16).padStart(64, '0'), `${label}[${index}]`);
  }));
}

function assertTransition(value, denominationSats) {
  if (
    value?.schema ===
      DIRECT_V2_PERSISTENT_PROVING_TRANSITION_SCHEMA
  ) {
    exactKeys(value, 'persistent transition result', PERSISTENT_TOP_KEYS);
  } else {
    exactKeys(value, 'transition result', TOP_KEYS);
  }
  const packet = Buffer.from(exactBytes(value.packet, ACTION_PACKET_BYTES, 'transition packet'));
  const packetContext = Object.freeze({ denominationSats });
  const decoded = decodeActionPacket(packet, packetContext);
  if (!Array.isArray(value.publicInputs) || value.publicInputs.length !== 2) {
    fail('transition publicInputs must contain two limbs');
  }
  const expected = actionPacketPublicLimbs(packet, packetContext);
  for (let index = 0; index < 2; index += 1) {
    if (String(value.publicInputs[index]) !== expected[index]) {
      fail(`transition public input ${index} does not match the packet`);
    }
  }
  if (value.witness === null || typeof value.witness !== 'object') {
    fail('transition witness is missing');
  }
  return Object.freeze({ decoded, packet, publicInputs: expected });
}

function outputInputs(output, packet) {
  exactKeys(output, 'output construction', OUTPUT_KEYS);
  exactKeys(output.public, 'output construction public', OUTPUT_PUBLIC_KEYS);
  exactKeys(output.witness, 'output construction witness', OUTPUT_WITNESS_KEYS);
  const encryptedRecord = exactBytes(
    output.public.encryptedRecord,
    128,
    'output encrypted record',
  );
  if (
    output.public.outputNoteLeaf !== packet.outputNoteLeaf
    || bytesToHex(Uint8Array.from(encryptedRecord))
      !== bytesToHex(packet.encryptedRecord)
  ) {
    fail('output construction does not match the action packet');
  }
  const spend = point(output.witness.spendPublicKey, 'output spend public key');
  const view = point(
    output.witness.incomingViewPublicKey,
    'output incoming-view public key',
  );
  return Object.freeze({
    outputSpendX: spend.x,
    outputSpendY: spend.y,
    outputSpendQX: spend.qx,
    outputSpendQY: spend.qy,
    outputIncomingViewX: view.x,
    outputIncomingViewY: view.y,
    outputIncomingViewQX: view.qx,
    outputIncomingViewQY: view.qy,
    outputRhoBlind: field(output.witness.rhoBlind, 'output rho blind'),
    outputR: field(output.witness.r, 'output r'),
    outputEsk: scalar(output.witness.ephemeralScalar, 'output ephemeral scalar'),
  });
}

function inactiveOutputInputs() {
  return Object.freeze({
    outputSpendX: ZERO_FIELD,
    outputSpendY: ZERO_FIELD,
    outputSpendQX: ZERO_FIELD,
    outputSpendQY: ZERO_FIELD,
    outputIncomingViewX: ZERO_FIELD,
    outputIncomingViewY: ZERO_FIELD,
    outputIncomingViewQX: ZERO_FIELD,
    outputIncomingViewQY: ZERO_FIELD,
    outputRhoBlind: ZERO_FIELD,
    outputR: ZERO_FIELD,
    outputEsk: ZERO_FIELD,
  });
}

function spendInputs(spend, transitionWitness, packet) {
  exactKeys(spend, 'spend witness', SPEND_KEYS);
  const record = exactBytes(spend.encryptedRecord, 128, 'spend encrypted record');
  const view = point(spend.incomingViewPublicKey, 'spend incoming-view public key');
  const membership = transitionWitness.spend;
  if (
    membership === null
    || typeof membership !== 'object'
    || membership.publicNullifier !== packet.publicNullifier
  ) {
    fail('transition spend witness does not match the packet nullifier');
  }
  return Object.freeze({
    spendSk: scalar(spend.spendSecret, 'spend secret'),
    spendIncomingViewX: view.x,
    spendIncomingViewY: view.y,
    spendIncomingViewQX: view.qx,
    spendIncomingViewQY: view.qy,
    spendRho: field(spend.rho, 'spend rho'),
    spendR: field(spend.r, 'spend r'),
    spendRecordTag: field(
      bytesToHex(Uint8Array.from(record.slice(96))),
      'spend record tag',
    ),
    spendNoteIndex: BigInt(membership.noteIndex).toString(),
    spendNoteSiblings: path(
      membership.noteMembershipPath,
      'spend note siblings',
    ),
  });
}

function inactiveSpendInputs() {
  return Object.freeze({
    spendSk: ZERO_FIELD,
    spendIncomingViewX: ZERO_FIELD,
    spendIncomingViewY: ZERO_FIELD,
    spendIncomingViewQX: ZERO_FIELD,
    spendIncomingViewQY: ZERO_FIELD,
    spendRho: ZERO_FIELD,
    spendR: ZERO_FIELD,
    spendRecordTag: ZERO_FIELD,
    spendNoteIndex: ZERO_FIELD,
    spendNoteSiblings: ZERO_PATH,
  });
}

function nullifierInputs(witness) {
  if (witness === undefined) fail('active nullifier insertion witness is missing');
  const type = witness.predecessor?.type === 'min'
    ? 1
    : witness.predecessor?.type === 'normal'
      ? 2
      : undefined;
  if (type === undefined || witness.append?.index === undefined) {
    fail('active nullifier insertion witness is malformed');
  }
  return Object.freeze({
    nullifierPredecessorType: String(type),
    nullifierPredecessorIndex: String(witness.predecessor.index),
    nullifierPredecessorKey: field(
      witness.predecessor.key,
      'nullifier predecessor key',
    ),
    nullifierSuccessorIndex: String(witness.predecessor.successorIndex),
    nullifierSuccessorKey: field(
      witness.predecessor.successorKey,
      'nullifier successor key',
    ),
    nullifierPredecessorSiblings: path(
      witness.predecessorPath,
      'nullifier predecessor siblings',
    ),
    nullifierAppendSiblings: path(
      witness.append.path,
      'nullifier append siblings',
    ),
  });
}

function inactiveNullifierInputs() {
  return Object.freeze({
    nullifierPredecessorType: ZERO_FIELD,
    nullifierPredecessorIndex: ZERO_FIELD,
    nullifierPredecessorKey: ZERO_FIELD,
    nullifierSuccessorIndex: ZERO_FIELD,
    nullifierSuccessorKey: ZERO_FIELD,
    nullifierPredecessorSiblings: ZERO_PATH,
    nullifierAppendSiblings: ZERO_PATH,
  });
}

/**
 * Convert an independently validated state transition plus private note
 * material into the exact Circom witness ABI. This function never derives or
 * accepts duplicated packet/state public fields.
 */
export function buildDirectV2CircuitInput({
  transition,
  spend,
  output,
  denominationSats,
}) {
  if (
    typeof denominationSats !== 'string'
    || !DECIMAL.test(denominationSats)
    || BigInt(denominationSats) === 0n
  ) {
    fail('denominationSats must be a canonical nonzero decimal string');
  }
  const checked = assertTransition(transition, denominationSats);
  const kind = checked.decoded.kind;
  const outputActive = kind === 'deposit' || kind === 'transfer';
  const spendActive = kind === 'transfer' || kind === 'withdrawal';
  if (outputActive !== (output !== undefined)) {
    fail(`${kind} output construction presence is incorrect`);
  }
  if (spendActive !== (spend !== undefined)) {
    fail(`${kind} spend witness presence is incorrect`);
  }

  const noteAppendSiblings = outputActive
    ? path(transition.witness.note?.emptyAppendPath, 'note append siblings')
    : ZERO_PATH;
  const inputs = {
    publicInput0: checked.publicInputs[0],
    publicInput1: checked.publicInputs[1],
    packet: Object.freeze([...checked.packet]),
    ...(spendActive
      ? spendInputs(spend, transition.witness, checked.decoded)
      : inactiveSpendInputs()),
    ...(outputActive
      ? outputInputs(output, checked.decoded)
      : inactiveOutputInputs()),
    noteAppendSiblings,
    ...(spendActive
      ? nullifierInputs(transition.witness.nullifier)
      : inactiveNullifierInputs()),
  };
  return Object.freeze(inputs);
}
