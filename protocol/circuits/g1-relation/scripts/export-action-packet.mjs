// Reconstruct the canonical SCAR packet committed by a G1 circuit input.
// This is a reproducibility bridge for existing public proof corpora; it does
// not create a witness, proof, profile, transaction, or wallet secret.
import { createHash } from 'node:crypto';
import { lstat, open, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  actionPacketPublicLimbs,
  encodeActionPacket,
  OUTPUT_RECORD_BYTES,
} from '../../../packages/action-packet/action-packet.mjs';
import { parseStrictJson } from '../../../packages/core/verifier-profile.mjs';

const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U128 = (1n << 128n) - 1n;
const MAX_U256 = (1n << 256n) - 1n;

const decimal = (value, maximum, label) => {
  if (typeof value !== 'string' || !DECIMAL.test(value)) throw new Error(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${label} exceeds its range`);
  return parsed;
};
const hex256 = (value, label) => decimal(value, MAX_U256, label).toString(16).padStart(64, '0');
const limbs = (hi, lo, label) => Buffer.concat([
  Buffer.from(decimal(hi, MAX_U128, `${label} high limb`).toString(16).padStart(32, '0'), 'hex'),
  Buffer.from(decimal(lo, MAX_U128, `${label} low limb`).toString(16).padStart(32, '0'), 'hex'),
]).toString('hex');
const state = (input, prefix) => ({
  profileId: limbs(input.profileHi, input.profileLo, 'profile'),
  instanceId: limbs(input.instanceHi, input.instanceLo, 'instance'),
  noteRoot: hex256(input[`${prefix}NoteRoot`], `${prefix} note root`),
  nullifierRoot: hex256(input[`${prefix}NullifierRoot`], `${prefix} nullifier root`),
  nextLeafIndex: decimal(input[`${prefix}NextLeafIndex`], 0xffff_ffffn, `${prefix} next leaf index`).toString(),
  actionSequence: decimal(input[`${prefix}ActionSequence`], 0xffff_ffff_ffff_ffffn, `${prefix} action sequence`).toString(),
  liveNoteCount: decimal(input[`${prefix}LiveNoteCount`], 0xffff_ffffn, `${prefix} live note count`).toString(),
  reserveSats: decimal(input[`${prefix}ReserveSats`], 0xffff_ffff_ffff_ffffn, `${prefix} reserve`).toString(),
  maximumReserve: decimal(input[`${prefix}MaximumReserve`], 0xffff_ffff_ffff_ffffn, `${prefix} maximum reserve`).toString(),
  stateCommitment: hex256(input[`${prefix}StateCommitment`], `${prefix} state commitment`),
});

function record(input) {
  if (!Array.isArray(input.recordBits) || input.recordBits.length !== OUTPUT_RECORD_BYTES * 8) {
    throw new Error(`recordBits must contain exactly ${OUTPUT_RECORD_BYTES * 8} bits`);
  }
  if (input.recordBits.some((bit) => bit !== '0' && bit !== '1')) throw new Error('recordBits must contain only string bits');
  return Buffer.from(Array.from(
    { length: OUTPUT_RECORD_BYTES },
    (_, index) => Number.parseInt(input.recordBits.slice(index * 8, index * 8 + 8).join(''), 2),
  ));
}

export function actionPacketFromCircuitVector(input) {
  if (input === null || Array.isArray(input) || typeof input !== 'object') throw new Error('circuit vector must be an object');
  const selectors = [
    ['deposit', input.isDeposit],
    ['transfer', input.isTransfer],
    ['withdrawal', input.isWithdrawal],
  ];
  if (selectors.some(([, value]) => value !== '0' && value !== '1')) throw new Error('action selectors must be string bits');
  const selected = selectors.filter(([, value]) => value === '1');
  if (selected.length !== 1) throw new Error('action selectors must be one-hot');
  const packet = encodeActionPacket({
    kind: selected[0][0],
    networkId: 2,
    preState: state(input, 'pre'),
    postState: state(input, 'post'),
    inputCommitment: hex256(input.inputCm, 'input commitment'),
    inputNullifier: hex256(input.inputNf, 'input nullifier'),
    outputCommitment: hex256(input.outputCm, 'output commitment'),
    outputRecord: record(input),
    boundaryAmount: decimal(input.boundaryAmount, 0xffff_ffff_ffff_ffffn, 'boundary amount').toString(),
    withdrawalScriptHash: limbs(input.withdrawalScriptHi, input.withdrawalScriptLo, 'withdrawal script'),
    transactionContextDigest: limbs(input.transactionContextHi, input.transactionContextLo, 'transaction context'),
  });
  const observed = actionPacketPublicLimbs(packet);
  const expected = [
    decimal(input.publicDigestHi, MAX_U128, 'public digest high limb').toString(),
    decimal(input.publicDigestLo, MAX_U128, 'public digest low limb').toString(),
  ];
  if (observed[0] !== expected[0] || observed[1] !== expected[1]) throw new Error('circuit vector public digest does not match its canonical action packet');
  return packet;
}

async function regularAbsolute(filename, label) {
  if (typeof filename !== 'string' || !path.isAbsolute(filename)) throw new Error(`${label} must be an absolute path`);
  const requested = path.resolve(filename);
  const stat = await lstat(requested).catch(() => { throw new Error(`${label} does not exist`); });
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  if (await realpath(requested) !== requested) throw new Error(`${label} must not resolve through a symlink`);
  return requested;
}

async function main() {
  if (process.argv.length !== 4) throw new Error('usage: node export-action-packet.mjs ABSOLUTE_VECTOR.json ABSOLUTE_OUTPUT.packet');
  const input = await regularAbsolute(process.argv[2], 'input vector');
  if (!path.isAbsolute(process.argv[3])) throw new Error('output path must be absolute');
  const output = path.resolve(process.argv[3]);
  const vector = parseStrictJson(await readFile(input), 'circuit vector');
  const packet = actionPacketFromCircuitVector(vector);
  const handle = await open(output, 'wx', 0o644).catch((error) => {
    if (error.code === 'EEXIST') throw new Error('output path already exists');
    throw error;
  });
  try { await handle.writeFile(packet); } finally { await handle.close(); }
  process.stdout.write(`${JSON.stringify({
    input,
    output,
    kind: vector.isDeposit === '1' ? 'deposit' : vector.isTransfer === '1' ? 'transfer' : 'withdrawal',
    bytes: packet.length,
    sha256: createHash('sha256').update(packet).digest('hex'),
    publicLimbs: actionPacketPublicLimbs(packet),
  })}\n`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { await main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
