// Measured direct-SCCT reconstruction floor. This is deliberately not a
// covenant candidate: see README for the semantics it does not implement.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  createVirtualMachineBch2026, disassembleBytecodeBch, encodeDataPush,
  encodeTokenPrefix,
} from '@bitauth/libauth';

const sha256 = bytes => createHash('sha256').update(bytes).digest();
const PF7 = JSON.parse(readFileSync(new URL('./pf7-v0-locks.json', import.meta.url)));
const op = {
  CAT: 0x7e, NUM2BIN: 0x80, SIZE: 0x82, EQUAL: 0x87, EQUALVERIFY: 0x88, SHA256: 0xa8,
  REVERSEBYTES: 0xbc, TXVERSION: 0xc2, TXINPUTCOUNT: 0xc3, TXLOCKTIME: 0xc5,
  UTXOVALUE: 0xc6, UTXOBYTECODE: 0xc7, OUTPOINTTXHASH: 0xc8,
  OUTPOINTINDEX: 0xc9, INPUTSEQUENCE: 0xcb, OUTPUTVALUE: 0xcc,
  OUTPUTBYTECODE: 0xcd, UTXOTOKENCATEGORY: 0xce, UTXOTOKENCOMMITMENT: 0xcf,
  UTXOTOKENAMOUNT: 0xd0, OUTPUTTOKENCATEGORY: 0xd1,
  OUTPUTTOKENCOMMITMENT: 0xd2, OUTPUTTOKENAMOUNT: 0xd3,
  DUP: 0x76, SWAP: 0x7c, SPLIT: 0x7f, TOALTSTACK: 0x6b,
  FROMALTSTACK: 0x6c, NIP: 0x77, SUB: 0x94,
};

const push = data => {
  const value = Buffer.from(data);
  if (value.length === 0) return Buffer.of(0);
  if (value.length === 1 && value[0] === 0) return Buffer.of(0);
  if (value.length === 1 && value[0] >= 1 && value[0] <= 16) return Buffer.of(0x50 + value[0]);
  if (value.length === 1 && value[0] === 0x81) return Buffer.of(0x4f);
  if (value.length <= 75) return Buffer.concat([Buffer.of(value.length), value]);
  if (value.length <= 255) return Buffer.concat([Buffer.of(0x4c, value.length), value]);
  if (value.length <= 65535) return Buffer.concat([Buffer.of(0x4d, value.length & 0xff, value.length >> 8), value]);
  throw new Error('push too large');
};
const vmNumber = value => {
  assert.ok(Number.isInteger(value) && value >= 0);
  if (value === 0) return Buffer.of(0);
  if (value >= 1 && value <= 16) return Buffer.of(0x50 + value);
  const bytes = []; let remaining = value;
  while (remaining) { bytes.push(remaining & 0xff); remaining >>>= 8; }
  if (bytes.at(-1) & 0x80) bytes.push(0);
  return push(Buffer.from(bytes));
};
const append = (out, item) => out.push(...item);
const appendOp = (out, opcode) => out.push(opcode);

const profileId = sha256(Buffer.from('g2-direct-probe-profile'));
const instanceId = sha256(Buffer.from('g2-direct-probe-instance'));
const stateCategory = sha256(Buffer.from('g2-direct-probe-state-category'));
const stateCommitment = Buffer.alloc(80, 0x42);
const mutableStateToken = { category: Uint8Array.from(stateCategory), amount: 0n, nft: { capability: 'mutable', commitment: Uint8Array.from(stateCommitment) } };
const noTokenHash = sha256(Buffer.alloc(0));
const stateTokenHash = sha256(encodeTokenPrefix(mutableStateToken));
const p2pkh = Buffer.from('76a914111111111111111111111111111111111111111188ac', 'hex');
const accepts = result => result.error === undefined && result.stack.length === 1 && result.stack[0].some(byte => byte !== 0);

function sourceLocking(index, binding) {
  if (index < 7) return Buffer.from(PF7.locks[index], 'hex');
  if (index === 7) return binding;
  return index === 8 ? Buffer.from('51', 'hex') : p2pkh;
}

function tokenHash(out) { return sha256(encodeTokenPrefix(out.token)); }
function materials(binding) {
  const sourceOutputs = Array.from({ length: 10 }, (_, index) => ({
    valueSatoshis: index === 8 ? 10_000_000n : 1000n + BigInt(index),
    lockingBytecode: sourceLocking(index, binding),
    ...(index === 8 ? { token: mutableStateToken } : {}),
  }));
  const outputs = [
    { valueSatoshis: 10_000_000n, lockingBytecode: Buffer.from('51', 'hex'), token: mutableStateToken },
    { valueSatoshis: 5_000n, lockingBytecode: p2pkh },
  ];
  return { sourceOutputs, transaction: {
    version: 2, locktime: 0,
    inputs: Array.from({ length: 10 }, (_, index) => ({ outpointTransactionHash: Uint8Array.from(Buffer.alloc(32, index + 1)), outpointIndex: index, sequenceNumber: 0, unlockingBytecode: Buffer.alloc(0) })),
    outputs,
  } };
}

function scct(binding) {
  const m = materials(binding); const fields = [Buffer.from('SCCT'), Buffer.of(1, 2, 1, 0), profileId, instanceId, Buffer.of(10, 0, 2, 0)];
  // Libauth's transaction field is display/hash order; both SCCT and
  // OP_OUTPOINTTXHASH use serialized (OP_HASH256) wire order.
  for (let i = 0; i < 10; i += 1) { const input = m.transaction.inputs[i], source = m.sourceOutputs[i]; const index = Buffer.alloc(4); index.writeUInt32LE(input.outpointIndex); const sequence = Buffer.alloc(4); sequence.writeUInt32LE(input.sequenceNumber); const value = Buffer.alloc(8); value.writeBigUInt64LE(source.valueSatoshis); fields.push(Buffer.of(i), Buffer.from(input.outpointTransactionHash).reverse(), index, sequence, value, sha256(source.lockingBytecode), tokenHash(source)); }
  for (const [role, output] of [[0, m.transaction.outputs[0]], [1, m.transaction.outputs[1]]]) { const value = Buffer.alloc(8); value.writeBigUInt64LE(output.valueSatoshis); fields.push(Buffer.of(role), value, sha256(output.lockingBytecode), tokenHash(output)); }
  const preimage = Buffer.concat(fields); assert.equal(preimage.length, 1352); return { ...m, preimage, digest: sha256(preimage) };
}

// Append `piece` to a byte-string accumulator on the main stack.
function appendPiece(out, piece) { append(out, piece); appendOp(out, op.CAT); }
function appendByte(out, value) {
  if (value === 0) { appendOp(out, 0); append(out, vmNumber(1)); appendOp(out, op.NUM2BIN); appendOp(out, op.CAT); return; }
  appendPiece(out, push(Buffer.of(value)));
}
function noToken(out, index, source) {
  const category = source ? op.UTXOTOKENCATEGORY : op.OUTPUTTOKENCATEGORY;
  const commitment = source ? op.UTXOTOKENCOMMITMENT : op.OUTPUTTOKENCOMMITMENT;
  const amount = source ? op.UTXOTOKENAMOUNT : op.OUTPUTTOKENAMOUNT;
  for (const opcode of [category, commitment, amount]) { append(out, vmNumber(index)); appendOp(out, opcode); appendOp(out, 0); appendOp(out, op.EQUALVERIFY); }
  appendPiece(out, Buffer.of(0, op.SHA256));
}
function stateToken(out, index, source) {
  const category = source ? op.UTXOTOKENCATEGORY : op.OUTPUTTOKENCATEGORY;
  const commitment = source ? op.UTXOTOKENCOMMITMENT : op.OUTPUTTOKENCOMMITMENT;
  const amount = source ? op.UTXOTOKENAMOUNT : op.OUTPUTTOKENAMOUNT;
  // The token hash is a profile-fixture constant here, but all three actual
  // token introspection values are checked before it is appended. This keeps
  // the reconstruction exact while making the direct (unrolled) floor easy
  // to audit; a candidate must replace these fixture constants with
  // action-derived values.
  append(out, vmNumber(index)); appendOp(out, category); append(out, push(Buffer.concat([Buffer.from(stateCategory).reverse(), Buffer.of(1)]))); appendOp(out, op.EQUALVERIFY);
  append(out, vmNumber(index)); appendOp(out, commitment); append(out, push(stateCommitment)); appendOp(out, op.EQUALVERIFY);
  append(out, vmNumber(index)); appendOp(out, amount); appendOp(out, 0); appendOp(out, op.EQUALVERIFY);
  appendPiece(out, push(stateTokenHash));
}

function buildDirectScctLock(raw = false) {
  const out = [];
  // Canonical single PUSHDATA2 of exactly 752 bytes: 4d f0 02 || SCAR.
  appendOp(out, op.DUP); appendOp(out, op.SIZE); append(out, vmNumber(752)); appendOp(out, op.EQUALVERIFY); appendOp(out, op.NIP);
  appendOp(out, op.DUP); append(out, vmNumber(7)); appendOp(out, 0xca); appendOp(out, op.SWAP); append(out, push(Buffer.from([0x4d, 0xf0, 0x02]))); appendOp(out, op.SWAP); appendOp(out, op.CAT); appendOp(out, op.EQUALVERIFY);
  appendOp(out, op.TOALTSTACK);
  // Fixed SCCT v1 deposit header. The packet's full semantics and header are
  // outside this probe; terminal proof verification is responsible for them.
  append(out, push(Buffer.concat([Buffer.from('SCCT'), Buffer.of(1, 2, 1, 0), profileId, instanceId, Buffer.of(10, 0, 2, 0)])));
  for (let index = 0; index < 10; index += 1) {
    appendByte(out, index);
    append(out, vmNumber(index)); appendOp(out, op.OUTPOINTTXHASH); appendOp(out, op.CAT);
    append(out, vmNumber(index)); appendOp(out, op.OUTPOINTINDEX); append(out, vmNumber(4)); appendOp(out, op.NUM2BIN); appendOp(out, op.CAT);
    append(out, vmNumber(index)); appendOp(out, op.INPUTSEQUENCE); append(out, vmNumber(4)); appendOp(out, op.NUM2BIN); appendOp(out, op.CAT);
    append(out, vmNumber(index)); appendOp(out, op.UTXOVALUE); append(out, vmNumber(8)); appendOp(out, op.NUM2BIN); appendOp(out, op.CAT);
    append(out, vmNumber(index)); appendOp(out, op.UTXOBYTECODE); appendOp(out, op.SHA256); appendOp(out, op.CAT);
    if (index === 8) stateToken(out, index, true); else noToken(out, index, true);
  }
  for (const [index, role] of [[0, 0], [1, 1]]) {
    appendByte(out, role);
    append(out, vmNumber(index)); appendOp(out, op.OUTPUTVALUE); append(out, vmNumber(8)); appendOp(out, op.NUM2BIN); appendOp(out, op.CAT);
    append(out, vmNumber(index)); appendOp(out, op.OUTPUTBYTECODE); appendOp(out, op.SHA256); appendOp(out, op.CAT);
    if (index === 0) stateToken(out, index, false); else noToken(out, index, false);
  }
  if (raw) { appendOp(out, op.FROMALTSTACK); appendOp(out, 0x75); return Uint8Array.from(out); }
  appendOp(out, op.SHA256); appendOp(out, op.FROMALTSTACK); appendOp(out, op.SIZE); append(out, vmNumber(32)); appendOp(out, op.SUB); appendOp(out, op.SPLIT); appendOp(out, op.NIP); appendOp(out, op.EQUAL);
  return Uint8Array.from(out);
}

function program(lock, packet, mutate = undefined) {
  const context = scct(lock); const tx = structuredClone(context.transaction); const sourceOutputs = structuredClone(context.sourceOutputs);
  tx.inputs[7].unlockingBytecode = Buffer.concat([Buffer.from([0x4d, 0xf0, 0x02]), packet]);
  if (mutate) mutate({ tx, sourceOutputs, packet });
  return { inputIndex: 7, sourceOutputs, transaction: tx };
}

test('direct exact-SCCT reconstruction executes in the BCH-2026 standard VM and rejects sampled introspection mutations', () => {
  const vm = createVirtualMachineBch2026(true);
  const rawLock = buildDirectScctLock(true); const rawExpected = scct(rawLock); const rawPacket = Buffer.alloc(752); Buffer.from('SCAR').copy(rawPacket); rawPacket.set([1, 2, 1, 0], 4);
  const raw = vm.evaluate(program(rawLock, rawPacket)); assert.equal(raw.error, undefined, raw.error); const rawPreimage = Buffer.from(raw.stack[0]); if (!rawPreimage.equals(rawExpected.preimage)) { let mismatch = 0; while (mismatch < Math.min(rawPreimage.length, rawExpected.preimage.length) && rawPreimage[mismatch] === rawExpected.preimage[mismatch]) mismatch += 1; throw new Error(`direct SCCT mismatch actual=${rawPreimage.length} expected=${rawExpected.preimage.length} first=${mismatch} actual=${rawPreimage.subarray(mismatch, mismatch + 16).toString('hex')} expected=${rawExpected.preimage.subarray(mismatch, mismatch + 16).toString('hex')}`); }
  const lock = buildDirectScctLock(); const expected = scct(lock); const packet = Buffer.alloc(752); Buffer.from('SCAR').copy(packet); packet.set([1, 2, 1, 0], 4); expected.digest.copy(packet, 720);
  const accepted = vm.evaluate(program(lock, packet));
  assert.equal(accepts(accepted), true, accepted.error); assert.equal(lock.length > 190, true);
  assert.equal(disassembleBytecodeBch(lock).includes('OP_UTXOBYTECODE'), true);
  const mutations = [
    ['outpoint-wire', p => { p.tx.inputs[0].outpointTransactionHash[0] ^= 1; }],
    ['outpoint-index', p => { p.tx.inputs[1].outpointIndex = 9; }],
    ['sequence', p => { p.tx.inputs[2].sequenceNumber = 1; }],
    ['source-value', p => { p.sourceOutputs[3].valueSatoshis += 1n; }],
    ['pf7-source-lock', p => { p.sourceOutputs[4].lockingBytecode = Uint8Array.of(0x51); }],
    ['binding-source-lock', p => { p.sourceOutputs[7].lockingBytecode = Uint8Array.of(0x51); }],
    ['state-category', p => { p.sourceOutputs[8].token.category[0] ^= 1; }],
    ['state-commitment', p => { p.sourceOutputs[8].token.nft.commitment[0] ^= 1; }],
    ['fee-token', p => { p.sourceOutputs[9].token = { category: Uint8Array.from(stateCategory), amount: 1n }; }],
    ['state-output-value', p => { p.tx.outputs[0].valueSatoshis += 1n; }],
    ['change-output-lock', p => { p.tx.outputs[1].lockingBytecode = Uint8Array.of(0x51); }],
    ['state-output-token', p => { p.tx.outputs[0].token.nft.commitment[0] ^= 1; }],
    ['noncanonical-packet-push', p => { p.tx.inputs[7].unlockingBytecode = Buffer.concat([Buffer.from([0x4e, 0xf0, 0x02, 0, 0]), packet]); }],
    ['packet-context', p => { p.tx.inputs[7].unlockingBytecode[3 + 720] ^= 1; }],
  ];
  for (const [name, mutate] of mutations) { const result = vm.evaluate(program(lock, packet, mutate)); assert.equal(accepts(result), false, name); }
  const asm = disassembleBytecodeBch(lock);
  console.log(JSON.stringify({ lockingBytes: lock.length, unlockingBytes: 755, operationCost: accepted.metrics.operationCost, allBytesContribution: lock.length + 755, directScctBytes: expected.preimage.length, asmSha256: sha256(Buffer.from(asm)).toString('hex') }, null, 2));
});
