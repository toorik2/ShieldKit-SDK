import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { encodeTokenPrefix } from '@bitauth/libauth';
import { INPUT_ROLES, SettlementContextError, canonicalTokenPrefix, encodeSettlementContext, validateSettlementContext } from './settlement-context.mjs';

const clone = value => JSON.parse(JSON.stringify(value));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const hex = (byte, bytes) => byte.toString(16).padStart(2, '0').repeat(bytes);
const output = (byte, token = null, valueSatoshis = '1000') => ({ valueSatoshis, lockingBytecode: `51${hex(byte, 2)}`, token });
const token = () => ({ category: hex(0xab, 32), amount: '0', nft: { capability: 'mutable', commitment: 'c0ffee' } });
const materials = (kind = 'deposit') => ({ kind, profileId: hex(0x11, 32), instanceId: hex(0x22, 32), transaction: { version: '2', locktime: '0', inputs: INPUT_ROLES.map((_, index) => ({ outpointTransactionHashWire: hex(index, 32), outpointIndex: String(index), sequenceNumber: '0' })), outputs: kind === 'withdrawal' ? [output(1, token()), output(2, null, '10000000'), output(3)] : [output(1, token()), output(3)] }, sourceOutputs: INPUT_ROLES.map((_, index) => output(index + 10, index === 8 ? token() : null, String(1000 + index))) });
const u16le = value => { const out = Buffer.alloc(2); out.writeUInt16LE(value); return out; };
const u32le = value => { const out = Buffer.alloc(4); out.writeUInt32LE(Number(value)); return out; };
const u64le = value => { const out = Buffer.alloc(8); out.writeBigUInt64LE(BigInt(value)); return out; };
const digest = value => createHash('sha256').update(value).digest();
const directToken = value => value === null ? Buffer.alloc(0) : Buffer.from(encodeTokenPrefix({ amount: BigInt(value.amount), category: Uint8Array.from(Buffer.from(value.category, 'hex')), ...(value.nft === null ? {} : { nft: { capability: value.nft.capability, commitment: Uint8Array.from(Buffer.from(value.nft.commitment, 'hex')) } }) }));
const independentConstruction = value => {
  const kind = { deposit: 1, transfer: 2, withdrawal: 3 }[value.kind]; const outputRole = value.kind === 'withdrawal' ? [0, 2, 1] : [0, 1];
  const fields = [Buffer.from('SCCT'), Buffer.of(1, 2, kind, 0), Buffer.from(value.profileId, 'hex'), Buffer.from(value.instanceId, 'hex'), u16le(10), u16le(value.transaction.outputs.length)];
  for (let index = 0; index < 10; index += 1) { const input = value.transaction.inputs[index], source = value.sourceOutputs[index]; fields.push(Buffer.of(index), Buffer.from(input.outpointTransactionHashWire, 'hex'), u32le(input.outpointIndex), u32le(input.sequenceNumber), u64le(source.valueSatoshis), digest(Buffer.from(source.lockingBytecode, 'hex')), digest(directToken(source.token))); }
  for (let index = 0; index < value.transaction.outputs.length; index += 1) { const out = value.transaction.outputs[index]; fields.push(Buffer.of(outputRole[index]), u64le(out.valueSatoshis), digest(Buffer.from(out.lockingBytecode, 'hex')), digest(directToken(out.token))); }
  return Buffer.concat(fields);
};

test('encodes fixed offsets, role order, and exact deposit/withdrawal lengths', () => {
  const deposit = encodeSettlementContext(materials('deposit')); const withdrawal = encodeSettlementContext(materials('withdrawal'));
  assert.equal(deposit.preimage.length, 1352); assert.equal(withdrawal.preimage.length, 1425);
  assert.equal(deposit.preimage.subarray(0, 4).toString(), 'SCCT'); assert.deepEqual([...deposit.preimage.subarray(4, 8)], [1, 2, 1, 0]);
  assert.equal(deposit.preimage.readUInt16LE(72), 10); assert.equal(deposit.preimage.readUInt16LE(74), 2);
  assert.deepEqual([...deposit.preimage.subarray(76, 77)], [0]); assert.deepEqual([...deposit.preimage.subarray(76 + 9 * 113, 76 + 9 * 113 + 1)], [9]);
  assert.deepEqual([...deposit.preimage.subarray(1206, 1207)], [0]); assert.deepEqual([...deposit.preimage.subarray(1279, 1280)], [1]);
  assert.deepEqual([...withdrawal.preimage.subarray(1206, 1207)], [0]); assert.deepEqual([...withdrawal.preimage.subarray(1279, 1280)], [2]); assert.deepEqual([...withdrawal.preimage.subarray(1352, 1353)], [1]);
});

test('uses libauth CashTokens prefix bytes and explicit empty no-token prefix', () => {
  const m = materials(); const prefix = canonicalTokenPrefix({ amount: 0n, category: Uint8Array.from(Buffer.from(m.sourceOutputs[8].token.category, 'hex')), nft: { capability: 'mutable', commitment: Uint8Array.from(Buffer.from('c0ffee', 'hex')) } });
  assert.deepEqual(prefix, encodeTokenPrefix({ amount: 0n, category: Uint8Array.from(Buffer.from(m.sourceOutputs[8].token.category, 'hex')), nft: { capability: 'mutable', commitment: Uint8Array.from(Buffer.from('c0ffee', 'hex')) } }));
  assert.equal(canonicalTokenPrefix(undefined).length, 0);
  const result = encodeSettlementContext(m); const sourceTokenHashOffset = 76 + 8 * 113 + 81;
  assert.equal(result.preimage.subarray(sourceTokenHashOffset, sourceTokenHashOffset + 32).toString('hex'), hash(prefix));
  assert.equal(result.preimage.subarray(76 + 81, 76 + 113).toString('hex'), hash(Buffer.alloc(0)));
});

test('round-trips an independently supplied expected commitment only if all raw fields agree', () => {
  const m = materials('transfer'); const encoded = encodeSettlementContext(m); const expected = { preimageHex: encoded.preimageHex, digestHex: encoded.digestHex, publicInputLimbs: [...encoded.publicInputLimbs] };
  assert.equal(validateSettlementContext(expected, clone(m)).digestHex, encoded.digestHex);
  assert.equal(independentConstruction(m).toString('hex'), encoded.preimageHex);
  const changed = clone(m); changed.sourceOutputs[7].lockingBytecode = '52'; assert.throws(() => validateSettlementContext(expected, changed), SettlementContextError);
});

test('rejects action layouts, role-count changes, and transaction-policy mutations', () => {
  for (const mutate of [m => { m.transaction.outputs.pop(); }, m => { m.transaction.inputs.pop(); }, m => { m.sourceOutputs.pop(); }, m => { m.transaction.version = '1'; }, m => { m.transaction.locktime = '1'; }, m => { m.transaction.inputs[5].sequenceNumber = '1'; }]) { const m = materials(); mutate(m); assert.throws(() => encodeSettlementContext(m), SettlementContextError); }
  const withdrawal = materials('withdrawal'); withdrawal.transaction.outputs.pop(); assert.throws(() => encodeSettlementContext(withdrawal), SettlementContextError);
});

test('commits every fixed role position, source field, output field, and wire-endian outpoint', () => {
  const base = encodeSettlementContext(materials()).digestHex;
  for (let index = 0; index < INPUT_ROLES.length; index += 1) {
    for (const mutate of [m => { m.transaction.inputs[index].outpointTransactionHashWire = hex(0xee - index, 32); }, m => { m.transaction.inputs[index].outpointIndex = String(100 + index); }, m => { m.sourceOutputs[index].valueSatoshis = String(2000 + index); }, m => { m.sourceOutputs[index].lockingBytecode = `52${hex(index, 1)}`; }]) { const m = materials(); mutate(m); assert.notEqual(encodeSettlementContext(m).digestHex, base, INPUT_ROLES[index]); }
    const nonzeroSequence = materials(); nonzeroSequence.transaction.inputs[index].sequenceNumber = '1'; assert.throws(() => encodeSettlementContext(nonzeroSequence), SettlementContextError, INPUT_ROLES[index]);
  }
  for (let index = 0; index < 2; index += 1) for (const mutate of [m => { m.transaction.outputs[index].valueSatoshis = String(2000 + index); }, m => { m.transaction.outputs[index].lockingBytecode = `53${hex(index, 1)}`; }]) { const m = materials(); mutate(m); assert.notEqual(encodeSettlementContext(m).digestHex, base); }
  for (let index = 0; index < 3; index += 1) for (const mutate of [m => { m.transaction.outputs[index].valueSatoshis = String(2000 + index); }, m => { m.transaction.outputs[index].lockingBytecode = `53${hex(index, 1)}`; }]) { const m = materials('withdrawal'); const before = encodeSettlementContext(m).digestHex; mutate(m); assert.notEqual(encodeSettlementContext(m).digestHex, before); }
  for (const mutate of [m => { m.sourceOutputs[8].token.nft.commitment = 'c0ffef'; }, m => { m.sourceOutputs[8].token.nft.capability = 'minting'; }, m => { m.transaction.outputs[0].token.nft.commitment = '00'; }]) { const m = materials(); mutate(m); assert.notEqual(encodeSettlementContext(m).digestHex, base); }
  const swapped = materials(); [swapped.transaction.inputs[0], swapped.transaction.inputs[1]] = [swapped.transaction.inputs[1], swapped.transaction.inputs[0]]; assert.notEqual(encodeSettlementContext(swapped).digestHex, base);
});

test('rejects noncanonical encodings, unbound hash fields, token ambiguity, and extras', () => {
  for (const mutate of [m => { m.profileId = `A${m.profileId.slice(1)}`; }, m => { m.instanceId = '0x01'; }, m => { m.sourceOutputs[0].valueSatoshis = '01'; }, m => { m.sourceOutputs[0].token = { category: hex(1, 32), amount: '0', nft: null }; }, m => { m.sourceOutputs[8].token.nft.commitment = hex(1, 129); }, m => { m.transaction.inputs[0].unlockingBytecode = '51'; }, m => { m.sourceOutputs[0].lockingBytecodeHash = hex(1, 32); }]) { const m = materials(); mutate(m); assert.throws(() => encodeSettlementContext(m), SettlementContextError); }
});
