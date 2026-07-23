import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { extractVerifierSet, Pf7VerifierGeneratorError, validateAdapter, validateProvenance } from './pf7-verifier-generator.mjs';

const hash256 = (bytes) => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
const lockFor = (redeem) => Buffer.concat([Buffer.from([0xaa, 0x20]), hash256(redeem), Buffer.from([0x87])]).toString('hex');
const push = (bytes) => Buffer.concat([Buffer.from([bytes.length]), bytes]).toString('hex');
const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];

test('retained PF7 format-patch chain is hash-pinned and complete', async () => {
  const provenance = await validateProvenance();
  assert.equal(provenance.patches.length, 7);
  assert.equal(provenance.terminal.commit, '17c6b9552c48b0fc5271be626a1578fb0065df09');
});

test('seven exact P2SH32 source/redeem pairs are canonicalized in role order', () => {
  const inputs = names.map((name, index) => { const redeem = Buffer.from([0x51, index]); return { name, lock: lockFor(redeem), unlock: push(redeem) }; });
  const set = extractVerifierSet(inputs);
  assert.equal(set.length, 7);
  assert.equal(set[6].name, 'terminal');
  assert.equal(set[0].redeemBytecodeHex, '5100');
});

test('source/redeem tampering and generic topology are rejected before output', () => {
  const inputs = names.map((name) => { const redeem = Buffer.from([0x51]); return { name, lock: lockFor(redeem), unlock: push(redeem) }; });
  inputs[3].lock = `${inputs[3].lock.slice(0, -2)}86`;
  assert.throws(() => extractVerifierSet(inputs), Pf7VerifierGeneratorError);
  assert.throws(() => extractVerifierSet(inputs.slice(0, 6)), Pf7VerifierGeneratorError);
});

test('adapter parser rejects non-complete or wrong-schema input', () => {
  assert.throws(() => validateAdapter(Buffer.from('{"schema":"wrong"}')), Pf7VerifierGeneratorError);
});
