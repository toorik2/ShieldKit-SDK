import test from 'node:test';
import assert from 'node:assert/strict';
import { NativeProverAdapterError, parseManifest } from './native-prover-adapter.mjs';

const hash = 'a'.repeat(64);
const valid = () => ({ schema: 'shield.cash/native-prover-adapter/v1', nativeProver: { path: '/native/prover', sha256: hash }, snarkjs: { path: '/native/snarkjs.cjs', sha256: hash, version: '0.7.6' }, artifacts: { zkey: { path: '/native/final.zkey', sha256: hash }, verificationKey: { path: '/native/vk.json', sha256: hash } }, actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, witness: { path: `/native/${kind}.wtns`, sha256: hash }, expectedPublicSignals: ['1', '2'] })), repetitions: 3, outputDirectory: '/tmp/native-prover-output' });

test('accepts exactly the three action kinds and pinned records', () => assert.equal(parseManifest(valid()).repetitions, 3));
test('rejects unknown or duplicate action kinds', () => { const input = valid(); input.actions[2].kind = 'deposit'; assert.throws(() => parseManifest(input), NativeProverAdapterError); });
test('rejects malformed hashes and unbounded repetitions', () => { const input = valid(); input.nativeProver.sha256 = 'z'; assert.throws(() => parseManifest(input), NativeProverAdapterError); input.nativeProver.sha256 = hash; input.repetitions = 11; assert.throws(() => parseManifest(input), NativeProverAdapterError); });
