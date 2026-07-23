import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserProverError, parseManifest } from './browser-prover.mjs';

const sha = 'a'.repeat(64);
const pinned = (path) => ({ path, sha256: sha });
const manifest = () => ({ schema: 'shield.cash/browser-prover/v1', browser: pinned('/usr/bin/chromium'), playwrightModule: pinned('/tool/playwright.mjs'), snarkjsBundle: pinned('/tool/snarkjs.min.js'), snarkjsCli: pinned('/tool/cli.cjs'), artifacts: { wasm: pinned('/artifact/relation.wasm'), zkey: pinned('/artifact/final.zkey'), verificationKey: pinned('/artifact/vk.json') }, actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, input: pinned(`/input/${kind}.json`), expectedPublicSignals: ['1', '2'] })), repetitions: 1, outputDirectory: '/tmp/browser-output' });

test('accepts an absolute pinned browser manifest', () => assert.equal(parseManifest(manifest()).repetitions, 1));
test('rejects relative paths and noncanonical public signals', () => { const value = manifest(); value.artifacts.zkey.path = 'relative.zkey'; assert.throws(() => parseManifest(value), BrowserProverError); value.artifacts.zkey.path = '/artifact/final.zkey'; value.actions[0].expectedPublicSignals = ['01', '2']; assert.throws(() => parseManifest(value), BrowserProverError); });
