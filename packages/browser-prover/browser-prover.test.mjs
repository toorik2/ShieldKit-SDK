import test from 'node:test';
import assert from 'node:assert/strict';
import { BrowserProverError, parseManifest } from './browser-prover.mjs';

const sha = 'a'.repeat(64);
const pinned = (path) => ({ path, sha256: sha });
const manifest = () => ({ schema: 'shield.cash/browser-prover/v1', browser: pinned('/usr/bin/chromium'), playwrightModule: pinned('/tool/playwright.mjs'), snarkjsBundle: pinned('/tool/snarkjs.min.js'), snarkjsCli: pinned('/tool/cli.cjs'), profile: { bundleDirectory: '/profiles/chipnet', expected: { network: 'chipnet', profileId: `sha256:${sha}`, instanceId: `sha256:${'b'.repeat(64)}` } }, actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, input: pinned(`/input/${kind}.json`), expectedPublicSignals: ['1', '2'] })), repetitions: 1, selectedAction: 'deposit', witnessMemoryPages: 1, outputDirectory: '/tmp/browser-output' });

test('accepts an absolute pinned browser manifest', () => assert.equal(parseManifest(manifest()).repetitions, 1));
test('rejects relative profile paths and noncanonical public signals', () => { const value = manifest(); value.profile.bundleDirectory = 'relative-profile'; assert.throws(() => parseManifest(value), BrowserProverError); value.profile.bundleDirectory = '/profiles/chipnet'; value.actions[0].expectedPublicSignals = ['01', '2']; assert.throws(() => parseManifest(value), BrowserProverError); });
test('rejects an action not present in the canonical action set', () => { const value = manifest(); value.selectedAction = 'merge'; assert.throws(() => parseManifest(value), BrowserProverError); });
test('requires a bounded positive witness-memory request', () => { const value = manifest(); value.witnessMemoryPages = 0; assert.throws(() => parseManifest(value), BrowserProverError); });
