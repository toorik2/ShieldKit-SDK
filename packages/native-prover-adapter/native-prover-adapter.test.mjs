import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NativeProverAdapterError, parseManifest, parseStrictJson, runNativeProverAdapter } from './native-prover-adapter.mjs';

const digest = (text) => createHash('sha256').update(text).digest('hex');
const hash = 'a'.repeat(64);
const valid = () => ({ schema: 'shield.cash/native-prover-adapter/v1', nativeProver: { path: '/native/prover', sha256: hash }, snarkjs: { path: '/native/snarkjs.cjs', sha256: hash, version: '0.7.6' }, artifacts: { zkey: { path: '/native/final.zkey', sha256: hash }, verificationKey: { path: '/native/vk.json', sha256: hash } }, actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, witness: { path: `/native/${kind}.wtns`, sha256: hash }, expectedPublicSignals: ['1', '2'] })), repetitions: 1, outputDirectory: '/tmp/native-prover-output' });

const executable = async (path, source) => { await writeFile(path, source, { mode: 0o700 }); await chmod(path, 0o700); };
const record = async (path) => ({ path, sha256: digest(await readFile(path)) });
const noStaging = async (root) => assert.deepEqual((await readdir(root)).filter((name) => name.includes('.staging-')), []);
const fixture = async (t, { publicSignals = '["1","2"]', mutate = '' } = {}) => {
  const root = await mkdtemp(join(tmpdir(), 'shield-native-prover-test-')); t.after(async () => rm(root, { recursive: true, force: true }));
  const native = join(root, 'prover.mjs'); const snarkjs = join(root, 'snarkjs.mjs'); const zkey = join(root, 'final.zkey'); const vk = join(root, 'vk.json');
  await writeFile(zkey, 'zkey'); await writeFile(vk, '{}');
  await executable(native, `#!/usr/bin/env node\nimport { writeFileSync, appendFileSync } from 'node:fs';\nconst args = process.argv.slice(2); ${mutate === 'prover' ? "appendFileSync(process.argv[1], '\\n// changed');" : ''}\nwriteFileSync(args[2], '{}'); writeFileSync(args[3], ${JSON.stringify(publicSignals)});\n`);
  await executable(snarkjs, `#!/usr/bin/env node\n${mutate === 'snarkjs' ? "import { appendFileSync } from 'node:fs';" : ''}\nconst args = process.argv.slice(2); if (args[0] === '--version') { console.log('snarkjs@0.7.6'); process.exit(99); } ${mutate === 'snarkjs' ? "appendFileSync(process.argv[1], '\\n// changed');" : ''}\nprocess.exit(0);\n`);
  const actions = [];
  for (const kind of ['deposit', 'transfer', 'withdrawal']) { const witness = join(root, `${kind}.wtns`); await writeFile(witness, kind); actions.push({ kind, witness: await record(witness), expectedPublicSignals: ['1', '2'] }); }
  const manifest = { schema: 'shield.cash/native-prover-adapter/v1', nativeProver: await record(native), snarkjs: { ...await record(snarkjs), version: '0.7.6' }, artifacts: { zkey: await record(zkey), verificationKey: await record(vk) }, actions, repetitions: 1, outputDirectory: join(root, 'published') };
  const manifestPath = join(root, 'manifest.json'); const save = async () => writeFile(manifestPath, `${JSON.stringify(manifest)}\n`); await save(); return { root, native, snarkjs, zkey, manifest, manifestPath, save };
};

test('accepts exactly the three action kinds and pinned records', () => assert.equal(parseManifest(valid()).repetitions, 1));
test('rejects unknown or duplicate action kinds', () => { const input = valid(); input.actions[2].kind = 'deposit'; assert.throws(() => parseManifest(input), NativeProverAdapterError); });
test('rejects malformed hashes, unbounded repetitions, extra signals, and non-canonical scalars', () => { const input = valid(); input.nativeProver.sha256 = 'z'; assert.throws(() => parseManifest(input), NativeProverAdapterError); input.nativeProver.sha256 = hash; input.repetitions = 11; assert.throws(() => parseManifest(input), NativeProverAdapterError); input.repetitions = 1; input.actions[0].expectedPublicSignals = ['1', '2', '3']; assert.throws(() => parseManifest(input), NativeProverAdapterError); input.actions[0].expectedPublicSignals = ['01', '2']; assert.throws(() => parseManifest(input), NativeProverAdapterError); input.actions[0].expectedPublicSignals = ['21888242871839275222246405745257275088548364400416034343698204186575808495617', '2']; assert.throws(() => parseManifest(input), NativeProverAdapterError); });
test('strict parser rejects duplicate keys at every object scope and preserves escaped strings', () => { assert.throws(() => parseStrictJson('{"a":1,"a":2}', 'manifest'), NativeProverAdapterError); assert.throws(() => parseStrictJson('{"a":{"b":1,"b":2}}', 'manifest'), NativeProverAdapterError); assert.equal(parseStrictJson(JSON.stringify({ a: 'x\\"y' }), 'manifest').a, 'x\\"y'); });
test('rejects duplicate manifest keys before execution', async (t) => { const f = await fixture(t); const text = await readFile(f.manifestPath, 'utf8'); await writeFile(f.manifestPath, text.replace('{', '{"schema":"shield.cash/native-prover-adapter/v1",')); await assert.rejects(runNativeProverAdapter(f.manifestPath), NativeProverAdapterError); });
test('rejects a non-UTF-8 manifest before execution', async (t) => { const f = await fixture(t); await writeFile(f.manifestPath, Buffer.from([0x7b, 0xff, 0x7d])); await assert.rejects(runNativeProverAdapter(f.manifestPath), /not valid UTF-8/); });
test('rejects witness path hash drift before native execution', async (t) => { const f = await fixture(t); await writeFile(f.manifest.actions[0].witness.path, 'tampered'); await assert.rejects(runNativeProverAdapter(f.manifestPath), /SHA-256 mismatch/); await assert.rejects(lstat(f.manifest.outputDirectory)); });
test('rejects a symlink input even when its target hash matches', async (t) => { const f = await fixture(t); const target = join(f.root, 'zkey-target'); await writeFile(target, 'zkey'); await rm(f.zkey); await symlink(target, f.zkey); await assert.rejects(runNativeProverAdapter(f.manifestPath), /direct regular non-symlink/); });
test('rejects a symlink output parent', async (t) => { const f = await fixture(t); const target = join(f.root, 'real-parent'); const link = join(f.root, 'linked-parent'); await mkdir(target); await symlink(target, link); f.manifest.outputDirectory = join(link, 'published'); await f.save(); await assert.rejects(runNativeProverAdapter(f.manifestPath), /output parent must be a direct non-symlink directory/); });
test('detects a self-mutating native prover and cleans staging', async (t) => { const f = await fixture(t, { mutate: 'prover' }); await assert.rejects(runNativeProverAdapter(f.manifestPath), /nativeProver (identity|content) changed/); await noStaging(f.root); });
test('detects a self-mutating verifier tool and cleans staging', async (t) => { const f = await fixture(t, { mutate: 'snarkjs' }); await assert.rejects(runNativeProverAdapter(f.manifestPath), /snarkjs (identity|content) changed/); await noStaging(f.root); });
test('rejects malformed or extra native public signals and cleans staging', async (t) => { const f = await fixture(t, { publicSignals: '["1","2","3"]' }); await assert.rejects(runNativeProverAdapter(f.manifestPath), /exactly two public signals/); await noStaging(f.root); });
test('does not overwrite an existing output destination', async (t) => { const f = await fixture(t); await writeFile(f.manifest.outputDirectory, 'occupied'); await assert.rejects(runNativeProverAdapter(f.manifestPath), /already exists/); assert.equal(await readFile(f.manifest.outputDirectory, 'utf8'), 'occupied'); await noStaging(f.root); });
test('runs a pinned happy path and publishes an atomically staged result', async (t) => { const f = await fixture(t); const result = await runNativeProverAdapter(f.manifestPath); assert.equal(result.actions.length, 3); assert.equal((await readFile(join(f.manifest.outputDirectory, 'result.json'), 'utf8')).includes('native-prover-adapter-result/v1'), true); assert.match(result.nativeProver.ino, /^\d+$/); await noStaging(f.root); });
