import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { PROVER_ARTIFACT_BUDGET_BYTES, budgetVerdict, canonicalJson, packageProverArtifacts } from './prover-artifact-budget.mjs';

const execFileAsync = promisify(execFile);
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
async function fileHash(filename) { return digest(await readFile(filename)); }
async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shield-cash-artifact-budget-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const zkey = path.join(root, 'final.zkey'); const wasm = path.join(root, 'witness-generator.wasm');
  await writeFile(zkey, Buffer.concat(Array.from({ length: 16 }, (_, i) => Buffer.from(`real-small-zkey-roundtrip-${i}\n`))));
  await writeFile(wasm, Buffer.concat(Array.from({ length: 20 }, (_, i) => Buffer.from(`\0asm-small-witness-${i}\n`))));
  return { root, zkey, wasm };
}
async function realZstd() {
  const binary = '/usr/bin/zstd'; const { stdout } = await execFileAsync(binary, ['--version']);
  return { path: binary, sha256: await fileHash(binary), version: stdout.trim() };
}
async function inputFor(data, zstd, destination = path.join(data.root, 'packed')) {
  return { destination, zstd, finalZkey: { path: data.zkey, sha256: await fileHash(data.zkey) }, witnessGeneratorWasm: { path: data.wasm, sha256: await fileHash(data.wasm) } };
}

test('real small files round-trip through pinned zstd with canonical PASS output', async (t) => {
  const data = await fixture(t); const input = await inputFor(data, await realZstd()); const result = await packageProverArtifacts(input);
  assert.equal(result.budget.verdict, 'PASS'); assert.equal(result.budget.compressedLimitBytes, PROVER_ARTIFACT_BUDGET_BYTES);
  assert.equal(canonicalJson(result), (await readFile(path.join(input.destination, 'result.json'), 'utf8')).trim());
  assert.equal(result.node.version, process.version); assert.deepEqual(result.zstd, input.zstd);
  assert.equal(result.artifacts.finalZkey.source.sha256, await fileHash(data.zkey));
  assert.equal(result.artifacts.witnessGeneratorWasm.source.sha256, await fileHash(data.wasm));
  assert.match(result.artifacts.finalZkey.compressed.sha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(result.artifacts.witnessGeneratorWasm.compressed.sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(result.budget.totalCompressedBytes, result.artifacts.finalZkey.compressed.bytes + result.artifacts.witnessGeneratorWasm.compressed.bytes);
  assert.match(result.scope, /not G1 qualification/);
  await lstat(path.join(input.destination, 'final.zkey.zst')); await lstat(path.join(input.destination, 'witness-generator.wasm.zst'));
});

test('rejects bad pins, direct-input symlinks, duplicates, and overwrite attempts', async (t) => {
  const data = await fixture(t); const zstd = await realZstd(); const badHash = await inputFor(data, zstd);
  badHash.finalZkey.sha256 = `sha256:${'0'.repeat(64)}`;
  await assert.rejects(() => packageProverArtifacts(badHash), /finalZkey hash mismatch/);
  const badZstd = await inputFor(data, zstd); badZstd.zstd = { ...zstd, sha256: `sha256:${'0'.repeat(64)}` };
  await assert.rejects(() => packageProverArtifacts(badZstd), /zstd hash mismatch/);
  const link = path.join(data.root, 'linked.zkey'); await symlink(data.zkey, link);
  const symlinkInput = await inputFor(data, zstd); symlinkInput.finalZkey.path = link;
  await assert.rejects(() => packageProverArtifacts(symlinkInput), /regular non-symlink file/);
  const duplicate = await inputFor(data, zstd); duplicate.witnessGeneratorWasm = { path: data.zkey, sha256: await fileHash(data.zkey) };
  await assert.rejects(() => packageProverArtifacts(duplicate), /inputs must be distinct/);
  const overwrite = await inputFor(data, zstd); await mkdir(overwrite.destination);
  await assert.rejects(() => packageProverArtifacts(overwrite), /destination already exists/);
});

test('fixed budget is not caller-overridable and FAIL remains measurable', () => {
  assert.equal(budgetVerdict(PROVER_ARTIFACT_BUDGET_BYTES), 'PASS');
  assert.equal(budgetVerdict(PROVER_ARTIFACT_BUDGET_BYTES + 1), 'FAIL');
  assert.throws(() => budgetVerdict(-1), /non-negative safe integer/);
});

async function fakeZstd(t, root, body) {
  const binary = path.join(root, `fake-zstd-${Math.random().toString(16).slice(2)}.sh`);
  await writeFile(binary, `#!/bin/sh\nif [ "$1" = "--version" ]; then echo fake-zstd-1; exit 0; fi\n${body}\n`); await chmod(binary, 0o700);
  return { path: binary, sha256: await fileHash(binary), version: 'fake-zstd-1' };
}

test('detects source changes after compression and bounds zstd stderr', async (t) => {
  const data = await fixture(t);
  const mutating = await fakeZstd(t, data.root, 'out=""; last=""; prev=""; for arg in "$@"; do if [ "$prev" = "-o" ]; then out="$arg"; fi; prev="$arg"; last="$arg"; done; if [ "$1" = "-d" ]; then cat "$last"; else cp "$last" "$out"; printf X >> "$last"; fi');
  const mutationInput = await inputFor(data, mutating, path.join(data.root, 'mutation-output'));
  await assert.rejects(() => packageProverArtifacts(mutationInput), /changed during packaging/);
  const noisy = await fakeZstd(t, data.root, 'head -c 70000 /dev/zero | tr "\\000" x >&2; exit 1');
  const noisyInput = await inputFor(data, noisy, path.join(data.root, 'noisy-output'));
  await assert.rejects(() => packageProverArtifacts(noisyInput), /bounded capture limit/);
});
