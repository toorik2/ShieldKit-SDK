import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { loadCliConfig } from './cli.mjs';
import { assertCleanGitRepository, extractVerifierSet, Pf7VerifierGeneratorError, validateAdapter, validateProvenance, validateRuntimePackageVersions } from './pf7-verifier-generator.mjs';

const execFileAsync = promisify(execFile);
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

test('all provenance repositories must have neither tracked nor untracked changes', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-clean-git-'));
  try {
    await execFileAsync('git', ['init', '-q', directory]);
    await execFileAsync('git', ['-C', directory, 'config', 'user.email', 'pf7@example.invalid']);
    await execFileAsync('git', ['-C', directory, 'config', 'user.name', 'PF7 test']);
    await writeFile(path.join(directory, 'tracked.txt'), 'clean\n');
    await execFileAsync('git', ['-C', directory, 'add', 'tracked.txt']);
    await execFileAsync('git', ['-C', directory, 'commit', '-qm', 'initial']);
    assert.equal(await assertCleanGitRepository(directory, 'fixture'), directory);
    await writeFile(path.join(directory, 'tracked.txt'), 'changed\n');
    await assert.rejects(assertCleanGitRepository(directory, 'fixture'), Pf7VerifierGeneratorError);
    await execFileAsync('git', ['-C', directory, 'checkout', '--', 'tracked.txt']);
    await writeFile(path.join(directory, 'untracked.txt'), 'present\n');
    await assert.rejects(assertCleanGitRepository(directory, 'fixture'), Pf7VerifierGeneratorError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('CLI accepts only direct strict-JSON configuration files', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-cli-config-'));
  try {
    const valid = path.join(directory, 'valid.json');
    await writeFile(valid, '{}');
    assert.equal(JSON.stringify(await loadCliConfig(valid)), '{}');
    for (const [name, contents] of [['duplicate.json', '{"a":1,"a":2}'], ['trailing.json', '{}{}'], ['bom.json', Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])]]) {
      const file = path.join(directory, name);
      await writeFile(file, contents);
      await assert.rejects(loadCliConfig(file));
    }
    const linked = path.join(directory, 'linked.json');
    await symlink(valid, linked);
    await assert.rejects(loadCliConfig(linked), /regular non-symlink/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('runtime package closure rejects a symlink boundary and version drift', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-runtime-'));
  try {
    const expected = { '@fixture/runtime': '1.2.3' };
    const direct = path.join(directory, 'node_modules');
    const packageDirectory = path.join(direct, '@fixture', 'runtime');
    await mkdir(packageDirectory, { recursive: true });
    await writeFile(path.join(packageDirectory, 'package.json'), '{"version":"1.2.3"}');
    assert.deepEqual(await validateRuntimePackageVersions(direct, expected, 'fixture'), expected);
    await writeFile(path.join(packageDirectory, 'package.json'), '{"version":"1.2.4"}');
    await assert.rejects(validateRuntimePackageVersions(direct, expected, 'fixture'), Pf7VerifierGeneratorError);
    const linked = path.join(directory, 'linked-node_modules');
    await symlink(direct, linked);
    await assert.rejects(validateRuntimePackageVersions(linked, expected, 'fixture'), Pf7VerifierGeneratorError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
