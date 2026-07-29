import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmod, link, lstat, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  buildV2RecoveryScannerForUnitTest,
  parseV2RecoveryScannerBuildArguments,
  V2RecoveryScannerBuildError,
} from './v2-build-recovery-scanner.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

async function fixture(t) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-v2-scanner-build-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const crate = path.join(root, 'crates', 'shieldkit-v2-recovery');
  await mkdir(crate, { recursive: true });
  await writeFile(path.join(crate, 'Cargo.toml'), '[package]\nname = "shieldkit-v2-recovery"\n');
  const lock = Buffer.from('version = 4\n', 'utf8');
  await writeFile(path.join(crate, 'Cargo.lock'), lock);
  return { root, crate, lock };
}

function runnerFor({ crate, dirty = false, build = null, revision = 'a'.repeat(40) }) {
  const calls = [];
  return {
    calls,
    runner: async ({ command, args, cwd, env }) => {
      calls.push({ command, args: [...args], cwd, env });
      if (command === 'git' && args.join(' ') === 'rev-parse HEAD') return { code: 0, stdout: revision, stderr: '' };
      if (command === 'git' && args.join(' ') === 'status --porcelain=v1 -z') return { code: 0, stdout: dirty ? ' M file\0' : '', stderr: '' };
      if (command === 'rustc' && args.join(' ') === '--version') return { code: 0, stdout: 'rustc 1.97.1', stderr: '' };
      if (command === 'cargo' && args.join(' ') === '--version') return { code: 0, stdout: 'cargo 1.97.1', stderr: '' };
      if (command === 'cargo' && args.join(' ') === 'build --locked --release') {
        const target = env?.CARGO_TARGET_DIR;
        assert.equal(typeof target, 'string');
        assert.equal((await lstat(target)).mode & 0o777, 0o700);
        const release = path.join(target, 'release');
        await mkdir(path.join(release, 'deps'), { recursive: true });
        if (build) await build(crate, target);
        else {
          const binary = path.join(release, 'shieldkit-v2-recovery');
          await writeFile(binary, Buffer.from('#!/bin/sh\nexit 0\n'));
          await link(binary, path.join(release, 'deps', 'shieldkit-v2-recovery-abc123'));
        }
        const binary = path.join(release, 'shieldkit-v2-recovery');
        const metadata = await lstat(binary).catch(() => undefined);
        if (metadata?.isFile() && !metadata.isSymbolicLink()) {
          await chmod(binary, 0o755);
        }
        return { code: 0, stdout: '', stderr: '' };
      }
      throw new Error(`unexpected command ${command} ${args.join(' ')}`);
    },
  };
}

test('scanner builder runs exact locked release command and atomically publishes canonical local-only provenance', async (t) => {
  const subject = await fixture(t);
  const { calls, runner } = runnerFor(subject);
  const result = await buildV2RecoveryScannerForUnitTest({
    workspaceRoot: subject.root,
    output: 'published-scanner',
    allowDevelopmentOnly: false,
  }, runner);
  const binary = await readFile(path.join(result.output, 'shieldkit-v2-recovery-scanner'));
  const manifestPath = path.join(result.output, 'shieldkit-v2-recovery-scanner.manifest.json');
  const manifestBytes = await readFile(manifestPath);
  const manifest = JSON.parse(manifestBytes);
  const build = calls.find((entry) => entry.command === 'cargo' && entry.args[0] === 'build');
  assert.deepEqual({ command: build.command, args: build.args, cwd: build.cwd }, {
    command: 'cargo', args: ['build', '--locked', '--release'], cwd: subject.crate,
  });
  assert.match(build.env.CARGO_TARGET_DIR, new RegExp(`^${subject.root.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/\\.shieldkit-v2-recovery-target-`));
  await assert.rejects(lstat(build.env.CARGO_TARGET_DIR));
  const binaryMetadata = await lstat(
    path.join(result.output, 'shieldkit-v2-recovery-scanner'),
  );
  const manifestMetadata = await lstat(manifestPath);
  assert.equal(binaryMetadata.mode & 0o777, 0o755);
  assert.equal(binaryMetadata.nlink, 1);
  assert.equal(manifestMetadata.mode & 0o777, 0o600);
  assert.equal(manifestMetadata.nlink, 1);
  assert.deepEqual(
    (await readdir(subject.root)).filter(
      (entry) => entry.startsWith('.published-scanner.stage-'),
    ),
    [],
  );
  assert.equal(manifestBytes.toString('utf8'), canonicalizeJcs(manifest));
  assert.deepEqual(manifest, {
    schema: 'shieldkit-v2-recovery-scanner-artifact-v1',
    target: 'linux-x64',
    binaryArtifactId: 'recovery-scanner-linux-x64',
    binarySha256: sha256(binary),
    binaryBytes: binary.length,
    cargoLockSha256: sha256(subject.lock),
    cargoVersion: 'cargo 1.97.1',
    eligibility: 'clean-source-build',
    protocolSchemas: [
      'shieldkit-v2-recovery-authenticate-snapshot-stream-input-v2',
      'shieldkit-v2-recovery-authenticate-snapshot-v2',
      'shieldkit-v2-recovery-authenticated-material-v2',
      'shieldkit-v2-recovery-scan-result-v2',
      'shieldkit-v2-recovery-scan-v2',
      'shieldkit-v2-recovery-snapshot-v2',
      'shieldkit-v2-recovery-stream-input-v2',
      'shieldkit-v2-recovery-stream-output-v2',
      'shieldkit-v2-recovery-verify-v2',
    ],
    rustcVersion: 'rustc 1.97.1',
    sourceRevision: 'a'.repeat(40),
  });
});

test('scanner builder rejects dirty revisions without an explicit development-only record and records approved development dirt', async (t) => {
  const subject = await fixture(t);
  const first = runnerFor({ ...subject, dirty: true });
  await assert.rejects(
    buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'clean-only', allowDevelopmentOnly: false }, first.runner),
    V2RecoveryScannerBuildError,
  );
  assert.equal(first.calls.some((entry) => entry.command === 'cargo' && entry.args[0] === 'build'), false);
  const second = runnerFor({ ...subject, dirty: true });
  const result = await buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'development-only', allowDevelopmentOnly: true }, second.runner);
  const manifest = JSON.parse(await readFile(path.join(result.output, 'shieldkit-v2-recovery-scanner.manifest.json')));
  assert.equal(manifest.eligibility, 'dirty-source-development-only');
});

test('scanner builder rejects pre-existing publication, failed cargo, and symlinked build output', async (t) => {
  const subject = await fixture(t);
  await mkdir(path.join(subject.root, 'exists'));
  const existing = runnerFor(subject);
  await assert.rejects(
    buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'exists', allowDevelopmentOnly: false }, existing.runner),
    V2RecoveryScannerBuildError,
  );
  assert.equal(existing.calls.length, 0);
  const failed = runnerFor({
    ...subject,
    build: async () => {},
  });
  let failedTarget;
  const failingRunner = async (input) => {
    if (input.command === 'cargo' && input.args[0] === 'build') {
      failedTarget = input.env.CARGO_TARGET_DIR;
      return { code: 7, stdout: '', stderr: 'compiler failed' };
    }
    return await failed.runner(input);
  };
  await assert.rejects(
    buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'failed', allowDevelopmentOnly: false }, failingRunner),
    /exit 7: compiler failed/,
  );
  await assert.rejects(lstat(failedTarget));
  const linked = runnerFor({
    ...subject,
    build: async (_crate, target) => {
      const release = path.join(target, 'release');
      const source = path.join(release, 'scanner-real');
      await writeFile(source, 'scanner');
      await symlink(source, path.join(release, 'shieldkit-v2-recovery'));
    },
  });
  await assert.rejects(
    buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'linked', allowDevelopmentOnly: false }, linked.runner),
    /regular, non-symlink, 2-link/,
  );
});

test('scanner builder rejects missing, extra, outside, and symlinked Cargo hardlink topology', async (t) => {
  const cases = [
    {
      name: 'missing deps sibling',
      build: async (_crate, target) => {
        await writeFile(path.join(target, 'release', 'shieldkit-v2-recovery'), 'scanner');
      },
      pattern: /2-link/,
    },
    {
      name: 'extra deps sibling',
      build: async (_crate, target) => {
        const release = path.join(target, 'release');
        const binary = path.join(release, 'shieldkit-v2-recovery');
        await writeFile(binary, 'scanner');
        await link(binary, path.join(release, 'deps', 'scanner-a'));
        await link(binary, path.join(release, 'deps', 'scanner-b'));
      },
      pattern: /2-link/,
    },
    {
      name: 'outside sibling',
      build: async (crate, target) => {
        const binary = path.join(target, 'release', 'shieldkit-v2-recovery');
        await writeFile(binary, 'scanner');
        await link(binary, path.join(crate, 'outside-hardlink'));
      },
      pattern: /same-inode release\/deps sibling/,
    },
    {
      name: 'symlinked deps sibling',
      build: async (crate, target) => {
        const release = path.join(target, 'release');
        const binary = path.join(release, 'shieldkit-v2-recovery');
        const outside = path.join(crate, 'outside-hardlink');
        await writeFile(binary, 'scanner');
        await link(binary, outside);
        await symlink(outside, path.join(release, 'deps', 'scanner-link'));
      },
      pattern: /same-inode release\/deps sibling/,
    },
  ];
  for (const scenario of cases) await t.test(scenario.name, async (inner) => {
    const subject = await fixture(inner);
    const { runner } = runnerFor({ ...subject, build: scenario.build });
    await assert.rejects(
      buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: scenario.name.replaceAll(' ', '-'), allowDevelopmentOnly: false }, runner),
      scenario.pattern,
    );
    const leftovers = (await readdir(subject.root))
      .filter((entry) => entry.startsWith('.shieldkit-v2-recovery-target-'));
    assert.deepEqual(leftovers, []);
  });
});

test('scanner builder rejects source, lockfile, and toolchain drift across compilation', async (t) => {
  await t.test('Cargo.lock drift', async (inner) => {
    const subject = await fixture(inner);
    const { runner } = runnerFor({
      ...subject,
      build: async (_crate, target) => {
        const release = path.join(target, 'release');
        const binary = path.join(release, 'shieldkit-v2-recovery');
        await writeFile(binary, 'scanner');
        await link(binary, path.join(release, 'deps', 'scanner'));
        await writeFile(
          path.join(subject.crate, 'Cargo.lock'),
          'version = 4\n# changed during build\n',
        );
      },
    });
    await assert.rejects(
      buildV2RecoveryScannerForUnitTest({
        workspaceRoot: subject.root,
        output: 'lock-drift',
        allowDevelopmentOnly: false,
      }, runner),
      /changed during the build/,
    );
    await assert.rejects(lstat(path.join(subject.root, 'lock-drift')));
  });

  await t.test('rustc version drift', async (inner) => {
    const subject = await fixture(inner);
    const baseRunner = runnerFor(subject);
    let rustcCalls = 0;
    const runner = async (input) => {
      if (input.command === 'rustc' && input.args.join(' ') === '--version') {
        rustcCalls += 1;
        return {
          code: 0,
          stdout: rustcCalls === 1 ? 'rustc 1.97.1' : 'rustc 1.97.2',
          stderr: '',
        };
      }
      return await baseRunner.runner(input);
    };
    await assert.rejects(
      buildV2RecoveryScannerForUnitTest({
        workspaceRoot: subject.root,
        output: 'toolchain-drift',
        allowDevelopmentOnly: false,
      }, runner),
      /changed during the build/,
    );
    await assert.rejects(lstat(path.join(subject.root, 'toolchain-drift')));
  });
});

test('argument parser accepts only the exact output/development-only surface', () => {
  assert.deepEqual(
    parseV2RecoveryScannerBuildArguments(['--output', 'artifact', '--development-only'], '/tmp/scanner'),
    { workspaceRoot: '/tmp/scanner', output: 'artifact', allowDevelopmentOnly: true },
  );
  for (const argv of [[], ['--development-only'], ['--output', 'x', '--unknown'], ['--output', '-x'], ['--output', 'x', '--development-only', 'extra']]) {
    assert.throws(() => parseV2RecoveryScannerBuildArguments(argv), V2RecoveryScannerBuildError);
  }
});

test('scanner builder requires a nonzero exact 40- or 64-character lowercase Git revision', async (t) => {
  for (const revision of ['a'.repeat(41), '0'.repeat(40), 'A'.repeat(40), 'a'.repeat(39)]) {
    const subject = await fixture(t);
    const { runner, calls } = runnerFor({ ...subject, revision });
    await assert.rejects(
      buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'rejected', allowDevelopmentOnly: false }, runner),
      /nonzero 40- or 64-character lowercase revision/,
    );
    assert.equal(calls.some((entry) => entry.command === 'cargo' && entry.args[0] === 'build'), false);
  }
  const subject = await fixture(t);
  const { runner } = runnerFor({ ...subject, revision: 'b'.repeat(64) });
  const result = await buildV2RecoveryScannerForUnitTest({ workspaceRoot: subject.root, output: 'sha256-revision', allowDevelopmentOnly: false }, runner);
  const manifest = JSON.parse(await readFile(path.join(result.output, 'shieldkit-v2-recovery-scanner.manifest.json')));
  assert.equal(manifest.sourceRevision, 'b'.repeat(64));
});

test('scanner builder rejects a symlinked workspace root', async (t) => {
  const subject = await fixture(t);
  const alias = `${subject.root}-alias`;
  await symlink(subject.root, alias);
  t.after(() => rm(alias, { force: true }));
  const { runner, calls } = runnerFor(subject);
  await assert.rejects(
    buildV2RecoveryScannerForUnitTest({
      workspaceRoot: alias,
      output: 'rejected',
      allowDevelopmentOnly: false,
    }, runner),
    /canonical real directory/,
  );
  assert.equal(calls.length, 0);
});
