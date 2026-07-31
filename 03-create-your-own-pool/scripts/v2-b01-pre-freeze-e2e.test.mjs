/*
 * Heavyweight, real-artifact B-01 integration qualification.
 *
 * This test intentionally runs only in the mandatory local verifier lane. It
 * creates a detached clean local clone at exact HEAD, performs the immutable
 * install/toolchain setup there, copies the already-qualified development
 * runtime into private single-link files, generates public Q-01-pre evidence,
 * and exercises only the public B-01 create and verify CLIs. Every mutation is
 * confined to the disposable worktree/evidence root.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { availableParallelism, tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';

const REPOSITORY = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
);
const GIT = '/usr/bin/git';
const NPM = join(dirname(process.execPath), 'npm');
const COMMAND_TIMEOUT_MS = 1_800_000;
const TEST_TIMEOUT_MS = 7_000_000;
const PARALLELISM = availableParallelism();
const ARTIFACT_DIRECTORIES = Object.freeze([
  'v2-circuit-model',
  'v2-dev-groth16',
  'v2-dev-ptau',
  'v2-development-profile',
  'v2-pf10-libauth-qualification',
  'v2-pf10-development-runtime',
]);
const CREATE_STATUS = 'b01-pre-freeze-candidate-awaiting-independent-review';
const VERIFY_STATUS = 'verified-b01-pre-freeze-candidate-awaiting-independent-review';

function cleanEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    const normalizedKey = key.toLowerCase();
    if (
      value === undefined
      || key === 'NODE_OPTIONS'
      || key === 'NODE_PATH'
      || key === 'NODE_V8_COVERAGE'
      || key.startsWith('LD_')
      || key.startsWith('DYLD_')
      || key.startsWith('GIT_')
      || normalizedKey.startsWith('npm_config_')
      || normalizedKey.startsWith('yarn_')
      || normalizedKey.startsWith('pnpm_')
      || normalizedKey.startsWith('corepack_')
      || key === 'RUSTC_WRAPPER'
      || key === 'RUSTC_WORKSPACE_WRAPPER'
      || key === 'RUSTFLAGS'
      || key === 'CARGO_ENCODED_RUSTFLAGS'
      || key === 'SHIELDKIT_SKIP_UNLOCK_SETUP'
      || key === 'XDG_CACHE_HOME'
      || key === 'XDG_CONFIG_HOME'
    ) continue;
    environment[key] = value;
  }
  return Object.freeze({
    ...environment,
    CARGO_BUILD_JOBS: String(PARALLELISM),
    GIT_CONFIG_COUNT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    LANG: 'C',
    LC_ALL: 'C',
    MAKEFLAGS: `-j${PARALLELISM}`,
    TZ: 'UTC',
    UV_THREADPOOL_SIZE: String(PARALLELISM),
  });
}

const ENVIRONMENT = cleanEnvironment();

function commandResult(executable, arguments_, {
  cwd,
  environment = ENVIRONMENT,
  timeout = COMMAND_TIMEOUT_MS,
} = {}) {
  return spawnSync(executable, arguments_, {
    cwd,
    env: environment,
    encoding: 'utf8',
    maxBuffer: 128 * 1024 * 1024,
    timeout,
    killSignal: 'SIGKILL',
  });
}

function diagnostic(result) {
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  return JSON.stringify({
    error: result.error?.message,
    signal: result.signal,
    status: result.status,
    stderr: stderr.slice(-8_000),
    stdout: stdout.slice(-8_000),
  });
}

function requireSuccess(result, label) {
  assert.equal(result.error, undefined, `${label}: ${diagnostic(result)}`);
  assert.equal(result.signal, null, `${label}: ${diagnostic(result)}`);
  assert.equal(result.status, 0, `${label}: ${diagnostic(result)}`);
  return result;
}

function requireRejection(result, expression, label) {
  assert.equal(result.error, undefined, `${label}: ${diagnostic(result)}`);
  assert.equal(result.signal, null, `${label}: ${diagnostic(result)}`);
  assert.notEqual(result.status, 0, `${label} unexpectedly succeeded`);
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  assert.match(output, expression, `${label}: ${diagnostic(result)}`);
  assert.doesNotMatch(result.stdout ?? '', new RegExp(VERIFY_STATUS, 'u'));
}

function parseLastJson(result, label) {
  const lines = (result.stdout ?? '')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.startsWith('{') && line.endsWith('}'));
  assert.notEqual(lines.length, 0, `${label} emitted no JSON: ${diagnostic(result)}`);
  try {
    return JSON.parse(lines.at(-1));
  } catch (error) {
    assert.fail(`${label} emitted invalid final JSON: ${error.message}`);
  }
}

function runGit(repository, arguments_, label, { timeout = 120_000 } = {}) {
  return requireSuccess(commandResult(GIT, [
    '--no-replace-objects',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    '-c', 'include.path=/dev/null',
    '-C', repository,
    ...arguments_,
  ], { cwd: repository, timeout }), label);
}

function gitText(repository, arguments_, label) {
  return runGit(repository, arguments_, label).stdout.trim();
}

function assertPrivatePath(filename, { directory }) {
  const metadata = lstatSync(filename);
  assert.equal(metadata.isSymbolicLink(), false, filename);
  assert.equal(directory ? metadata.isDirectory() : metadata.isFile(), true, filename);
  assert.equal(metadata.mode & 0o777, directory ? 0o700 : 0o600, filename);
  if (!directory) assert.equal(metadata.nlink, 1, filename);
  if (typeof process.getuid === 'function') {
    assert.equal(metadata.uid, process.getuid(), filename);
  }
  assert.equal(realpathSync(filename), filename, filename);
}

function makePrivateDirectory(filename) {
  mkdirSync(filename, { mode: 0o700 });
  chmodSync(filename, 0o700);
  assertPrivatePath(filename, { directory: true });
}

function npmEnvironment(temporaryRoot) {
  const stateRoot = join(temporaryRoot, 'package-manager-state');
  const npmCache = join(stateRoot, 'npm-cache');
  const yarnCache = join(stateRoot, 'yarn-cache');
  const yarnGlobal = join(stateRoot, 'yarn-global');
  const pnpmStore = join(stateRoot, 'pnpm-store');
  const xdgCache = join(stateRoot, 'xdg-cache');
  const xdgConfig = join(stateRoot, 'xdg-config');
  const npmGlobalConfig = join(stateRoot, 'npm-global-config');
  const npmUserConfig = join(stateRoot, 'npm-user-config');
  makePrivateDirectory(stateRoot);
  for (const directory of [
    npmCache,
    yarnCache,
    yarnGlobal,
    pnpmStore,
    xdgCache,
    xdgConfig,
  ]) makePrivateDirectory(directory);
  writePrivate(npmGlobalConfig, Buffer.alloc(0));
  writePrivate(npmUserConfig, Buffer.alloc(0));
  return Object.freeze({
    ...ENVIRONMENT,
    PATH: `${dirname(process.execPath)}:/usr/bin:/bin`,
    NPM_CONFIG_AUDIT: 'false',
    NPM_CONFIG_CACHE: npmCache,
    NPM_CONFIG_FUND: 'false',
    NPM_CONFIG_GLOBALCONFIG: npmGlobalConfig,
    NPM_CONFIG_IGNORE_SCRIPTS: 'false',
    NPM_CONFIG_PROVENANCE: 'false',
    NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org/',
    NPM_CONFIG_UPDATE_NOTIFIER: 'false',
    NPM_CONFIG_USERCONFIG: npmUserConfig,
    YARN_CACHE_FOLDER: yarnCache,
    YARN_DISABLE_SELF_UPDATE_CHECK: '1',
    YARN_GLOBAL_FOLDER: yarnGlobal,
    YARN_IGNORE_PATH: '1',
    XDG_CACHE_HOME: xdgCache,
    XDG_CONFIG_HOME: xdgConfig,
    npm_config_jobs: String(PARALLELISM),
    npm_config_store_dir: pnpmStore,
  });
}

function copyPrivateTree(source, destination) {
  const sourceMetadata = lstatSync(source);
  assert.equal(sourceMetadata.isDirectory(), true, source);
  assert.equal(sourceMetadata.isSymbolicLink(), false, source);
  assert.equal(realpathSync(source), source, source);
  makePrivateDirectory(destination);
  for (const entry of readdirSync(source, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, 'en'))) {
    const from = join(source, entry.name);
    const to = join(destination, entry.name);
    if (entry.isDirectory()) {
      copyPrivateTree(from, to);
    } else if (entry.isFile()) {
      const fileMetadata = lstatSync(from);
      assert.equal(fileMetadata.isSymbolicLink(), false, from);
      assert.equal(fileMetadata.nlink, 1, from);
      copyFileSync(from, to, constants.COPYFILE_FICLONE);
      chmodSync(to, 0o600);
      assertPrivatePath(to, { directory: false });
    } else {
      assert.fail(`unsupported artifact entry: ${from}`);
    }
  }
}

function writePrivate(filename, bytes) {
  writeDirectFile(filename, bytes, 0o600);
}

function writeDirectFile(filename, bytes, mode) {
  writeFileSync(filename, bytes, { mode });
  chmodSync(filename, mode);
  const metadata = lstatSync(filename);
  assert.equal(metadata.isFile(), true, filename);
  assert.equal(metadata.isSymbolicLink(), false, filename);
  assert.equal(metadata.nlink, 1, filename);
  assert.equal(metadata.mode & 0o777, mode, filename);
  assert.equal(realpathSync(filename), filename, filename);
}

function withChangedFile(filename, replacement, action) {
  const original = readFileSync(filename);
  const originalMode = lstatSync(filename).mode & 0o777;
  const changed = replacement(Buffer.from(original));
  assert.equal(Buffer.isBuffer(changed), true);
  assert.equal(changed.equals(original), false, `mutation did not change ${filename}`);
  try {
    writeDirectFile(filename, changed, originalMode);
    action();
  } finally {
    writeDirectFile(filename, original, originalMode);
    assert.equal(readFileSync(filename).equals(original), true, filename);
  }
}

function flipFirstByte(bytes) {
  assert.notEqual(bytes.length, 0);
  bytes[0] ^= 0x01;
  return bytes;
}

function nodeCommand(checkout, relativeScript, arguments_) {
  return commandResult(process.execPath, [join(checkout, relativeScript), ...arguments_], {
    cwd: checkout,
  });
}

function verifyCommand(checkout, bundle) {
  return nodeCommand(
    checkout,
    '03-create-your-own-pool/scripts/v2-b01-pre-freeze.mjs',
    ['--verify', bundle],
  );
}

function assertBoundaryClaims(value, expectedStatus) {
  assert.equal(value.status, expectedStatus);
  if (expectedStatus === VERIFY_STATUS) {
    assert.equal(value.b01PreFreezeCandidate, true);
    assert.equal(value.reviewed, false);
    assert.equal(value.ceremonyAuthorized, false);
    assert.equal(value.production, false);
    assert.equal(value.releaseQualified, false);
  }
}

function removeDisposableClone(checkout, temporaryRoot) {
  assert.equal(
    resolve(dirname(temporaryRoot)),
    realpathSync(tmpdir()),
    'B-01 disposable root escaped the process temporary directory',
  );
  assert.match(basename(temporaryRoot), /^shieldkit-b01-e2e-[A-Za-z0-9_-]+$/u);
  assert.equal(resolve(checkout), join(temporaryRoot, 'checkout'));
  rmSync(temporaryRoot, { recursive: true, force: true });
}

test('B-01 real-artifact clean-clone create, verify, and tamper closure', {
  timeout: TEST_TIMEOUT_MS,
}, async (t) => {
  assert.equal(Number.isSafeInteger(PARALLELISM) && PARALLELISM > 0, true);
  t.diagnostic(`B-01 heavy-job parallelism: ${PARALLELISM} cores`);
  assert.equal(existsSync(GIT), true, GIT);
  assert.equal(existsSync(NPM), true, NPM);
  const sourceArtifacts = join(REPOSITORY, '.codex-build');
  for (const directory of ARTIFACT_DIRECTORIES) {
    assertPrivatePath(join(sourceArtifacts, directory), { directory: true });
  }

  const temporaryRoot = mkdtempSync(join(tmpdir(), 'shieldkit-b01-e2e-'));
  chmodSync(temporaryRoot, 0o700);
  assertPrivatePath(temporaryRoot, { directory: true });
  const checkout = join(temporaryRoot, 'checkout');
  const evidence = join(temporaryRoot, 'evidence');
  const installEnvironment = npmEnvironment(temporaryRoot);
  t.after(() => removeDisposableClone(checkout, temporaryRoot));

  const commit = gitText(REPOSITORY, ['rev-parse', 'HEAD^{commit}'], 'read exact HEAD');
  assert.match(commit, /^[0-9a-f]{40}$/u);
  requireSuccess(commandResult(GIT, [
    '--no-replace-objects',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.hooksPath=/dev/null',
    '-c', 'core.pager=cat',
    '-c', 'include.path=/dev/null',
    'clone', '--local', '--no-hardlinks', '--no-checkout',
    REPOSITORY, checkout,
  ], { cwd: REPOSITORY, timeout: 300_000 }), 'create isolated B-01 source clone');
  runGit(checkout, ['checkout', '--detach', commit], 'detach B-01 source clone');

  requireSuccess(commandResult(NPM, [
    `--userconfig=${installEnvironment.NPM_CONFIG_USERCONFIG}`,
    `--globalconfig=${installEnvironment.NPM_CONFIG_GLOBALCONFIG}`,
    `--cache=${installEnvironment.NPM_CONFIG_CACHE}`,
    'ci', '--include-workspace-root', '--ignore-scripts=false',
    '--no-audit', '--no-fund',
  ], {
    cwd: checkout,
    environment: installEnvironment,
    timeout: 600_000,
  }), 'immutable child-clone npm ci');
  requireSuccess(commandResult(NPM, [
    `--userconfig=${installEnvironment.NPM_CONFIG_USERCONFIG}`,
    `--globalconfig=${installEnvironment.NPM_CONFIG_GLOBALCONFIG}`,
    `--cache=${installEnvironment.NPM_CONFIG_CACHE}`,
    'run', 'unlock-builder:setup',
  ], {
    cwd: checkout,
    environment: installEnvironment,
    timeout: 600_000,
  }), 'materialize child-clone verifier toolchain');

  const childArtifacts = join(checkout, '.codex-build');
  makePrivateDirectory(childArtifacts);
  for (const directory of ARTIFACT_DIRECTORIES) {
    copyPrivateTree(
      join(sourceArtifacts, directory),
      join(childArtifacts, directory),
    );
  }
  assert.equal(
    gitText(checkout, ['status', '--porcelain=v1', '--untracked-files=all'], 'assert clean child worktree'),
    '',
  );
  const tree = gitText(checkout, ['rev-parse', 'HEAD^{tree}'], 'read exact child tree');
  assert.match(tree, /^[0-9a-f]{40}$/u);

  makePrivateDirectory(evidence);
  const q01Parent = join(evidence, 'q01');
  makePrivateDirectory(q01Parent);
  const q01Result = requireSuccess(nodeCommand(
    checkout,
    '03-create-your-own-pool/scripts/v2-q01-commit-bound-evidence.mjs',
    ['--output-directory', q01Parent],
  ), 'public Q-01-pre generation');
  const q01 = parseLastJson(q01Result, 'public Q-01-pre generation');
  assert.equal(q01.status, 'verified-local-pre-ceremony-four-implementation-conformance');
  assert.equal(q01.gitCommit, commit);
  assert.equal(q01.gitTree, tree);
  assert.equal(q01.executed, true);
  assert.equal(q01.finalArtifacts, false);
  assert.equal(q01.finalQualification, false);
  assertPrivatePath(q01.bundlePath, { directory: true });

  const b01Bundle = join(evidence, 'b01');
  const runtime = join(childArtifacts, 'v2-pf10-development-runtime');
  const createResult = requireSuccess(nodeCommand(
    checkout,
    '03-create-your-own-pool/scripts/v2-b01-pre-freeze.mjs',
    [
      '--runtime-bundle', runtime,
      '--q01-pre-bundle', q01.bundlePath,
      '--expected-commit', commit,
      '--expected-tree', tree,
      '--output-dir', b01Bundle,
    ],
  ), 'public B-01 creation');
  assertBoundaryClaims(parseLastJson(createResult, 'public B-01 creation'), CREATE_STATUS);
  assertPrivatePath(b01Bundle, { directory: true });
  assertPrivatePath(join(b01Bundle, 'manifest.json'), { directory: false });

  const baselineVerify = requireSuccess(
    verifyCommand(checkout, b01Bundle),
    'independent public B-01 verification',
  );
  assertBoundaryClaims(
    parseLastJson(baselineVerify, 'independent public B-01 verification'),
    VERIFY_STATUS,
  );

  await t.test('rejects a resealed B-01 production-claim overstatement', () => {
    const manifestPath = join(b01Bundle, 'manifest.json');
    withChangedFile(manifestPath, (bytes) => {
      const value = JSON.parse(bytes.toString('utf8'));
      value.reviewed = true;
      return Buffer.from(canonicalJson(value), 'utf8');
    }, () => requireRejection(
      verifyCommand(checkout, b01Bundle),
      /freeze manifest claim boundary is invalid/u,
      'B-01 claim overstatement',
    ));
  });

  await t.test('rejects a changed runtime artifact', () => {
    withChangedFile(
      join(runtime, 'runtime', 'executor-body.bin'),
      flipFirstByte,
      () => requireRejection(
        verifyCommand(checkout, b01Bundle),
        /runtime artifact\[[0-9]+\] differs from the runtime artifact manifest/u,
        'B-01 runtime artifact mutation',
      ),
    );
  });

  await t.test('rejects changed Libauth support evidence', () => {
    withChangedFile(
      join(childArtifacts, 'v2-pf10-libauth-qualification', 'libauth.json'),
      flipFirstByte,
      () => requireRejection(
        verifyCommand(checkout, b01Bundle),
        /Libauth publication file libauth\.json differs from its completion record/u,
        'B-01 Libauth support mutation',
      ),
    );
  });

  await t.test('rejects changed development-profile support evidence', () => {
    withChangedFile(
      join(childArtifacts, 'v2-development-profile', 'profile-package.json'),
      flipFirstByte,
      () => requireRejection(
        verifyCommand(checkout, b01Bundle),
        /bundled development profile is invalid/u,
        'B-01 development-profile support mutation',
      ),
    );
  });

  await t.test('rejects a changed profile-bound proof artifact', () => {
    withChangedFile(
      join(childArtifacts, 'v2-circuit-model', 'main-chipnet.r1cs'),
      flipFirstByte,
      () => requireRejection(
        verifyCommand(checkout, b01Bundle),
        /proof artifact r1cs differs from its package record/u,
        'B-01 profile-bound R1CS mutation',
      ),
    );
  });

  await t.test('rejects changed sealed Q-01 evidence', () => {
    withChangedFile(
      join(q01.bundlePath, 'qualification.json'),
      flipFirstByte,
      () => requireRejection(
        verifyCommand(checkout, b01Bundle),
        /artifact qualification hash differs/u,
        'B-01 Q-01 evidence mutation',
      ),
    );
  });

  await t.test('rejects a changed tracked source file', () => {
    const tracked = join(
      checkout,
      '03-create-your-own-pool/packages/action/v2/packet.mjs',
    );
    withChangedFile(tracked, (bytes) => Buffer.concat([
      bytes,
      Buffer.from('\n', 'utf8'),
    ]), () => {
      assert.match(
        gitText(checkout, ['status', '--porcelain=v1', '--untracked-files=all'], 'observe tracked source mutation'),
        /packet\.mjs/u,
      );
      requireRejection(
        verifyCommand(checkout, b01Bundle),
        /source checkout must be clean/u,
        'B-01 tracked source mutation',
      );
    });
  });

  await t.test('rejects an untracked source file', () => {
    const probe = join(checkout, 'B01_SOURCE_TAMPER_PROBE.txt');
    try {
      writePrivate(probe, Buffer.from('B-01 source-state probe\n', 'utf8'));
      assert.match(
        gitText(checkout, ['status', '--porcelain=v1', '--untracked-files=all'], 'observe untracked source mutation'),
        /B01_SOURCE_TAMPER_PROBE\.txt/u,
      );
      requireRejection(
        verifyCommand(checkout, b01Bundle),
        /source checkout must be clean/u,
        'B-01 untracked source mutation',
      );
    } finally {
      if (existsSync(probe)) unlinkSync(probe);
    }
  });

  assert.equal(
    gitText(checkout, ['status', '--porcelain=v1', '--untracked-files=all'], 'assert restored child worktree'),
    '',
  );
  const restoredVerify = requireSuccess(
    verifyCommand(checkout, b01Bundle),
    'restored public B-01 verification',
  );
  assertBoundaryClaims(
    parseLastJson(restoredVerify, 'restored public B-01 verification'),
    VERIFY_STATUS,
  );
});
