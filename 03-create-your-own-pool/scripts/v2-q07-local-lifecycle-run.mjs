#!/usr/bin/env node

/*
 * Local-only Q07 lifecycle evidence. This deliberately produces a sealed
 * replay bundle, not chain evidence or a published-machine qualification.
 */
import { createHash, randomBytes } from 'node:crypto';
import {
  chmodSync, closeSync, constants, createReadStream, existsSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, readSync, realpathSync, renameSync,
  unlinkSync, writeSync,
} from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import os from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';
import { decodeStateNftCommitment } from '../packages/action/v2/state.mjs';

export const V2_Q07_LOCAL_LIFECYCLE_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-run/v1';
export const V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-bundle/v1';
export const V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-run/v2';
export const V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-bundle/v2';
export const V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS = 100_000;
const Q07_RUST_TOOLCHAIN = '1.97.1';
const Q07_DENOMINATION_SATS = '10000000';
const Q07_CORPUS_FILENAME = 'q07-non-chain-lifecycle.ndjson';
const RESUME_PREFIX = 'resume-v2-';
const RESUME_LEASE_FILENAME = '.q07-resume-v2.lease';
const RESUME_ID = /^[1-9][0-9]*-[0-9a-f]{32}$/u;
const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
export const V2_Q07_PRESERVED_ORIGIN_PINS = Object.freeze({
  corpus: Object.freeze({
    sha256: 'aa39af48d1690aa9e45885e52816b11b95ff08820dbe26625eac215777819fde',
    bytes: '670291065',
    lines: '100002',
  }),
  source: Object.freeze({
    sourceSetArtifactSha256: '70c2db593c0a46c56a6ec1181900840f25503f251f330a3b86910ac92a254cc8',
    sourceSetSha256: 'd73b81c7769da928712ec721a90e085d602e171bce8fe427599c0894be4ad895',
    gitCommit: '18ff9bc90f4ecac4b44e1f0c359c338be0029dac',
    gitTree: '383fd2b65fbd3f4b8ff5a4d4ec20a7e854e7770d',
  }),
});
const fail = (message) => { throw new V2Q07LocalLifecycleError(message); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const own = (path, label) => {
  const s = lstatSync(path);
  if (s.isSymbolicLink() || !s.isFile() || s.nlink !== 1 || (s.mode & 0o777) !== 0o600 || (typeof process.getuid === 'function' && s.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0600 single-link file`);
  return s;
};
const directDirectory = (path, label, create = false) => {
  if (!isAbsolute(path) || resolve(path) !== path) fail(`${label} must be an absolute normalized path`);
  if (create) mkdirSync(path, { mode: 0o700 });
  const s = lstatSync(path);
  if (s.isSymbolicLink() || !s.isDirectory() || (s.mode & 0o777) !== 0o700 || (typeof process.getuid === 'function' && s.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned mode-0700 directory`);
  return s;
};
const directChild = (root, name, label) => {
  if (typeof name !== 'string' || name.length === 0 || basename(name) !== name) fail(`${label} must be one direct filename`);
  const out = join(root, name); if (dirname(out) !== root) fail(`${label} escapes its bundle`); return out;
};
function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail(`${label} has missing or unknown fields`);
  return value;
}
function writeFully(fd, bytes) { for (let offset = 0; offset < bytes.length;) { const count = writeSync(fd, bytes, offset, bytes.length - offset); if (count <= 0) fail('atomic write made no progress'); offset += count; } }
function atomic(root, name, bytes) {
  const path = directChild(root, name, 'artifact'); if (existsSync(path)) fail(`refusing to overwrite ${path}`);
  const temporary = directChild(root, `.${name}.${process.pid}.${Date.now()}.tmp`, 'temporary artifact'); let fd;
  try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); chmodSync(temporary, 0o600); writeFully(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; own(temporary, 'temporary artifact'); if (existsSync(path)) fail(`refusing to overwrite ${path}`); renameSync(temporary, path); own(path, 'artifact'); fsyncDirectory(root); return Object.freeze({ path: name, bytes: bytes.length, sha256: sha256(bytes) }); }
  finally { if (fd !== undefined) closeSync(fd); if (existsSync(temporary)) unlinkSync(temporary); }
}
function fsyncDirectory(path) { const fd = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | (constants.O_NOFOLLOW ?? 0)); try { fsyncSync(fd); } finally { closeSync(fd); } }
function json(bytes, label) { let parsed; try { parsed = parseStrictJson(bytes); } catch (error) { fail(`${label} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); } if (canonicalJson(parsed) !== new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)) fail(`${label} is not canonical JSON`); return parsed; }
function commandJson(bytes, label) { try { return parseStrictJson(bytes); } catch (error) { fail(`${label} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`); } }
function run(command, args, { stdinPath = undefined, cwd, env = undefined }) { return new Promise((resolveRun, rejectRun) => { const child = spawn(command, args, { cwd, env, stdio: [stdinPath ? 'pipe' : 'ignore', 'pipe', 'pipe'] }); const output = []; const errors = []; child.stdout.on('data', (part) => output.push(part)); child.stderr.on('data', (part) => errors.push(part)); child.on('error', rejectRun); if (stdinPath) { const input = createReadStream(stdinPath); input.on('error', rejectRun); input.pipe(child.stdin); } child.on('close', (code, signal) => { const stdout = Buffer.concat(output); const stderr = Buffer.concat(errors).toString('utf8'); if (code !== 0) rejectRun(new V2Q07LocalLifecycleError(`${command} failed (${signal ?? code}): ${stderr.trim()}`)); else resolveRun(stdout); }); }); }
function commandText(command, args) { return Object.freeze({ command, args: Object.freeze([...args]) }); }
const pause = (ms) => new Promise((resolvePause) => setTimeout(resolvePause, ms));
function privateEmpty(root, name) { const path = directChild(root, name, 'private child'); const fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); try { fsyncSync(fd); } finally { closeSync(fd); } chmodSync(path, 0o600); own(path, 'private child'); return path; }
function cgroupV2() {
  const membership = '/proc/self/cgroup'; const root = '/sys/fs/cgroup';
  try { const line = readFileSync(membership, 'utf8').split('\n').find((v) => v.startsWith('0::')); if (!line) return Object.freeze({ available: false, reason: 'no unified cgroup-v2 membership' }); const suffix = line.slice(3); const directory = resolve(root, `.${suffix}`); if (!directory.startsWith(`${root}/`) && directory !== root) return Object.freeze({ available: false, reason: 'invalid cgroup-v2 path' }); const numeric = (name) => { try { const raw = readFileSync(join(directory, name), 'utf8').trim(); return /^(max|[0-9]+)$/u.test(raw) ? raw : null; } catch { return null; } }; return Object.freeze({ available: true, directory, memoryCurrentBytes: numeric('memory.current'), memoryPeakBytes: numeric('memory.peak'), memoryMaxBytes: numeric('memory.max') }); }
  catch { return Object.freeze({ available: false, reason: 'cgroup-v2 inspection unavailable' }); }
}
function measure(memory, fn) { return (async () => { const before = cgroupV2(); const started = performance.now(); const bytes = await fn(); const elapsed = performance.now() - started; const after = cgroupV2(); return Object.freeze({ bytes, wallMs: elapsed, cgroupV2: Object.freeze({ before, after, scope: 'runner-cgroup-observation-not-child-private-peak' }) }); })(); }
function git(root, args) { return new Promise((resolveGit, rejectGit) => { const child = spawn('git', args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] }); const out = []; const err = []; child.stdout.on('data', (v) => out.push(v)); child.stderr.on('data', (v) => err.push(v)); child.on('error', rejectGit); child.on('close', (code) => code === 0 ? resolveGit(Buffer.concat(out)) : rejectGit(new V2Q07LocalLifecycleError(`git ${args.join(' ')} failed: ${Buffer.concat(err).toString('utf8').trim()}`))); }); }
async function sourceSnapshot(sourceRoot) {
  const root = resolve(sourceRoot); if (!isAbsolute(root) || realpathSync(root) !== root) fail('sourceRoot must be a direct absolute checkout path');
  const top = (await git(root, ['rev-parse', '--show-toplevel'])).toString('utf8').trim(); if (top !== root) fail('sourceRoot must be the exact Git checkout root');
  const dirty = (await git(root, ['status', '--porcelain=v1', '--untracked-files=all'])).toString('utf8'); if (dirty !== '') fail('real local lifecycle runs require an exact clean committed source checkout');
  const commit = (await git(root, ['rev-parse', 'HEAD'])).toString('utf8').trim(); const tree = (await git(root, ['rev-parse', 'HEAD^{tree}'])).toString('utf8').trim(); if (!GIT.test(commit) || !GIT.test(tree)) fail('Git commit/tree identity is invalid');
  const names = (await git(root, ['ls-files', '-z'])).toString('utf8').split('\0').filter(Boolean); if (names.length === 0) fail('source checkout has no tracked source files');
  const files = names.map((path) => { if (path.includes('..') || path.startsWith('/')) fail('tracked source path is unsafe'); const absolute = resolve(root, path); if (!absolute.startsWith(`${root}/`)) fail('tracked source path escapes root'); const s = lstatSync(absolute); if (s.isSymbolicLink() || !s.isFile() || s.nlink !== 1) fail(`tracked source path is not a direct single-link file: ${path}`); return Object.freeze({ path, bytes: s.size, sha256: sha256(readFileSync(absolute)) }); });
  const locks = files.filter((entry) => /(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|Cargo\.lock)$/u.test(entry.path)); if (locks.length === 0) fail('source set must bind package/Cargo lock files');
  return Object.freeze({ schema: `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/source-set`, sourceRoot: root, gitCommit: commit, gitTree: tree, files, locks, sourceSetSha256: sha256(Buffer.from(canonicalJson(files), 'utf8')) });
}
async function recheckSource(source) { const dirty = (await git(source.sourceRoot, ['status', '--porcelain=v1', '--untracked-files=all'])).toString('utf8'); const commit = (await git(source.sourceRoot, ['rev-parse', 'HEAD'])).toString('utf8').trim(); const tree = (await git(source.sourceRoot, ['rev-parse', 'HEAD^{tree}'])).toString('utf8').trim(); if (dirty !== '' || commit !== source.gitCommit || tree !== source.gitTree) fail('source checkout changed during local lifecycle run'); }
function pinnedRustEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^(?:CARGO_TARGET_DIR|CARGO_ENCODED_RUSTFLAGS|MISE_RUST_VERSION|RUSTC|RUSTFLAGS|RUSTUP_TOOLCHAIN|RUSTDOCFLAGS|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER)$/u.test(key)) continue;
    if (/^npm_config_/iu.test(key)) continue;
    environment[key] = value;
  }
  return Object.freeze({ ...environment, MISE_RUST_VERSION: Q07_RUST_TOOLCHAIN, RUSTUP_TOOLCHAIN: Q07_RUST_TOOLCHAIN });
}
async function toolVersions(sourceRoot) {
  const env = pinnedRustEnvironment();
  const cargo = (await run('cargo', [`+${Q07_RUST_TOOLCHAIN}`, '--version'], { cwd: sourceRoot, env })).toString('utf8').trim();
  const rustc = (await run('rustc', [`+${Q07_RUST_TOOLCHAIN}`, '--version'], { cwd: sourceRoot, env })).toString('utf8').trim();
  if (!cargo.startsWith(`cargo ${Q07_RUST_TOOLCHAIN} `) || !rustc.startsWith(`rustc ${Q07_RUST_TOOLCHAIN} `)) fail(`pinned Rust ${Q07_RUST_TOOLCHAIN} toolchain identity differs`);
  return Object.freeze({ cargo, rustc });
}
async function exactPinnedResumeToolchain(sourceRoot) {
  const env = pinnedRustEnvironment();
  const capture = async (name) => {
    const selected = (await run('rustup', ['which', name], { cwd: sourceRoot, env })).toString('utf8').trim();
    if (!isAbsolute(selected) || resolve(selected) !== selected) fail(`rustup returned an unsafe ${name} path`);
    const path = realpathSync(selected);
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0) fail(`rustup resolved ${name} is not a direct executable file`);
    const version = (await run(path, ['--version'], { cwd: sourceRoot, env })).toString('utf8').trim();
    if (!version.startsWith(`${name} ${Q07_RUST_TOOLCHAIN} `)) fail(`pinned ${name} ${Q07_RUST_TOOLCHAIN} identity differs`);
    return Object.freeze({ path, sha256: sha256(readFileSync(path)), version });
  };
  return Object.freeze({ cargo: await capture('cargo'), rustc: await capture('rustc') });
}
function pinnedRustBuildEnvironment(toolchain) {
  if (toolchain === null || Array.isArray(toolchain) || typeof toolchain !== 'object'
    || toolchain.rustc === null || Array.isArray(toolchain.rustc) || typeof toolchain.rustc !== 'object'
    || typeof toolchain.rustc.path !== 'string' || !isAbsolute(toolchain.rustc.path)) {
    fail('pinned Rust build toolchain is invalid');
  }
  return Object.freeze({
    ...pinnedRustEnvironment(),
    RUSTC: toolchain.rustc.path,
  });
}
async function machineManifest(sourceRoot, toolchain) { return Object.freeze({ schema: `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/machine`, platform: { platform: process.platform, architecture: process.arch, release: os.release(), node: process.version, v8: process.versions.v8, cargo: toolchain.cargo, rustc: toolchain.rustc }, hardware: { cpuModels: [...new Set(os.cpus().map((cpu) => cpu.model))].sort(), logicalCores: os.availableParallelism(), totalMemoryBytes: os.totalmem() }, cgroupV2: cgroupV2(), chainAuthenticated: false, q07Qualified: false, qualification: 'local-non-chain-not-published-machine-qualification' }); }
function binarySnapshot(path, label) {
  const s = lstatSync(path);
  if (s.isSymbolicLink() || !s.isFile() || ![1, 2].includes(s.nlink) || (typeof process.getuid === 'function' && s.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned regular file with only Cargo's optional deps hardlink`);
  let cargoDepsPath = null;
  if (s.nlink === 2) {
    const deps = join(dirname(path), 'deps');
    const matches = readdirSync(deps)
      .map((name) => join(deps, name))
      .filter((candidate) => {
        const candidateStat = lstatSync(candidate);
        return !candidateStat.isSymbolicLink() && candidateStat.isFile() && candidateStat.dev === s.dev && candidateStat.ino === s.ino;
      });
    if (matches.length !== 1 || realpathSync(matches[0]) !== matches[0]) fail(`${label} Cargo hardlink topology is ambiguous`);
    cargoDepsPath = matches[0];
  }
  return Object.freeze({
    path,
    bytes: s.size,
    sha256: sha256(readFileSync(path)),
    linkTopology: Object.freeze({ linkCount: s.nlink, cargoDepsPath }),
  });
}
function executableSnapshot(path, label) {
  const snapshot = stableFileSnapshot(path, label, { privateMode: false, exactMode: 0o700 });
  return Object.freeze({ ...snapshot, mode: '0700' });
}
function assertExecutableSnapshot(value, label) {
  exact(value, ['bytes', 'identity', 'mode', 'path', 'sha256'], label);
  assertStableSnapshot({
    path: value.path,
    bytes: value.bytes,
    sha256: value.sha256,
    identity: value.identity,
  }, label);
  if (value.mode !== '0700') fail(`${label} must be mode-0700`);
  return value;
}
function atomicExecutable(root, name, bytes) {
  const path = directChild(root, name, 'executable artifact');
  if (existsSync(path)) fail(`refusing to overwrite ${path}`);
  const temporary = directChild(root, `.${name}.${process.pid}.${Date.now()}.tmp`, 'temporary executable artifact');
  let fd;
  try {
    fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o700);
    chmodSync(temporary, 0o700);
    writeFully(fd, bytes);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    executableSnapshot(temporary, 'temporary executable artifact');
    if (existsSync(path)) fail(`refusing to overwrite ${path}`);
    renameSync(temporary, path);
    const snapshot = executableSnapshot(path, 'executable artifact');
    fsyncDirectory(root);
    return snapshot;
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}
/** Test-only inspection seam for Cargo's documented final-binary hardlink topology. */
export function snapshotQ07BuiltBinaryForTest(path) { return binarySnapshot(resolve(path), 'test release Rust verifier binary'); }
function assertIdentity(value, label, expectedCount, corpusSha, testOnly) {
  const keys = ['actionCount', 'bodySha256', 'chainAuthenticated', 'fileSha256', 'q07Qualified', 'qualification', 'schema', 'terminalStateHex'];
  if (testOnly) exact(value, label === 'JS verifier result' ? [...keys, 'actionTranscriptSha256'] : keys, label);
  else if (label === 'JS verifier result') exact(value, [...keys, 'actionTranscriptSha256', 'path'], label);
  else exact(value, [...keys, 'path'], label);
  const expectedQualification = label === 'generator result'
    ? (testOnly ? 'test-only-nonqualifying' : 'non-chain-corpus-generated-not-q07-qualified')
    : (testOnly ? 'test-only-nonqualifying' : 'non-chain-corpus-verified-not-q07-qualified');
  if (value.actionCount !== String(expectedCount) || value.fileSha256 !== corpusSha || value.chainAuthenticated !== false || value.q07Qualified !== false || !HASH.test(value.bodySha256) || typeof value.terminalStateHex !== 'string' || (!testOnly && value.schema !== 'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus/v1') || value.qualification !== expectedQualification) fail(`${label} identity or local-only status is invalid`);
}
function assertRust(value, expectedCount, js, testOnly) {
  if (testOnly) exact(value, ['actionCount', 'actionTranscriptSha256', 'bodySha256', 'chainAuthenticated', 'q07LifecycleCorpusVerified', 'q07Qualified', 'schema', 'terminalStateHex'], 'Rust verifier result');
  else exact(value, ['actionCount', 'actionCounts', 'actionTranscriptSha256', 'authority', 'bodySha256', 'chainAuthenticated', 'instanceId', 'profileId', 'q07LifecycleCorpusVerified', 'q07Qualified', 'schema', 'status', 'terminalNoteRoot', 'terminalNullifierRoot', 'terminalStateHex', 'terminalStateSha256'], 'Rust verifier result');
  if (value.actionCount !== String(expectedCount) || value.chainAuthenticated !== false || value.q07Qualified !== false || value.q07LifecycleCorpusVerified !== true || value.bodySha256 !== js.bodySha256 || value.actionTranscriptSha256 !== js.actionTranscriptSha256 || value.terminalStateHex !== js.terminalStateHex) fail('Rust verifier result identity or local-only status is invalid');
  if (!testOnly) {
    exact(value.actionCounts, ['deposit', 'transfer', 'withdrawal'], 'Rust verifier actionCounts');
    const expectedCounts = { deposit: '1', transfer: String(expectedCount - 2), withdrawal: '1' };
    if (canonicalJson(value.actionCounts) !== canonicalJson(expectedCounts)
      || value.schema !== 'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus-result/v1'
      || value.status !== 'verified' || value.authority !== 'non-chain-lifecycle-corpus'
      || !HASH.test(value.profileId) || !HASH.test(value.instanceId)
      || !HASH.test(value.terminalNoteRoot) || !HASH.test(value.terminalNullifierRoot)
      || !/^[0-9a-f]{256}$/u.test(value.terminalStateHex)
      || value.terminalStateSha256 !== sha256(Buffer.from(value.terminalStateHex, 'hex'))) {
      fail('Rust verifier result schema, terminal roots, or lifecycle counts are invalid');
    }
    assertResumeTerminal(js, value, expectedCount);
  }
}
function systemdProperties(bytes) { const result = {}; for (const line of bytes.toString('utf8').trim().split('\n')) { const index = line.indexOf('='); if (index <= 0) fail('systemd property output is malformed'); result[line.slice(0, index)] = line.slice(index + 1); } exact(result, ['ActiveState', 'ControlGroup', 'ExecMainStatus', 'MemoryAccounting', 'MemoryPeak', 'SubState'], 'systemd properties'); return result; }
async function childPrivateRust({ sourceRoot, bundleRoot, binaryPath, corpusPath }) {
  const unit = `shieldkit-q07-${process.pid}-${Date.now()}`; const stdoutPath = privateEmpty(bundleRoot, `.rust-stdout-${unit}`); const stderrPath = privateEmpty(bundleRoot, `.rust-stderr-${unit}`); const args = ['--user', '--unit', unit, '--property=MemoryAccounting=yes', '--property=RemainAfterExit=yes', `--property=WorkingDirectory=${sourceRoot}`, `--property=StandardInput=file:${corpusPath}`, `--property=StandardOutput=file:${stdoutPath}`, `--property=StandardError=file:${stderrPath}`, '--service-type=exec', binaryPath]; const command = commandText('systemd-run', args);
  try { await run('systemd-run', args, { cwd: sourceRoot }); let properties; for (let attempt = 0; attempt < 43_200; attempt += 1) { properties = systemdProperties(await run('systemctl', ['--user', 'show', unit, '--property=ActiveState', '--property=SubState', '--property=ExecMainStatus', '--property=ControlGroup', '--property=MemoryPeak', '--property=MemoryAccounting'], { cwd: sourceRoot })); if (properties.SubState === 'exited' || properties.ActiveState === 'failed') break; await pause(1000); } if (!properties || properties.ActiveState !== 'active' || properties.SubState !== 'exited' || properties.ExecMainStatus !== '0' || properties.MemoryAccounting !== 'yes' || !/^\/[^\n]*$/u.test(properties.ControlGroup) || !/^[0-9]+$/u.test(properties.MemoryPeak)) fail('rootless systemd child cgroup measurement is unavailable or invalid'); own(stdoutPath, 'Rust child stdout'); own(stderrPath, 'Rust child stderr'); return Object.freeze({ stdout: readFileSync(stdoutPath), stderr: readFileSync(stderrPath), command, cgroup: Object.freeze({ available: true, unit, controlGroup: properties.ControlGroup, memoryAccounting: true, memoryPeakBytes: properties.MemoryPeak, source: 'systemd --user transient service MemoryPeak property after SubState=exited' }) }); }
  finally { await run('systemctl', ['--user', 'stop', unit], { cwd: sourceRoot }).catch(() => undefined); await run('systemctl', ['--user', 'reset-failed', unit], { cwd: sourceRoot }).catch(() => undefined); if (existsSync(stdoutPath)) unlinkSync(stdoutPath); if (existsSync(stderrPath)) unlinkSync(stderrPath); }
}
async function realExecutor({ sourceRoot, bundleRoot, corpusPath, toolchain }) {
  const script = join(sourceRoot, '03-create-your-own-pool/scripts/v2-q07-lifecycle-corpus.mjs'); const manifest = join(sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.toml'); const binaryPath = join(sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/target/release/q07-lifecycle-verify'); const timed = async (fn) => { const started = performance.now(); const bytes = await fn(); return Object.freeze({ bytes, wallMs: performance.now() - started }); };
  const buildArgs = [`+${Q07_RUST_TOOLCHAIN}`, 'build', '--locked', '--release', '--manifest-path', manifest, '--bin', 'q07-lifecycle-verify']; const rustEnvironment = pinnedRustEnvironment(); const build = await timed(() => run('cargo', buildArgs, { cwd: sourceRoot, env: rustEnvironment })); const binaryBefore = binarySnapshot(binaryPath, 'release Rust verifier binary'); const generator = await timed(() => run(process.execPath, [script, '--output-directory', bundleRoot], { cwd: sourceRoot })); const js = await timed(() => run(process.execPath, [script, '--verify', corpusPath], { cwd: sourceRoot })); const rust = await timed(() => childPrivateRust({ sourceRoot, bundleRoot, binaryPath, corpusPath })); const binaryAfter = binarySnapshot(binaryPath, 'release Rust verifier binary'); if (canonicalJson(binaryBefore) !== canonicalJson(binaryAfter)) fail('release Rust verifier binary changed during measurement');
  const buildCommand = Object.freeze({ ...commandText('cargo', buildArgs), environment: Object.freeze({ MISE_RUST_VERSION: Q07_RUST_TOOLCHAIN, RUSTUP_TOOLCHAIN: Q07_RUST_TOOLCHAIN, inheritedRustFlagsAndWrappers: false }) });
  return Object.freeze({ generator: generator.bytes, js: js.bytes, rust: rust.bytes.stdout, wallMs: Object.freeze({ build: build.wallMs, generator: generator.wallMs, jsVerifier: js.wallMs, rustVerifier: rust.wallMs }), commands: [buildCommand, commandText(process.execPath, [script, '--output-directory', bundleRoot]), commandText(process.execPath, [script, '--verify', corpusPath]), rust.bytes.command], build: Object.freeze({ command: buildCommand, stdoutSha256: sha256(build.bytes), wallMs: build.wallMs, toolchain, binaryBefore, binaryAfter }), childCgroup: rust.bytes.cgroup });
}
async function lifecycle({ outputDirectory, sourceRoot = process.cwd(), actionCount = V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS, executor = realExecutor, testOnly = false } = {}) {
  if (!testOnly && actionCount !== V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS) fail('public local lifecycle runs allow exactly 100000 actions'); if (testOnly && (!Number.isSafeInteger(actionCount) || actionCount < 3 || actionCount > 64)) fail('test-only actionCount must be 3 through 64'); if (typeof executor !== 'function') fail('executor must be a function');
  const parent = resolve(outputDirectory); directDirectory(parent, 'outputDirectory'); const name = `q07-local-lifecycle-${Date.now()}-${process.pid}`; const bundleRoot = join(parent, name); if (existsSync(bundleRoot)) fail('refusing to overwrite lifecycle bundle'); directDirectory(bundleRoot, 'bundle root', true);
  try {
    const source = await sourceSnapshot(sourceRoot); const testToolchain = testOnly ? Object.freeze({ cargo: 'test-only-unavailable', rustc: 'test-only-unavailable' }) : await toolVersions(source.sourceRoot); const sourceArtifact = atomic(bundleRoot, 'source-set.json', Buffer.from(canonicalJson(source), 'utf8')); const machineArtifact = atomic(bundleRoot, 'machine.json', Buffer.from(canonicalJson(await machineManifest(source.sourceRoot, testToolchain)), 'utf8'));
    const corpusPath = directChild(bundleRoot, 'q07-non-chain-lifecycle.ndjson', 'corpus'); const runResult = await measure(cgroupV2(), () => executor({ sourceRoot: source.sourceRoot, bundleRoot, corpusPath, actionCount, testOnly, toolchain: testToolchain }));
    await recheckSource(source); if (!existsSync(corpusPath)) fail('executor did not create the corpus'); const corpus = own(corpusPath, 'corpus'); const corpusSha = sha256(readFileSync(corpusPath)); const generator = json(runResult.bytes.generator, 'generator stdout'); const js = json(runResult.bytes.js, 'JS verifier stdout'); const rust = commandJson(runResult.bytes.rust, 'Rust verifier stdout'); assertIdentity(generator, 'generator result', actionCount, corpusSha, testOnly); assertIdentity(js, 'JS verifier result', actionCount, corpusSha, testOnly); assertRust(rust, actionCount, js, testOnly);
    const corpusArtifact = Object.freeze({ path: 'q07-non-chain-lifecycle.ndjson', bytes: corpus.size, sha256: corpusSha }); const generatorArtifact = atomic(bundleRoot, 'generator-result.json', Buffer.from(canonicalJson(generator), 'utf8')); const jsArtifact = atomic(bundleRoot, 'js-verifier-result.json', Buffer.from(canonicalJson(js), 'utf8')); const rustArtifact = atomic(bundleRoot, 'rust-verifier-result.json', Buffer.from(canonicalJson(rust), 'utf8'));
    const walls = runResult.bytes.wallMs; if (walls === null || typeof walls !== 'object' || !['generator', 'jsVerifier', 'rustVerifier'].every((key) => Number.isFinite(walls[key]) && walls[key] >= 0) || (!testOnly && (!Number.isFinite(walls.build) || walls.build < 0 || runResult.bytes.childCgroup?.available !== true))) fail('executor must report required real-run wall times and child-private cgroup measurement'); const runRecord = Object.freeze({ schema: V2_Q07_LOCAL_LIFECYCLE_SCHEMA, localOnly: true, chainAuthenticated: false, q07Qualified: false, testOnly, qualification: testOnly ? 'test-only-non-chain-local-run' : 'non-chain-local-run-not-final-or-published-machine-qualification', actionCount: String(actionCount), commands: runResult.bytes.commands ?? [], wallMs: Object.freeze({ total: runResult.wallMs, ...walls }), cgroupV2: runResult.cgroupV2, childCgroup: runResult.bytes.childCgroup ?? { available: false, reason: 'test-only-no-benchmark' }, sourceSet: sourceArtifact, machine: machineArtifact, sourceSetSha256: source.sourceSetSha256, corpus: corpusArtifact, generator: generatorArtifact, jsVerifier: jsArtifact, rustVerifier: rustArtifact, build: runResult.bytes.build ?? { status: 'test-only-not-built' } }); const runArtifact = atomic(bundleRoot, 'run.json', Buffer.from(canonicalJson(runRecord), 'utf8'));
    const artifacts = [sourceArtifact, machineArtifact, corpusArtifact, generatorArtifact, jsArtifact, rustArtifact, runArtifact].map((entry, index) => Object.freeze({ role: ['source-set', 'machine', 'corpus', 'generator-result', 'js-verifier-result', 'rust-verifier-result', 'run'][index], ...entry })); const manifest = Object.freeze({ schema: V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA, localOnly: true, chainAuthenticated: false, q07Qualified: false, artifacts }); atomic(bundleRoot, 'manifest.json', Buffer.from(canonicalJson(manifest), 'utf8')); fsyncDirectory(bundleRoot); fsyncDirectory(parent); return verifyQ07LocalLifecycleBundle(bundleRoot);
  } catch (error) { throw error; }
}
export class V2Q07LocalLifecycleError extends Error { constructor(message) { super(message); this.name = 'V2Q07LocalLifecycleError'; } }
export async function runQ07LocalLifecycle(options = {}) { if (options === null || Array.isArray(options) || typeof options !== 'object') fail('public run options must be an object'); for (const forbidden of ['actionCount', 'executor', 'testOnly']) if (Object.hasOwn(options, forbidden)) fail(`public runQ07LocalLifecycle rejects injected ${forbidden}`); return lifecycle({ outputDirectory: options.outputDirectory, sourceRoot: options.sourceRoot ?? process.cwd(), actionCount: V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS, executor: realExecutor, testOnly: false }); }
/** Explicit test-only seam: bounded 3..64 corpus with a fake executor. */
export async function runQ07LocalLifecycleForTest(options = {}) { return lifecycle({ ...options, testOnly: true }); }
function list(root) { const out = []; for (const name of readdirSync(root)) { const path = join(root, name); const s = lstatSync(path); if (s.isSymbolicLink() || !s.isFile() || s.nlink !== 1) fail(`bundle contains a link or non-regular entry: ${name}`); out.push(name); } return out.sort(); }
function assertSourceSet(source) {
  exact(source, ['files', 'gitCommit', 'gitTree', 'locks', 'schema', 'sourceRoot', 'sourceSetSha256'], 'source set');
  if (source.schema !== `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/source-set` || !GIT.test(source.gitCommit) || !GIT.test(source.gitTree) || typeof source.sourceRoot !== 'string' || !isAbsolute(source.sourceRoot) || resolve(source.sourceRoot) !== source.sourceRoot || !Array.isArray(source.files) || !Array.isArray(source.locks) || !HASH.test(source.sourceSetSha256)) fail('source set identity is invalid');
  const names = [];
  for (const entry of source.files) {
    exact(entry, ['bytes', 'path', 'sha256'], 'source file');
    if (typeof entry.path !== 'string' || entry.path.length === 0 || entry.path.startsWith('/') || entry.path.split('/').some((part) => part === '' || part === '.' || part === '..') || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 || !HASH.test(entry.sha256) || names.includes(entry.path)) fail('source file entry is invalid or duplicated');
    names.push(entry.path);
  }
  if (names.length === 0 || canonicalJson(names) !== canonicalJson([...names].sort())) fail('source files must be nonempty and canonically ordered');
  const expectedLocks = source.files.filter((entry) => /(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|Cargo\.lock)$/u.test(entry.path));
  if (expectedLocks.length === 0 || !expectedLocks.some((entry) => entry.path === 'package-lock.json') || canonicalJson(source.locks) !== canonicalJson(expectedLocks) || sha256(Buffer.from(canonicalJson(source.files), 'utf8')) !== source.sourceSetSha256) fail('source locks or source-set hash are incomplete');
}
function positiveDecimal(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/u.test(value)) fail(`${label} must be a positive canonical decimal string`);
  return BigInt(value);
}
function finiteDuration(value, label) {
  if (!Number.isFinite(value) || value < 0) fail(`${label} must be a finite nonnegative duration`);
  return value;
}
function assertBinarySnapshot(value, expectedPath, label) {
  exact(value, ['bytes', 'linkTopology', 'path', 'sha256'], label);
  exact(value.linkTopology, ['cargoDepsPath', 'linkCount'], `${label} link topology`);
  if (value.path !== expectedPath || !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || !HASH.test(value.sha256) || ![1, 2].includes(value.linkTopology.linkCount)) fail(`${label} is invalid`);
  if (value.linkTopology.linkCount === 1 && value.linkTopology.cargoDepsPath !== null) fail(`${label} single-link topology is invalid`);
  if (value.linkTopology.linkCount === 2) {
    const depsRoot = join(dirname(expectedPath), 'deps');
    if (typeof value.linkTopology.cargoDepsPath !== 'string' || !value.linkTopology.cargoDepsPath.startsWith(`${depsRoot}/`) || dirname(value.linkTopology.cargoDepsPath) !== depsRoot) fail(`${label} Cargo deps hardlink path is invalid`);
  }
}
function assertBinaryPair(value, expectedPath, label, { unchanged = false } = {}) {
  exact(value, ['after', 'before'], label);
  assertBinarySnapshot(value.before, expectedPath, `${label} before`);
  assertBinarySnapshot(value.after, expectedPath, `${label} after`);
  if (unchanged && canonicalJson(value.before) !== canonicalJson(value.after)) {
    fail(`${label} changed while the exact snapshotted binary was executing`);
  }
  return value;
}
function assertResumeBuildBinary(value, sourceRoot, bundleRoot, attemptId) {
  exact(value, ['snapshot', 'sourceTarget'], 'resume rebuilt binary');
  assertBinarySnapshot(value.sourceTarget, expectedBinaryPath(sourceRoot), 'resume rebuilt binary source target');
  assertExecutableSnapshot(value.snapshot, 'resume rebuilt binary snapshot');
  if (value.snapshot.path !== resumeName(attemptId, 'build.binary')
    || value.snapshot.bytes !== value.sourceTarget.bytes
    || value.snapshot.sha256 !== value.sourceTarget.sha256) {
    fail('resume rebuilt binary snapshot does not bind the post-build target');
  }
  const current = executableSnapshot(
    directChild(bundleRoot, value.snapshot.path, 'resume rebuilt binary snapshot'),
    'resume rebuilt binary snapshot',
  );
  if (canonicalJson(current) !== canonicalJson(value.snapshot)) {
    fail('resume rebuilt binary snapshot drifted');
  }
  return Object.freeze({ snapshot: value.snapshot });
}
function assertResumeRustBinary(value, bundleRoot, buildSnapshot) {
  exact(value, ['after', 'before', 'snapshot'], 'systemd immutable Rust verifier binary');
  assertExecutableSnapshot(buildSnapshot, 'selected immutable release Rust verifier snapshot');
  assertExecutableSnapshot(value.snapshot, 'systemd immutable Rust verifier snapshot');
  assertExecutableSnapshot(value.before, 'systemd immutable Rust verifier before');
  assertExecutableSnapshot(value.after, 'systemd immutable Rust verifier after');
  if (canonicalJson(value.snapshot) !== canonicalJson(buildSnapshot)
    || canonicalJson(value.before) !== canonicalJson(buildSnapshot)
    || canonicalJson(value.after) !== canonicalJson(buildSnapshot)) {
    fail('immutable release Rust verifier snapshot changed while systemd executed it');
  }
  const current = executableSnapshot(
    directChild(bundleRoot, buildSnapshot.path, 'selected immutable release Rust verifier snapshot'),
    'selected immutable release Rust verifier snapshot',
  );
  if (canonicalJson(current) !== canonicalJson(buildSnapshot)) {
    fail('selected immutable release Rust verifier snapshot drifted');
  }
  return value;
}
function assertRealRunProvenance(runRecord, source, machine, root) {
  exact(runRecord.childCgroup, ['available', 'controlGroup', 'memoryAccounting', 'memoryPeakBytes', 'source', 'unit'], 'child cgroup');
  if (runRecord.childCgroup.available !== true || runRecord.childCgroup.memoryAccounting !== true || typeof runRecord.childCgroup.unit !== 'string' || !/^shieldkit-q07-[1-9][0-9]*-[1-9][0-9]*$/u.test(runRecord.childCgroup.unit) || typeof runRecord.childCgroup.controlGroup !== 'string' || !runRecord.childCgroup.controlGroup.startsWith('/') || runRecord.childCgroup.source !== 'systemd --user transient service MemoryPeak property after SubState=exited') fail('child-private cgroup provenance is invalid');
  positiveDecimal(runRecord.childCgroup.memoryPeakBytes, 'child cgroup MemoryPeak');
  exact(runRecord.wallMs, ['build', 'generator', 'jsVerifier', 'rustVerifier', 'total'], 'real wall times');
  const componentTotal = ['build', 'generator', 'jsVerifier', 'rustVerifier'].reduce((sum, key) => sum + finiteDuration(runRecord.wallMs[key], `wallMs.${key}`), 0);
  if (finiteDuration(runRecord.wallMs.total, 'wallMs.total') < componentTotal) fail('total wall time is shorter than measured components');
  exact(runRecord.build, ['binaryAfter', 'binaryBefore', 'command', 'stdoutSha256', 'toolchain', 'wallMs'], 'build provenance');
  exact(runRecord.build.command, ['args', 'command', 'environment'], 'build command');
  exact(runRecord.build.command.environment, ['MISE_RUST_VERSION', 'RUSTUP_TOOLCHAIN', 'inheritedRustFlagsAndWrappers'], 'build environment');
  const expectedManifest = join(source.sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.toml');
  const expectedBinary = join(source.sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/target/release/q07-lifecycle-verify');
  const expectedArgs = [`+${Q07_RUST_TOOLCHAIN}`, 'build', '--locked', '--release', '--manifest-path', expectedManifest, '--bin', 'q07-lifecycle-verify'];
  if (runRecord.build.command.command !== 'cargo' || canonicalJson(runRecord.build.command.args) !== canonicalJson(expectedArgs) || runRecord.build.command.environment.MISE_RUST_VERSION !== Q07_RUST_TOOLCHAIN || runRecord.build.command.environment.RUSTUP_TOOLCHAIN !== Q07_RUST_TOOLCHAIN || runRecord.build.command.environment.inheritedRustFlagsAndWrappers !== false || !HASH.test(runRecord.build.stdoutSha256) || runRecord.build.wallMs !== runRecord.wallMs.build) fail('build command, environment, or timing is invalid');
  exact(runRecord.build.toolchain, ['cargo', 'rustc'], 'build toolchain');
  if (runRecord.build.toolchain.cargo !== machine.platform.cargo || runRecord.build.toolchain.rustc !== machine.platform.rustc || !runRecord.build.toolchain.cargo.startsWith(`cargo ${Q07_RUST_TOOLCHAIN} `) || !runRecord.build.toolchain.rustc.startsWith(`rustc ${Q07_RUST_TOOLCHAIN} `)) fail('build toolchain identity differs');
  assertBinarySnapshot(runRecord.build.binaryBefore, expectedBinary, 'pre-measurement binary');
  assertBinarySnapshot(runRecord.build.binaryAfter, expectedBinary, 'post-measurement binary');
  if (canonicalJson(runRecord.build.binaryBefore) !== canonicalJson(runRecord.build.binaryAfter)) fail('release binary provenance changes across measurement');
  if (!Array.isArray(runRecord.commands) || runRecord.commands.length !== 4 || canonicalJson(runRecord.commands[0]) !== canonicalJson(runRecord.build.command)) fail('real run command transcript is invalid');
  const corpusPath = join(root, 'q07-non-chain-lifecycle.ndjson');
  for (const [index, expectedArgsForCommand] of [
    [join(source.sourceRoot, '03-create-your-own-pool/scripts/v2-q07-lifecycle-corpus.mjs'), '--output-directory', root],
    [join(source.sourceRoot, '03-create-your-own-pool/scripts/v2-q07-lifecycle-corpus.mjs'), '--verify', corpusPath],
  ].entries()) {
    const command = runRecord.commands[index + 1];
    exact(command, ['args', 'command'], `run command ${index + 1}`);
    if (typeof command.command !== 'string' || !isAbsolute(command.command) || canonicalJson(command.args) !== canonicalJson(expectedArgsForCommand)) fail(`run command ${index + 1} is invalid`);
  }
  exact(runRecord.commands[3], ['args', 'command'], 'Rust systemd command');
  if (runRecord.commands[3].command !== 'systemd-run' || !Array.isArray(runRecord.commands[3].args) || runRecord.commands[3].args.at(-1) !== expectedBinary || !runRecord.commands[3].args.includes('--property=MemoryAccounting=yes') || !runRecord.commands[3].args.includes('--property=RemainAfterExit=yes') || !runRecord.commands[3].args.includes(`--property=WorkingDirectory=${source.sourceRoot}`) || !runRecord.commands[3].args.includes(`--property=StandardInput=file:${corpusPath}`)) fail('Rust systemd command is invalid');
}

/*
 * The v2 resume format is intentionally incompatible with the original
 * all-or-nothing bundle. It treats every pre-resume byte as an immutable
 * interrupted-origin artifact and never invents timing or generator output
 * that the interrupted v1 process failed to preserve.
 */
const RESUME_QUALIFICATION = 'local-only-interrupted-run-resume-non-chain-non-final-non-published-machine-not-q07-qualified';
const RESUME_PHASES = Object.freeze(['build', 'js-verifier', 'rust-verifier']);
const RESUME_SUFFIX = /^(?:attempt|machine|run)\.json$|^build\.binary$|^(?:build|js-verifier|rust-verifier)\.(?:stdout|stderr|receipt\.json)$/u;
const SYSTEMD_KEYS = Object.freeze([
  'ActiveState', 'ControlGroup', 'ExecMainCode', 'ExecMainStatus', 'InvocationID',
  'MemoryAccounting', 'MemoryPeak', 'Result', 'SubState',
]);
const RESUME_LABEL_KEYS = Object.freeze([
  'chainAuthenticated', 'final', 'localOnly', 'production', 'publishedMachine',
  'q07Qualified', 'qualification', 'releaseQualified',
]);

function plainArtifact(value, label) {
  exact(value, ['bytes', 'path', 'sha256'], label);
  if (typeof value.path !== 'string' || value.path.length === 0 || basename(value.path) !== value.path
    || !Number.isSafeInteger(value.bytes) || value.bytes < 0 || !HASH.test(value.sha256)) {
    fail(`${label} is invalid`);
  }
  return value;
}

function stableIdentity(stat) {
  return Object.freeze({
    device: stat.dev.toString(),
    inode: stat.ino.toString(),
    sizeBytes: stat.size.toString(),
    mtimeNs: stat.mtimeNs.toString(),
    ctimeNs: stat.ctimeNs.toString(),
    linkCount: stat.nlink.toString(),
  });
}

function assertStableIdentity(value, label) {
  exact(value, ['ctimeNs', 'device', 'inode', 'linkCount', 'mtimeNs', 'sizeBytes'], label);
  for (const key of ['device', 'inode', 'sizeBytes', 'mtimeNs', 'ctimeNs', 'linkCount']) {
    if (typeof value[key] !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(value[key])) fail(`${label}.${key} is invalid`);
  }
  if (value.linkCount !== '1') fail(`${label} must describe a single-link file`);
  return value;
}

function sameBigIntStat(left, right) {
  return ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs', 'nlink', 'mode', 'uid']
    .every((key) => left[key] === right[key]);
}

/**
 * Chunked, no-follow hashing for resume evidence. This deliberately avoids
 * materialising the large lifecycle corpus in memory.
 */
function stableFileSnapshot(path, label, { privateMode = true, exactMode = null, countLines = false } = {}) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const initial = fstatSync(fd, { bigint: true });
    const named = lstatSync(path, { bigint: true });
    const expectedUid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : initial.uid;
    if (!initial.isFile() || initial.nlink !== 1n || initial.uid !== expectedUid
      || (privateMode && (initial.mode & 0o777n) !== 0o600n)
      || (exactMode !== null && (initial.mode & 0o777n) !== BigInt(exactMode))
      || !sameBigIntStat(initial, named) || realpathSync(path) !== path) {
      fail(`${label} must remain a direct user-owned ${
        exactMode === null ? (privateMode ? 'mode-0600 ' : '') : `mode-${exactMode.toString(8)} `
      }single-link file`);
    }
    const digest = createHash('sha256');
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let bytes = 0;
    let lines = 0;
    let finalByte = null;
    for (;;) {
      const count = readSync(fd, chunk, 0, chunk.length, null);
      if (count === 0) break;
      digest.update(chunk.subarray(0, count));
      if (countLines) {
        for (let index = 0; index < count; index += 1) if (chunk[index] === 0x0a) lines += 1;
        finalByte = chunk[count - 1];
      }
      bytes += count;
    }
    const final = fstatSync(fd, { bigint: true });
    const finalNamed = lstatSync(path, { bigint: true });
    if (!sameBigIntStat(initial, final) || !sameBigIntStat(initial, finalNamed)
      || BigInt(bytes) !== initial.size || realpathSync(path) !== path) {
      fail(`${label} changed while it was stream-hashed`);
    }
    if (initial.size > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} is too large to seal safely`);
    if (countLines && initial.size !== 0n && finalByte !== 0x0a) fail(`${label} must end in a newline`);
    const snapshot = {
      path: basename(path),
      bytes: Number(initial.size),
      sha256: digest.digest('hex'),
      identity: stableIdentity(initial),
    };
    if (countLines) snapshot.lines = String(lines);
    return Object.freeze(snapshot);
  } finally {
    closeSync(fd);
  }
}

function assertStableSnapshot(value, label, { corpus = false } = {}) {
  exact(value, corpus ? ['bytes', 'identity', 'lines', 'path', 'sha256'] : ['bytes', 'identity', 'path', 'sha256'], label);
  plainArtifact({ path: value.path, bytes: value.bytes, sha256: value.sha256 }, label);
  assertStableIdentity(value.identity, `${label} identity`);
  if (value.identity.sizeBytes !== String(value.bytes)) fail(`${label} size identity differs`);
  if (corpus && (typeof value.lines !== 'string' || !/^[1-9][0-9]*$/u.test(value.lines))) fail(`${label} line count is invalid`);
  return value;
}

function stableReference(value) {
  return Object.freeze({ path: value.path, bytes: value.bytes, sha256: value.sha256 });
}

function compareStableSnapshot(actual, expected, label, options = {}) {
  assertStableSnapshot(expected, label, options);
  if (canonicalJson(actual) !== canonicalJson(expected)) fail(`${label} drifted`);
}

function commandOutputJson(bytes, label) {
  let value;
  try {
    value = parseStrictJson(bytes);
  } catch (error) {
    fail(`${label} is not strict JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const canonical = canonicalJson(value);
  if (text !== canonical && text !== `${canonical}\n`) fail(`${label} is not one canonical JSON value`);
  return value;
}

function resumeLabels() {
  return Object.freeze({
    localOnly: true,
    chainAuthenticated: false,
    final: false,
    publishedMachine: false,
    q07Qualified: false,
    production: false,
    releaseQualified: false,
    qualification: RESUME_QUALIFICATION,
  });
}

function assertOriginPins(value, label = 'independent origin pins') {
  exact(value, ['corpus', 'source'], label);
  exact(value.corpus, ['bytes', 'lines', 'sha256'], `${label} corpus`);
  exact(
    value.source,
    ['gitCommit', 'gitTree', 'sourceSetArtifactSha256', 'sourceSetSha256'],
    `${label} source`,
  );
  if (!HASH.test(value.corpus.sha256)
    || typeof value.corpus.bytes !== 'string' || !/^[1-9][0-9]*$/u.test(value.corpus.bytes)
    || typeof value.corpus.lines !== 'string' || !/^[1-9][0-9]*$/u.test(value.corpus.lines)
    || !HASH.test(value.source.sourceSetArtifactSha256)
    || !HASH.test(value.source.sourceSetSha256)
    || !GIT.test(value.source.gitCommit) || !GIT.test(value.source.gitTree)) {
    fail(`${label} is invalid`);
  }
  return value;
}

function normaliseOriginPins(value, testOnly) {
  assertOriginPins(value);
  const pins = Object.freeze({
    corpus: Object.freeze({ ...value.corpus }),
    source: Object.freeze({ ...value.source }),
  });
  if (!testOnly && canonicalJson(pins) !== canonicalJson(V2_Q07_PRESERVED_ORIGIN_PINS)) {
    fail('public resume origin pins do not identify the preserved 670291065-byte/100002-line corpus and exact v1 source');
  }
  return pins;
}

function assertOrchestrationPins(value, label = 'independent orchestration pins') {
  exact(value, ['gitCommit', 'gitTree', 'runnerSha256'], label);
  if (!GIT.test(value.gitCommit) || !GIT.test(value.gitTree) || !HASH.test(value.runnerSha256)) {
    fail(`${label} is invalid`);
  }
  return value;
}

function normaliseOrchestrationPins(value) {
  assertOrchestrationPins(value);
  return Object.freeze({ ...value });
}

function assertLiveRunnerCheckout(pins) {
  normaliseOrchestrationPins(pins);
  const runnerPath = realpathSync(fileURLToPath(import.meta.url));
  const runnerRoot = gitSync(dirname(runnerPath), ['rev-parse', '--show-toplevel']).trim();
  if (gitSync(runnerRoot, ['status', '--porcelain=v1', '--untracked-files=all']) !== ''
    || gitSync(runnerRoot, ['rev-parse', 'HEAD']).trim() !== pins.gitCommit
    || gitSync(runnerRoot, ['rev-parse', 'HEAD^{tree}']).trim() !== pins.gitTree) {
    fail('live v2 runner checkout is not the explicitly pinned clean commit/tree');
  }
  const runnerRelative = relative(runnerRoot, runnerPath);
  if (runnerRelative === '' || runnerRelative.startsWith('../') || isAbsolute(runnerRelative)
    || gitSync(runnerRoot, ['ls-files', '--error-unmatch', '--', runnerRelative]).trim() !== runnerRelative) {
    fail('live v2 runner is not a tracked direct file of its pinned checkout');
  }
  const fileHash = sha256(readFileSync(runnerPath));
  if (fileHash !== pins.runnerSha256) {
    fail('live v2 runner file hash differs from the explicitly pinned runner hash');
  }
  return Object.freeze({ ...pins });
}

function observedOriginPins(source, corpus, sourceSetArtifactSha256, testOnly) {
  if (!HASH.test(sourceSetArtifactSha256)) fail('observed source-set artifact hash is invalid');
  const pins = normaliseOriginPins({
    corpus: {
      sha256: corpus.sha256,
      bytes: String(corpus.bytes),
      lines: corpus.lines,
    },
    source: {
      sourceSetArtifactSha256,
      sourceSetSha256: source.sourceSetSha256,
      gitCommit: source.gitCommit,
      gitTree: source.gitTree,
    },
  }, testOnly);
  if (pins.corpus.sha256 !== corpus.sha256 || pins.corpus.bytes !== String(corpus.bytes)
    || pins.corpus.lines !== corpus.lines
    || pins.source.sourceSetArtifactSha256 !== sourceSetArtifactSha256
    || pins.source.sourceSetSha256 !== source.sourceSetSha256
    || pins.source.gitCommit !== source.gitCommit || pins.source.gitTree !== source.gitTree) {
    fail('independent origin pins do not match the preserved corpus and source set');
  }
  return pins;
}

function interruptedOriginRecord(originPins) {
  return Object.freeze({
    ...resumeLabels(),
    classification: 'interrupted-v1-partial-bundle-with-complete-corpus',
    sourceLifecycleSchema: V2_Q07_LOCAL_LIFECYCLE_SCHEMA,
    originPins,
    generatorResult: null,
    generatorWallMs: null,
    originalJsVerifierResult: null,
    originalJsVerifierWallMs: null,
    originalRustVerifierResult: null,
    originalRustVerifierWallMs: null,
    originalTotalWallMs: null,
  });
}

function assertInterruptedOrigin(value, label) {
  exact(value, [
    ...RESUME_LABEL_KEYS, 'classification', 'generatorResult', 'generatorWallMs',
    'originPins', 'originalJsVerifierResult', 'originalJsVerifierWallMs',
    'originalRustVerifierResult', 'originalRustVerifierWallMs', 'originalTotalWallMs',
    'sourceLifecycleSchema',
  ], label);
  assertResumeLabels(value, label);
  assertOriginPins(value.originPins, `${label} origin pins`);
  if (value.classification !== 'interrupted-v1-partial-bundle-with-complete-corpus'
    || value.sourceLifecycleSchema !== V2_Q07_LOCAL_LIFECYCLE_SCHEMA
    || value.generatorResult !== null || value.generatorWallMs !== null
    || value.originalJsVerifierResult !== null || value.originalJsVerifierWallMs !== null
    || value.originalRustVerifierResult !== null || value.originalRustVerifierWallMs !== null
    || value.originalTotalWallMs !== null) {
    fail(`${label} must retain all lost v1 evidence as null`);
  }
  return value;
}

function acquireResumeLease(root) {
  const path = directChild(root, RESUME_LEASE_FILENAME, 'resume lease');
  const lease = Object.freeze({
    schema: `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/exclusive-lease`,
    pid: String(process.pid),
    nonce: randomBytes(32).toString('hex'),
  });
  const bytes = Buffer.from(canonicalJson(lease), 'utf8');
  let fd;
  try {
    fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600);
  } catch (error) {
    if (existsSync(path)) fail('bundle already has an active or stale exclusive resume lease');
    throw error;
  }
  try {
    chmodSync(path, 0o600);
    writeFully(fd, bytes);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  const snapshot = stableFileSnapshot(path, 'exclusive resume lease');
  fsyncDirectory(root);
  return Object.freeze({
    name: RESUME_LEASE_FILENAME,
    release() {
      if (!existsSync(path)) fail('exclusive resume lease disappeared before release');
      const current = stableFileSnapshot(path, 'exclusive resume lease');
      compareStableSnapshot(current, snapshot, 'exclusive resume lease');
      if (!readFileSync(path).equals(bytes)) fail('exclusive resume lease token changed');
      unlinkSync(path);
      fsyncDirectory(root);
    },
  });
}

function resumeName(attemptId, suffix) {
  if (!RESUME_ID.test(attemptId) || !RESUME_SUFFIX.test(suffix)) fail('resume artifact name is invalid');
  return `${RESUME_PREFIX}${attemptId}-${suffix}`;
}

function parseResumeName(name) {
  if (!name.startsWith(RESUME_PREFIX)) return null;
  const rest = name.slice(RESUME_PREFIX.length);
  const match = /^([1-9][0-9]*-[0-9a-f]{32})-(.+)$/u.exec(rest);
  if (match === null || !RESUME_SUFFIX.test(match[2])) fail(`unrecognised v2 resume artifact: ${name}`);
  return Object.freeze({ attemptId: match[1], suffix: match[2] });
}

function resumeArtifactSnapshot(root, name, label) {
  const path = directChild(root, name, label);
  return parseResumeName(name)?.suffix === 'build.binary'
    ? executableSnapshot(path, label)
    : stableFileSnapshot(path, label);
}

function newAttemptId(root) {
  for (;;) {
    const timestamp = String(Date.now());
    const attemptId = `${timestamp}-${randomBytes(16).toString('hex')}`;
    if (!existsSync(directChild(root, resumeName(attemptId, 'attempt.json'), 'attempt'))) {
      return Object.freeze({ attemptId, createdAtUnixMs: timestamp });
    }
  }
}

function assertOriginMachine(machine) {
  exact(machine, ['cgroupV2', 'chainAuthenticated', 'hardware', 'platform', 'q07Qualified', 'qualification', 'schema'], 'interrupted origin machine');
  exact(machine.platform, ['architecture', 'cargo', 'node', 'platform', 'release', 'rustc', 'v8'], 'interrupted origin machine platform');
  exact(machine.hardware, ['cpuModels', 'logicalCores', 'totalMemoryBytes'], 'interrupted origin machine hardware');
  if (machine.schema !== `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/machine`
    || machine.chainAuthenticated !== false || machine.q07Qualified !== false
    || machine.qualification !== 'local-non-chain-not-published-machine-qualification'
    || !Array.isArray(machine.hardware.cpuModels) || machine.hardware.cpuModels.length === 0) {
    fail('interrupted origin machine is invalid');
  }
}

async function assertRecordedSourceCheckout(source) {
  assertSourceSet(source);
  const current = await sourceSnapshot(source.sourceRoot);
  if (canonicalJson(current) !== canonicalJson(source)) {
    fail('recorded source-set commit/tree/files/locks differ from the clean source checkout');
  }
  return current;
}

function gitSync(root, args) {
  const result = spawnSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (result.error !== undefined) fail(`git ${args.join(' ')} failed: ${result.error.message}`);
  if (result.status !== 0) fail(`git ${args.join(' ')} failed: ${result.stderr.trim()}`);
  return result.stdout;
}

function assertRecordedSourceCheckoutSync(source) {
  assertSourceSet(source);
  const root = source.sourceRoot;
  if (!existsSync(root) || realpathSync(root) !== root
    || gitSync(root, ['rev-parse', '--show-toplevel']).trim() !== root
    || gitSync(root, ['status', '--porcelain=v1', '--untracked-files=all']) !== ''
    || gitSync(root, ['rev-parse', 'HEAD']).trim() !== source.gitCommit
    || gitSync(root, ['rev-parse', 'HEAD^{tree}']).trim() !== source.gitTree) {
    fail('recorded source checkout is absent, dirty, or has drifted');
  }
  const names = gitSync(root, ['ls-files', '-z']).split('\0').filter(Boolean);
  if (canonicalJson(names) !== canonicalJson(source.files.map((entry) => entry.path))) {
    fail('recorded tracked source file set drifted');
  }
  for (const entry of source.files) {
    const path = resolve(root, entry.path);
    if (!path.startsWith(`${root}/`)) fail('recorded source path escapes its checkout');
    const current = stableFileSnapshot(path, `recorded source ${entry.path}`, { privateMode: false });
    if (current.bytes !== entry.bytes || current.sha256 !== entry.sha256) fail(`recorded source file drifted: ${entry.path}`);
  }
}

function assertResumeLabels(value, label) {
  if (value.localOnly !== true || value.chainAuthenticated !== false || value.final !== false
    || value.publishedMachine !== false || value.q07Qualified !== false || value.production !== false
    || value.releaseQualified !== false || value.qualification !== RESUME_QUALIFICATION) {
    fail(`${label} is not explicitly local-only and non-qualifying`);
  }
}

function assertAttemptRecord(value, name) {
  exact(value, [
    'actionCount', 'attemptId', 'chainAuthenticated', 'corpus', 'createdAtUnixMs', 'final',
    'interruptedOrigin', 'localOnly', 'originArtifacts', 'production', 'publishedMachine',
    'orchestrationPins', 'q07Qualified', 'qualification', 'releaseQualified', 'schema', 'sourceSet',
    'sourceSetSha256', 'testOnly',
  ], 'resume attempt');
  const parsedName = parseResumeName(name);
  if (parsedName === null || parsedName.suffix !== 'attempt.json' || value.schema !== `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/attempt`
    || value.attemptId !== parsedName.attemptId || !RESUME_ID.test(value.attemptId)
    || value.createdAtUnixMs !== value.attemptId.slice(0, value.attemptId.indexOf('-'))
    || typeof value.testOnly !== 'boolean' || typeof value.actionCount !== 'string') {
    fail('resume attempt identity is invalid');
  }
  assertResumeLabels(value, 'resume attempt');
  assertOrchestrationPins(value.orchestrationPins, 'resume attempt orchestration pins');
  plainArtifact(value.sourceSet, 'resume attempt source set');
  assertStableSnapshot(value.corpus, 'resume attempt corpus');
  assertInterruptedOrigin(value.interruptedOrigin, 'resume attempt interrupted origin');
  if (!HASH.test(value.sourceSetSha256) || !Array.isArray(value.originArtifacts) || value.originArtifacts.length < 3) {
    fail('resume attempt origin inventory is invalid');
  }
  let previous = '';
  for (const artifact of value.originArtifacts) {
    assertStableSnapshot(artifact, 'resume attempt origin artifact');
    if (artifact.path <= previous || artifact.path.startsWith(RESUME_PREFIX) || artifact.path === 'manifest.json') {
      fail('resume attempt origin inventory is not canonical');
    }
    previous = artifact.path;
  }
  return value;
}

function readAttempt(root, name) {
  return assertAttemptRecord(json(readFileSync(directChild(root, name, 'attempt')), 'resume attempt'), name);
}

function inspectResumeDirectory(root) {
  const names = list(root).filter((name) => name !== 'manifest.json' && name !== RESUME_LEASE_FILENAME);
  const attemptNames = names.filter((name) => parseResumeName(name)?.suffix === 'attempt.json').sort();
  if (attemptNames.length === 0) {
    if (names.some((name) => name.startsWith(RESUME_PREFIX))) fail('resume artifacts exist without an immutable attempt record');
    const originArtifacts = names.map((name) => stableFileSnapshot(directChild(root, name, 'origin artifact'), `origin artifact ${name}`));
    return Object.freeze({ originArtifacts: Object.freeze(originArtifacts), attempts: Object.freeze([]) });
  }
  const attempts = attemptNames.map((name) => readAttempt(root, name));
  const originArtifacts = attempts[0].originArtifacts;
  for (const attempt of attempts) {
    if (canonicalJson(attempt.originArtifacts) !== canonicalJson(originArtifacts)) fail('resume attempts disagree about the immutable interrupted origin');
  }
  const originNames = new Set(originArtifacts.map((entry) => entry.path));
  const attemptIds = new Set(attempts.map((entry) => entry.attemptId));
  for (const artifact of originArtifacts) {
    const current = stableFileSnapshot(directChild(root, artifact.path, 'origin artifact'), `origin artifact ${artifact.path}`);
    compareStableSnapshot(current, artifact, `origin artifact ${artifact.path}`);
  }
  for (const name of names) {
    if (originNames.has(name)) continue;
    const parsed = parseResumeName(name);
    if (parsed === null || !attemptIds.has(parsed.attemptId)) fail(`unowned post-origin artifact: ${name}`);
    resumeArtifactSnapshot(root, name, `resume artifact ${name}`);
  }
  return Object.freeze({ originArtifacts: Object.freeze(originArtifacts), attempts: Object.freeze(attempts) });
}

function originArtifact(state, name) {
  const artifact = state.originArtifacts.find((entry) => entry.path === name);
  if (artifact === undefined) fail(`interrupted origin lacks ${name}`);
  return artifact;
}

function captureCommand(command, args, { cwd, env = undefined, stdinPath = undefined } = {}) {
  return new Promise((resolveCapture) => {
    const started = performance.now();
    const stdout = [];
    const stderr = [];
    let spawnFailure = null;
    let settled = false;
    const finish = (code, signal) => {
      if (settled) return;
      settled = true;
      resolveCapture(Object.freeze({
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        exitCode: Number.isInteger(code) ? code : null,
        signal: typeof signal === 'string' ? signal : null,
        wallMs: performance.now() - started,
        command: commandText(command, args),
        failure: spawnFailure,
      }));
    };
    let child;
    try {
      child = spawn(command, args, { cwd, env, stdio: [stdinPath === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    } catch (error) {
      spawnFailure = error instanceof Error ? error.message : String(error);
      finish(null, null);
      return;
    }
    child.stdout.on('data', (part) => stdout.push(part));
    child.stderr.on('data', (part) => stderr.push(part));
    child.on('error', (error) => {
      spawnFailure = error instanceof Error ? error.message : String(error);
    });
    if (stdinPath !== undefined) {
      const input = createReadStream(stdinPath);
      input.on('error', (error) => {
        spawnFailure = error instanceof Error ? error.message : String(error);
        child.kill();
      });
      input.pipe(child.stdin);
    }
    child.on('close', finish);
  });
}

function parseSystemdProperties(bytes) {
  const properties = {};
  const text = bytes.toString('utf8');
  for (const line of text.endsWith('\n') ? text.slice(0, -1).split('\n') : text.split('\n')) {
    const index = line.indexOf('=');
    if (index <= 0) fail('systemd property output is malformed');
    properties[line.slice(0, index)] = line.slice(index + 1);
  }
  exact(properties, SYSTEMD_KEYS, 'systemd properties');
  return Object.freeze(properties);
}

async function querySystemdUnit(unit, cwd) {
  const args = ['--user', 'show', unit, ...SYSTEMD_KEYS.map((key) => `--property=${key}`)];
  const result = await captureCommand('systemctl', args, { cwd });
  if (result.exitCode !== 0 || result.signal !== null || result.failure !== null || result.stderr.length !== 0) {
    fail(`systemctl could not inspect ${unit}`);
  }
  return parseSystemdProperties(result.stdout);
}

function assertSystemdEvidence(value, label = 'Rust systemd evidence') {
  exact(value, [
    'available', 'exited', 'launcherStderrSha256', 'launcherStdoutSha256',
    'running', 'source', 'unit',
  ], label);
  if (value.available !== true || typeof value.unit !== 'string'
    || !/^shieldkit-q07-resume-[1-9][0-9]*-[0-9a-f]{16}$/u.test(value.unit)
    || value.source !== 'systemd --user transient service observed while running and after successful exit'
    || !HASH.test(value.launcherStdoutSha256) || !HASH.test(value.launcherStderrSha256)) {
    fail(`${label} identity is invalid`);
  }
  exact(value.running, ['activeState', 'controlGroup', 'invocationId', 'subState'], `${label} running`);
  if (value.running.activeState !== 'active' || value.running.subState !== 'running'
    || !/^\/[^\n]+$/u.test(value.running.controlGroup)
    || !/^[0-9a-f]{32}$/u.test(value.running.invocationId)) {
    fail(`${label} lacks a nonempty ControlGroup and InvocationID captured during execution`);
  }
  exact(value.exited, [
    'activeState', 'controlGroup', 'execMainCode', 'execMainCodeRaw', 'execMainStatus',
    'invocationId', 'memoryAccounting', 'memoryPeakBytes', 'result', 'subState',
  ], `${label} exited`);
  if (value.exited.activeState !== 'active' || value.exited.subState !== 'exited'
    || value.exited.invocationId !== value.running.invocationId
    || value.exited.result !== 'success' || value.exited.execMainCode !== 'exited'
    || value.exited.execMainCodeRaw !== '1' || value.exited.execMainStatus !== '0'
    || value.exited.memoryAccounting !== true || !/^(?:0|[1-9][0-9]*)$/u.test(value.exited.memoryPeakBytes)
    || (value.exited.controlGroup !== '' && value.exited.controlGroup !== value.running.controlGroup)) {
    fail(`${label} does not prove a successful invariant systemd invocation`);
  }
  return value;
}

async function runSystemdChild({
  sourceRoot, bundleRoot, executable, executableArgs = [], stdinPath = undefined,
  maximumPolls = 43_200, pollMilliseconds = 1_000,
}) {
  const started = performance.now();
  const unit = `shieldkit-q07-resume-${process.pid}-${randomBytes(8).toString('hex')}`;
  const stdoutPath = privateEmpty(bundleRoot, `.${unit}.stdout`);
  const stderrPath = privateEmpty(bundleRoot, `.${unit}.stderr`);
  const args = [
    '--user', '--unit', unit, '--property=MemoryAccounting=yes',
    '--property=RemainAfterExit=yes', `--property=WorkingDirectory=${sourceRoot}`,
    ...(stdinPath === undefined ? [] : [`--property=StandardInput=file:${stdinPath}`]),
    `--property=StandardOutput=file:${stdoutPath}`,
    `--property=StandardError=file:${stderrPath}`,
    '--service-type=exec', '--', executable, ...executableArgs,
  ];
  const command = commandText('systemd-run', args);
  let launcher = null;
  let running = null;
  let exited = null;
  let failure = null;
  let stdout = Buffer.alloc(0);
  let stderr = Buffer.alloc(0);
  try {
    launcher = await captureCommand('systemd-run', args, { cwd: sourceRoot });
    if (launcher.exitCode !== 0 || launcher.signal !== null || launcher.failure !== null) {
      fail(`systemd-run --user could not start the mandatory transient service: ${
        launcher.failure ?? (launcher.stderr.toString('utf8').trim() || `exit ${launcher.signal ?? launcher.exitCode}`)
      }`);
    }
    for (let attempt = 0; attempt < maximumPolls; attempt += 1) {
      const properties = await querySystemdUnit(unit, sourceRoot);
      if (running === null && properties.ActiveState === 'active' && properties.SubState === 'running') {
        if (!/^\/[^\n]+$/u.test(properties.ControlGroup) || !/^[0-9a-f]{32}$/u.test(properties.InvocationID)) {
          fail('systemd running observation lacks ControlGroup or InvocationID');
        }
        running = Object.freeze({
          activeState: properties.ActiveState,
          subState: properties.SubState,
          controlGroup: properties.ControlGroup,
          invocationId: properties.InvocationID,
        });
      }
      if (properties.SubState === 'exited' || properties.ActiveState === 'failed') {
        exited = properties;
        break;
      }
      await pause(pollMilliseconds);
    }
    if (running === null || exited === null) fail('systemd transient service was not observed both running and exited');
    const evidence = Object.freeze({
      available: true,
      unit,
      running,
      exited: Object.freeze({
        activeState: exited.ActiveState,
        subState: exited.SubState,
        controlGroup: exited.ControlGroup,
        invocationId: exited.InvocationID,
        result: exited.Result,
        execMainCode: exited.ExecMainCode === '1' ? 'exited' : 'unknown',
        execMainCodeRaw: exited.ExecMainCode,
        execMainStatus: exited.ExecMainStatus,
        memoryAccounting: exited.MemoryAccounting === 'yes',
        memoryPeakBytes: exited.MemoryPeak,
      }),
      launcherStdoutSha256: sha256(launcher.stdout),
      launcherStderrSha256: sha256(launcher.stderr),
      source: 'systemd --user transient service observed while running and after successful exit',
    });
    assertSystemdEvidence(evidence);
    own(stdoutPath, 'systemd child stdout');
    own(stderrPath, 'systemd child stderr');
    stdout = readFileSync(stdoutPath);
    stderr = readFileSync(stderrPath);
    if (stderr.length !== 0) fail('Rust verifier systemd stderr must be empty');
    return Object.freeze({
      stdout,
      stderr,
      exitCode: 0,
      signal: null,
      wallMs: performance.now() - started,
      command,
      systemd: evidence,
      failure: null,
    });
  } catch (error) {
    failure = error instanceof Error ? error.message : String(error);
    if (existsSync(stdoutPath)) stdout = readFileSync(stdoutPath);
    if (existsSync(stderrPath)) stderr = readFileSync(stderrPath);
    return Object.freeze({
      stdout,
      stderr,
      exitCode: 1,
      signal: null,
      wallMs: performance.now() - started,
      command,
      systemd: null,
      failure,
    });
  } finally {
    await run('systemctl', ['--user', 'stop', unit], { cwd: sourceRoot }).catch(() => undefined);
    await run('systemctl', ['--user', 'reset-failed', unit], { cwd: sourceRoot }).catch(() => undefined);
    if (existsSync(stdoutPath)) unlinkSync(stdoutPath);
    if (existsSync(stderrPath)) unlinkSync(stderrPath);
  }
}

function buildCommand(sourceRoot, toolchain) {
  const manifest = join(sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/Cargo.toml');
  if (toolchain === null || Array.isArray(toolchain) || typeof toolchain !== 'object'
    || toolchain.cargo === null || Array.isArray(toolchain.cargo) || typeof toolchain.cargo !== 'object'
    || typeof toolchain.cargo.path !== 'string' || !isAbsolute(toolchain.cargo.path)) {
    fail('pinned Cargo toolchain is invalid');
  }
  const args = ['build', '--locked', '--release', '--manifest-path', manifest, '--bin', 'q07-lifecycle-verify'];
  return Object.freeze({
    command: toolchain.cargo.path,
    args: Object.freeze(args),
    environment: Object.freeze({
      MISE_RUST_VERSION: Q07_RUST_TOOLCHAIN,
      RUSTUP_TOOLCHAIN: Q07_RUST_TOOLCHAIN,
      RUSTC: toolchain.rustc.path,
      inheritedRustFlagsAndWrappers: false,
    }),
  });
}

function expectedBinaryPath(sourceRoot) {
  return join(sourceRoot, '03-create-your-own-pool/crates/shieldkit-v2-recovery/target/release/q07-lifecycle-verify');
}

function snapshotBuiltBinary({ sourceRoot, bundleRoot, attemptId }) {
  const target = expectedBinaryPath(sourceRoot);
  const before = binarySnapshot(target, 'post-build release Rust verifier binary');
  const bytes = readFileSync(target);
  const after = binarySnapshot(target, 'post-build release Rust verifier binary');
  if (canonicalJson(before) !== canonicalJson(after) || sha256(bytes) !== before.sha256) {
    fail('release Rust verifier target changed while its immutable snapshot was captured');
  }
  const snapshot = atomicExecutable(bundleRoot, resumeName(attemptId, 'build.binary'), bytes);
  if (snapshot.bytes !== before.bytes || snapshot.sha256 !== before.sha256) {
    fail('immutable release Rust verifier snapshot differs from the post-build target');
  }
  return Object.freeze({ sourceTarget: before, snapshot });
}
/** Test-only seams for snapshot and command binding; production never accepts injected executors. */
export function captureQ07BuiltBinaryForTest({ sourceRoot, bundleRoot, attemptId }) {
  return snapshotBuiltBinary({ sourceRoot: resolve(sourceRoot), bundleRoot: resolve(bundleRoot), attemptId });
}
export function q07ResumeBuildCommandForTest({ sourceRoot, toolchain }) {
  return buildCommand(resolve(sourceRoot), toolchain);
}
export function snapshotQ07ExecutableForTest(path) {
  return executableSnapshot(resolve(path), 'test immutable executable snapshot');
}
export function assertQ07ResumeRustSnapshotForTest({ binary, bundleRoot, buildSnapshot }) {
  return assertResumeRustBinary(binary, resolve(bundleRoot), buildSnapshot);
}

function realResumeExecutor() {
  return Object.freeze({
    async build({ sourceRoot, bundleRoot, attemptId, toolchain }) {
      const command = buildCommand(sourceRoot, toolchain);
      const capture = await captureCommand(command.command, command.args, { cwd: sourceRoot, env: pinnedRustBuildEnvironment(toolchain) });
      let binary = null;
      let failure = capture.failure;
      if (capture.exitCode === 0 && capture.signal === null && failure === null) {
        try {
          binary = snapshotBuiltBinary({ sourceRoot, bundleRoot, attemptId });
        } catch (error) {
          failure = error instanceof Error ? error.message : String(error);
        }
      }
      return Object.freeze({ ...capture, command, binary, systemd: null, failure });
    },
    async jsVerifier({ sourceRoot, corpusPath }) {
      const script = join(sourceRoot, '03-create-your-own-pool/scripts/v2-q07-lifecycle-corpus.mjs');
      const capture = await captureCommand(process.execPath, [script, '--verify', corpusPath], { cwd: sourceRoot });
      return Object.freeze({ ...capture, binary: null, systemd: null });
    },
    async rustVerifier({ sourceRoot, bundleRoot, corpusPath, buildSnapshot }) {
      assertExecutableSnapshot(buildSnapshot, 'selected immutable release Rust verifier snapshot');
      const executable = directChild(bundleRoot, buildSnapshot.path, 'selected immutable release Rust verifier snapshot');
      const before = executableSnapshot(executable, 'pre-systemd immutable release Rust verifier snapshot');
      const capture = await runSystemdChild({
        sourceRoot,
        bundleRoot,
        executable,
        stdinPath: corpusPath,
      });
      const after = executableSnapshot(executable, 'post-systemd immutable release Rust verifier snapshot');
      return Object.freeze({ ...capture, binary: Object.freeze({ snapshot: buildSnapshot, before, after }) });
    },
  });
}

function normaliseCapture(value, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} executor result must be an object`);
  const stdout = value.stdout instanceof Uint8Array ? Buffer.from(value.stdout) : null;
  const stderr = value.stderr instanceof Uint8Array ? Buffer.from(value.stderr) : null;
  if (stdout === null || stderr === null || (!Number.isInteger(value.exitCode) && value.exitCode !== null)
    || (typeof value.signal !== 'string' && value.signal !== null)
    || !Number.isFinite(value.wallMs) || value.wallMs < 0
    || value.command === null || Array.isArray(value.command) || typeof value.command !== 'object'
    || (typeof value.failure !== 'string' && value.failure !== null && value.failure !== undefined)) {
    fail(`${label} executor result is malformed`);
  }
  return Object.freeze({
    stdout,
    stderr,
    exitCode: value.exitCode,
    signal: value.signal,
    wallMs: value.wallMs,
    command: value.command,
    binary: value.binary ?? null,
    systemd: value.systemd ?? null,
    failure: value.failure ?? null,
  });
}

function assertResumeTerminal(js, rust, actionCount) {
  if (!/^[0-9a-f]{256}$/u.test(js.terminalStateHex)) fail('JS verifier terminal state is not one SKS2 commitment');
  let state;
  try {
    state = decodeStateNftCommitment(
      Buffer.from(js.terminalStateHex, 'hex'),
      Object.freeze({ denominationSats: Q07_DENOMINATION_SATS }),
    );
  } catch (error) {
    fail(`JS verifier terminal SKS2 commitment is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  const expectedCounter = String(actionCount - 1);
  if (state.noteCount !== expectedCounter || state.nullifierCount !== expectedCounter
    || state.maximumLiveNotes !== '32' || state.reserveSats !== '0'
    || state.actionSequence !== String(actionCount)) {
    fail('decoded terminal SKS2 state does not match the exact lifecycle');
  }
  if (rust.profileId !== undefined && rust.profileId !== state.profileId) fail('Rust profileId differs from decoded SKS2 state');
  if (rust.terminalNoteRoot !== undefined && rust.terminalNoteRoot !== state.noteRoot) fail('Rust note root differs from decoded SKS2 state');
  if (rust.terminalNullifierRoot !== undefined && rust.terminalNullifierRoot !== state.nullifierRoot) fail('Rust nullifier root differs from decoded SKS2 state');
  return state;
}

function phaseMethod(phase) {
  return ({ build: 'build', 'js-verifier': 'jsVerifier', 'rust-verifier': 'rustVerifier' })[phase];
}

function resumeRustSystemdArgs(sourceRoot, corpusPath, systemd, buildSnapshot) {
  assertSystemdEvidence(systemd);
  assertExecutableSnapshot(buildSnapshot, 'selected immutable release Rust verifier snapshot');
  const snapshotPath = directChild(dirname(corpusPath), buildSnapshot.path, 'selected immutable release Rust verifier snapshot');
  return Object.freeze([
    '--user',
    '--unit',
    systemd.unit,
    '--property=MemoryAccounting=yes',
    '--property=RemainAfterExit=yes',
    `--property=WorkingDirectory=${sourceRoot}`,
    `--property=StandardInput=file:${corpusPath}`,
    `--property=StandardOutput=file:${join(dirname(corpusPath), `.${systemd.unit}.stdout`)}`,
    `--property=StandardError=file:${join(dirname(corpusPath), `.${systemd.unit}.stderr`)}`,
    '--service-type=exec',
    '--',
    snapshotPath,
  ]);
}
/** Test-only command inspection seam for the immutable systemd binary path. */
export function q07ResumeRustSystemdArgsForTest({ sourceRoot, corpusPath, systemd, buildSnapshot }) {
  return resumeRustSystemdArgs(resolve(sourceRoot), resolve(corpusPath), systemd, buildSnapshot);
}

function assertResumeCommand(command, phase, sourceRoot, corpusPath, testOnly, systemd = null, toolchain = null, buildSnapshot = null) {
  if (testOnly) {
    exact(command, ['args', 'command'], `${phase} test command`);
    if (typeof command.command !== 'string' || command.command.length === 0 || !Array.isArray(command.args)) {
      fail(`${phase} test command is invalid`);
    }
    return;
  }
  if (phase === 'build') {
    if (canonicalJson(command) !== canonicalJson(buildCommand(sourceRoot, toolchain))) fail('resume build command is not the pinned absolute locked Rust build');
    return;
  }
  exact(command, ['args', 'command'], `${phase} command`);
  if (!Array.isArray(command.args)) fail(`${phase} command args are invalid`);
  if (phase === 'js-verifier') {
    const expected = [
      join(sourceRoot, '03-create-your-own-pool/scripts/v2-q07-lifecycle-corpus.mjs'),
      '--verify',
      corpusPath,
    ];
    if (command.command !== process.execPath || canonicalJson(command.args) !== canonicalJson(expected)) {
      fail('resume JS phase must invoke only the corpus --verify path');
    }
    return;
  }
  const expected = resumeRustSystemdArgs(sourceRoot, corpusPath, systemd, buildSnapshot);
  if (command.command !== 'systemd-run' || canonicalJson(command.args) !== canonicalJson(expected)) {
    fail('resume Rust phase is not the mandatory user-systemd verifier command');
  }
}

function validateResumeOutput({ phase, stdout, stderr, binary, systemd, sourceRoot, bundleRoot, attemptId, corpusPath, corpus, actionCount, testOnly, jsResult, buildSnapshot }) {
  if (phase === 'build') {
    if (testOnly) {
      if (binary !== null || systemd !== null) fail('test-only build receipt carries real benchmark provenance');
    } else {
      const result = assertResumeBuildBinary(binary, sourceRoot, bundleRoot, attemptId);
      if (systemd !== null) fail('build receipt unexpectedly carries systemd evidence');
      return Object.freeze({ result, binary });
    }
    return Object.freeze({ result: null, binary });
  }
  if (phase === 'js-verifier') {
    if (binary !== null) fail('JS verifier receipt unexpectedly carries binary provenance');
    if (stderr.length !== 0) fail('JS verifier stderr must be empty');
    if (systemd !== null) fail('JS verifier receipt unexpectedly carries systemd evidence');
    const result = commandOutputJson(stdout, 'resume JS verifier stdout');
    assertIdentity(result, 'JS verifier result', actionCount, corpus.sha256, testOnly);
    if (!testOnly && result.path !== corpusPath) fail('JS verifier result path does not identify the preserved corpus');
    assertResumeTerminal(result, {}, actionCount);
    return Object.freeze({ result, binary: null });
  }
  if (stderr.length !== 0) fail('Rust verifier stderr must be empty');
  if (testOnly) {
    if (binary !== null) fail('test-only Rust receipt carries real binary provenance');
  } else {
    assertResumeRustBinary(binary, bundleRoot, buildSnapshot);
  }
  assertSystemdEvidence(systemd, testOnly ? 'mocked Rust systemd evidence' : 'Rust systemd evidence');
  const result = commandOutputJson(stdout, 'resume Rust verifier stdout');
  assertRust(result, actionCount, jsResult, testOnly);
  assertResumeTerminal(jsResult, result, actionCount);
  return Object.freeze({ result, binary: null });
}

function receiptFilename(attemptId, phase) {
  return resumeName(attemptId, `${phase}.receipt.json`);
}

function receiptReference(root, name) {
  const snapshot = stableFileSnapshot(directChild(root, name, 'phase receipt'), `phase receipt ${name}`);
  return stableReference(snapshot);
}

function assertReceiptShape(value, name) {
  exact(value, [
    'actionCount', 'attemptId', 'binary', 'chainAuthenticated', 'command', 'context',
    'dependencies', 'exit', 'failure', 'final', 'localOnly', 'phase', 'production',
    'orchestrationPins', 'publishedMachine', 'q07Qualified', 'qualification', 'releaseQualified', 'schema',
    'status', 'stderr', 'stdout', 'systemd', 'testOnly', 'wallMs',
  ], 'resume phase receipt');
  const parsedName = parseResumeName(name);
  if (parsedName === null || parsedName.suffix !== `${value.phase}.receipt.json`
    || value.schema !== `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/phase-receipt`
    || !RESUME_PHASES.includes(value.phase) || value.attemptId !== parsedName.attemptId
    || typeof value.testOnly !== 'boolean' || typeof value.actionCount !== 'string'
    || !['completed', 'failed'].includes(value.status) || !Number.isFinite(value.wallMs) || value.wallMs < 0
    || !Array.isArray(value.dependencies)) {
    fail('resume phase receipt identity is invalid');
  }
  assertResumeLabels(value, 'resume phase receipt');
  assertOrchestrationPins(value.orchestrationPins, 'resume phase receipt orchestration pins');
  exact(value.context, ['corpus', 'sourceSetSha256'], 'resume phase context');
  assertStableSnapshot(value.context.corpus, 'resume phase corpus');
  if (!HASH.test(value.context.sourceSetSha256)) fail('resume phase source-set identity is invalid');
  exact(value.exit, ['code', 'signal'], 'resume phase exit');
  if ((!Number.isInteger(value.exit.code) && value.exit.code !== null)
    || (typeof value.exit.signal !== 'string' && value.exit.signal !== null)
    || (typeof value.failure !== 'string' && value.failure !== null)) {
    fail('resume phase exit is invalid');
  }
  plainArtifact(value.stdout, 'resume phase stdout');
  plainArtifact(value.stderr, 'resume phase stderr');
  for (const dependency of value.dependencies) plainArtifact(dependency, 'resume phase dependency');
  if (value.status === 'completed' && (value.exit.code !== 0 || value.exit.signal !== null || value.failure !== null)) {
    fail('completed resume phase has a failed exit');
  }
  if (value.status === 'failed' && value.failure === null) fail('failed resume phase lacks a failure reason');
  return value;
}

function readReceipt(root, name) {
  const value = json(readFileSync(directChild(root, name, 'phase receipt')), `phase receipt ${name}`);
  return assertReceiptShape(value, name);
}

function validateReceiptFiles(root, receipt) {
  for (const [field, artifact] of [['stdout', receipt.stdout], ['stderr', receipt.stderr]]) {
    const current = stableFileSnapshot(directChild(root, artifact.path, `phase ${field}`), `phase ${field}`);
    if (canonicalJson(stableReference(current)) !== canonicalJson(artifact)) fail(`phase ${field} artifact drifted`);
  }
}

function validateCompletedReceipt({
  root, receipt, expectedPhase, source, corpus, actionCount, testOnly, dependencies, jsResult, orchestrationPins, toolchain, buildSnapshot,
}) {
  if (receipt.status !== 'completed' || receipt.phase !== expectedPhase
    || receipt.actionCount !== String(actionCount) || receipt.testOnly !== testOnly
    || receipt.context.sourceSetSha256 !== source.sourceSetSha256
    || canonicalJson(receipt.context.corpus) !== canonicalJson(corpus)
    || canonicalJson(receipt.orchestrationPins) !== canonicalJson(orchestrationPins)) {
    return null;
  }
  validateReceiptFiles(root, receipt);
  if (canonicalJson(receipt.dependencies) !== canonicalJson(dependencies)) return null;
  const stdout = readFileSync(directChild(root, receipt.stdout.path, 'phase stdout'));
  const stderr = readFileSync(directChild(root, receipt.stderr.path, 'phase stderr'));
  assertResumeCommand(receipt.command, expectedPhase, source.sourceRoot, directChild(root, Q07_CORPUS_FILENAME, 'corpus'), testOnly, receipt.systemd, toolchain, buildSnapshot);
  const validated = validateResumeOutput({
    phase: expectedPhase,
    stdout,
    stderr,
    binary: receipt.binary,
    systemd: receipt.systemd,
    sourceRoot: source.sourceRoot,
    bundleRoot: root,
    attemptId: receipt.attemptId,
    corpusPath: directChild(root, Q07_CORPUS_FILENAME, 'corpus'),
    corpus,
    actionCount,
    testOnly,
    jsResult,
    buildSnapshot,
  });
  return Object.freeze({
    receipt,
    reference: receiptReference(root, receiptFilename(receipt.attemptId, receipt.phase)),
    result: validated.result,
  });
}

function findReusableReceipt({
  root, phase, source, corpus, actionCount, testOnly, dependencies, jsResult, orchestrationPins, toolchain, buildSnapshot,
}) {
  const candidates = list(root)
    .filter((name) => parseResumeName(name)?.suffix === `${phase}.receipt.json`)
    .sort();
  for (const name of candidates) {
    const receipt = readReceipt(root, name);
    validateReceiptFiles(root, receipt);
    if (receipt.status !== 'completed') continue;
    const validated = validateCompletedReceipt({
      root,
      receipt,
      expectedPhase: phase,
      source,
      corpus,
      actionCount,
      testOnly,
      dependencies,
      jsResult,
      orchestrationPins,
      toolchain,
      buildSnapshot,
    });
    if (validated !== null) return validated;
  }
  return null;
}

async function recheckResumeInvariants(source, corpusPath, corpus) {
  await assertRecordedSourceCheckout(source);
  const current = stableFileSnapshot(corpusPath, 'preserved lifecycle corpus');
  compareStableSnapshot(current, corpus, 'preserved lifecycle corpus');
}

async function executeResumePhase({
  root, attemptId, phase, executor, source, corpus, actionCount, testOnly, dependencies, jsResult, orchestrationPins, toolchain, buildSnapshot,
}) {
  const method = phaseMethod(phase);
  if (typeof executor[method] !== 'function') fail(`resume executor lacks ${method}`);
  let capture;
  try {
    capture = normaliseCapture(await executor[method]({
      sourceRoot: source.sourceRoot,
      bundleRoot: root,
      corpusPath: directChild(root, Q07_CORPUS_FILENAME, 'corpus'),
      actionCount,
      testOnly,
      attemptId,
      toolchain,
      buildSnapshot,
    }), phase);
  } catch (error) {
    capture = Object.freeze({
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(`${error instanceof Error ? error.message : String(error)}\n`, 'utf8'),
      exitCode: null,
      signal: null,
      wallMs: 0,
      command: Object.freeze({ command: `failed-${phase}-executor`, args: Object.freeze([]) }),
      binary: null,
      systemd: null,
      failure: error instanceof Error ? error.message : String(error),
    });
  }
  const stdout = atomic(root, resumeName(attemptId, `${phase}.stdout`), capture.stdout);
  const stderr = atomic(root, resumeName(attemptId, `${phase}.stderr`), capture.stderr);
  let validationFailure = capture.failure;
  let validated = null;
  try {
    await recheckResumeInvariants(source, directChild(root, Q07_CORPUS_FILENAME, 'corpus'), corpus);
    if (capture.exitCode !== 0 || capture.signal !== null) fail(`${phase} exited unsuccessfully`);
    assertResumeCommand(capture.command, phase, source.sourceRoot, directChild(root, Q07_CORPUS_FILENAME, 'corpus'), testOnly, capture.systemd, toolchain, buildSnapshot);
    validated = validateResumeOutput({
      phase,
      stdout: capture.stdout,
      stderr: capture.stderr,
      binary: capture.binary,
      systemd: capture.systemd,
      sourceRoot: source.sourceRoot,
      bundleRoot: root,
      attemptId,
      corpusPath: directChild(root, Q07_CORPUS_FILENAME, 'corpus'),
      corpus,
      actionCount,
      testOnly,
      jsResult,
      buildSnapshot,
    });
  } catch (error) {
    validationFailure ??= error instanceof Error ? error.message : String(error);
  }
  const completed = validationFailure === null;
  const receipt = Object.freeze({
    schema: `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/phase-receipt`,
    attemptId,
    phase,
    status: completed ? 'completed' : 'failed',
    ...resumeLabels(),
    orchestrationPins,
    testOnly,
    actionCount: String(actionCount),
    command: capture.command,
    dependencies: Object.freeze(dependencies),
    context: Object.freeze({ sourceSetSha256: source.sourceSetSha256, corpus }),
    exit: Object.freeze({ code: capture.exitCode, signal: capture.signal }),
    wallMs: capture.wallMs,
    stdout,
    stderr,
    binary: capture.binary,
    systemd: capture.systemd,
    failure: completed ? null : validationFailure,
  });
  const receiptArtifact = atomic(root, receiptFilename(attemptId, phase), Buffer.from(canonicalJson(receipt), 'utf8'));
  fsyncDirectory(root);
  if (!completed) fail(`${phase} resume phase failed: ${validationFailure}`);
  return Object.freeze({ receipt, reference: receiptArtifact, result: validated.result });
}

async function selectResumePhase(options) {
  const reusable = findReusableReceipt(options);
  if (reusable !== null) return Object.freeze({ ...reusable, reused: true });
  const executed = await executeResumePhase(options);
  return Object.freeze({ ...executed, reused: false });
}

function validActionCount(actionCount, testOnly) {
  if (!Number.isSafeInteger(actionCount)
    || (testOnly ? actionCount < 3 || actionCount > 64 : actionCount !== V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS)) {
    fail(testOnly ? 'test-only resume actionCount must be 3 through 64' : 'public resume requires exactly 100000 actions');
  }
}

async function resumeMachineRecord(attemptId, sourceRoot, toolchain, orchestrationPins) {
  const base = await machineManifest(sourceRoot, testOnlyResumeToolchainVersions(toolchain));
  return Object.freeze({
    schema: `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/machine`,
    attemptId,
    ...resumeLabels(),
    orchestrationPins,
    toolchain,
    platform: base.platform,
    hardware: base.hardware,
    cgroupV2: base.cgroupV2,
  });
}

function testOnlyResumeToolchainVersions(toolchain) {
  return toolchain === null
    ? Object.freeze({ cargo: 'test-only-unavailable', rustc: 'test-only-unavailable' })
    : Object.freeze({ cargo: toolchain.cargo.version, rustc: toolchain.rustc.version });
}

function assertResumeToolchain(value, testOnly) {
  if (testOnly) {
    if (value !== null) fail('test-only resume machine must not claim a real toolchain hash');
    return;
  }
  exact(value, ['cargo', 'rustc'], 'resume toolchain');
  for (const name of ['cargo', 'rustc']) {
    exact(value[name], ['path', 'sha256', 'version'], `resume ${name} toolchain`);
    if (!isAbsolute(value[name].path) || resolve(value[name].path) !== value[name].path
      || !HASH.test(value[name].sha256) || !value[name].version.startsWith(`${name} ${Q07_RUST_TOOLCHAIN} `)
      || realpathSync(value[name].path) !== value[name].path
      || sha256(readFileSync(value[name].path)) !== value[name].sha256) {
      fail(`resume ${name} toolchain identity is invalid`);
    }
  }
}

function assertResumeMachine(value, attemptId, testOnly) {
  exact(value, [
    'attemptId', 'cgroupV2', 'chainAuthenticated', 'final', 'hardware', 'localOnly',
    'orchestrationPins', 'platform', 'production', 'publishedMachine', 'q07Qualified', 'qualification',
    'releaseQualified', 'schema', 'toolchain',
  ], 'resume machine');
  exact(value.platform, ['architecture', 'cargo', 'node', 'platform', 'release', 'rustc', 'v8'], 'resume machine platform');
  exact(value.hardware, ['cpuModels', 'logicalCores', 'totalMemoryBytes'], 'resume machine hardware');
  assertResumeLabels(value, 'resume machine');
  assertOrchestrationPins(value.orchestrationPins, 'resume machine orchestration pins');
  assertResumeToolchain(value.toolchain, testOnly);
  if (value.schema !== `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/machine`
    || value.attemptId !== attemptId || !Array.isArray(value.hardware.cpuModels)
    || value.hardware.cpuModels.length === 0 || !Number.isSafeInteger(value.hardware.logicalCores)
    || value.hardware.logicalCores <= 0 || !Number.isSafeInteger(value.hardware.totalMemoryBytes)
    || value.hardware.totalMemoryBytes <= 0) {
    fail('resume machine is invalid');
  }
}

function resumePhaseRecord(selection, currentAttemptId) {
  return Object.freeze({
    receipt: selection.reference,
    reusedFromAttemptId: selection.receipt.attemptId === currentAttemptId ? null : selection.receipt.attemptId,
  });
}

function resumeArtifactRole(name, currentAttemptId) {
  if (name === 'source-set.json') return 'source-set';
  if (name === Q07_CORPUS_FILENAME) return 'corpus';
  if (name === resumeName(currentAttemptId, 'attempt.json')) return 'attempt';
  if (name === resumeName(currentAttemptId, 'machine.json')) return 'machine';
  if (name === resumeName(currentAttemptId, 'build.binary')) return 'build-snapshot';
  if (name === resumeName(currentAttemptId, 'run.json')) return 'run';
  return `history/${name}`;
}

function createResumeManifest(root, attemptId, orchestrationPins) {
  const artifacts = list(root).filter((name) => name !== RESUME_LEASE_FILENAME).map((name) => {
    if (name === 'manifest.json') fail('refusing to overwrite an existing manifest');
    const snapshot = resumeArtifactSnapshot(root, name, `bundle artifact ${name}`);
    return Object.freeze({ role: resumeArtifactRole(name, attemptId), ...stableReference(snapshot) });
  });
  return Object.freeze({
    schema: V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA,
    ...resumeLabels(),
    orchestrationPins,
    artifacts: Object.freeze(artifacts),
  });
}

async function resumeLifecycle({
  bundlePath,
  actionCount = V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS,
  executor = realResumeExecutor(),
  testOnly = false,
  orchestrationPins = null,
} = {}) {
  validActionCount(actionCount, testOnly);
  if (executor === null || Array.isArray(executor) || typeof executor !== 'object') fail('resume executor must be an object');
  const root = resolve(bundlePath);
  directDirectory(root, 'partial bundle root');
  const manifestPath = directChild(root, 'manifest.json', 'manifest');
  if (existsSync(manifestPath)) {
    const manifest = json(readFileSync(manifestPath), 'manifest');
    if (manifest.schema !== V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA) {
      fail('resume refuses an already sealed non-v2 bundle');
    }
    const verified = verifyQ07LocalLifecycleBundle(root);
    if (verified.testOnly !== testOnly || verified.actionCount !== String(actionCount)) {
      fail('sealed v2 bundle is incompatible with the requested resume mode');
    }
    return verified;
  }

  const pinnedRunner = testOnly
    ? normaliseOrchestrationPins(orchestrationPins ?? {
      gitCommit: '1'.repeat(40), gitTree: '2'.repeat(40), runnerSha256: '3'.repeat(64),
    })
    : assertLiveRunnerCheckout(orchestrationPins);
  const lease = acquireResumeLease(root);
  let leaseReleased = false;
  try {
  let state = inspectResumeDirectory(root);
  const sourceArtifact = originArtifact(state, 'source-set.json');
  const originMachineArtifact = originArtifact(state, 'machine.json');
  const corpusOrigin = originArtifact(state, Q07_CORPUS_FILENAME);
  const source = json(readFileSync(directChild(root, sourceArtifact.path, 'source set')), 'interrupted source set');
  const originMachine = json(readFileSync(directChild(root, originMachineArtifact.path, 'origin machine')), 'interrupted origin machine');
  assertOriginMachine(originMachine);
  await assertRecordedSourceCheckout(source);
  if (sourceArtifact.sha256 !== sha256(Buffer.from(canonicalJson(source), 'utf8'))
    || sourceArtifact.bytes !== Buffer.byteLength(canonicalJson(source), 'utf8')) {
    fail('interrupted source-set artifact differs from its canonical record');
  }
  const corpusPath = directChild(root, Q07_CORPUS_FILENAME, 'corpus');
  const corpus = stableFileSnapshot(corpusPath, 'preserved lifecycle corpus');
  compareStableSnapshot(corpus, corpusOrigin, 'preserved lifecycle corpus');
  const originPins = observedOriginPins(
    source,
    stableFileSnapshot(corpusPath, 'preserved lifecycle corpus line-count pin', { countLines: true }),
    sourceArtifact.sha256,
    testOnly,
  );

  if (state.attempts.length !== 0) {
    for (const prior of state.attempts) {
      if (prior.testOnly !== testOnly || prior.actionCount !== String(actionCount)
        || prior.sourceSetSha256 !== source.sourceSetSha256
        || canonicalJson(prior.sourceSet) !== canonicalJson(stableReference(sourceArtifact))
        || canonicalJson(prior.corpus) !== canonicalJson(corpus)
        || canonicalJson(prior.orchestrationPins) !== canonicalJson(pinnedRunner)
        || canonicalJson(prior.interruptedOrigin) !== canonicalJson(interruptedOriginRecord(originPins))) {
        fail('existing resume attempt is incompatible with this exact corpus/source resume');
      }
    }
  }

  const { attemptId, createdAtUnixMs } = newAttemptId(root);
  const attempt = Object.freeze({
    schema: `${V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA}/attempt`,
    attemptId,
    createdAtUnixMs,
    ...resumeLabels(),
    orchestrationPins: pinnedRunner,
    testOnly,
    actionCount: String(actionCount),
    sourceSet: stableReference(sourceArtifact),
    sourceSetSha256: source.sourceSetSha256,
    corpus,
    originArtifacts: state.originArtifacts,
    interruptedOrigin: interruptedOriginRecord(originPins),
  });
  const attemptArtifact = atomic(root, resumeName(attemptId, 'attempt.json'), Buffer.from(canonicalJson(attempt), 'utf8'));

  const toolchain = testOnly ? null : await exactPinnedResumeToolchain(source.sourceRoot);
  const machine = await resumeMachineRecord(attemptId, source.sourceRoot, toolchain, pinnedRunner);
  const machineArtifact = atomic(root, resumeName(attemptId, 'machine.json'), Buffer.from(canonicalJson(machine), 'utf8'));
  fsyncDirectory(root);

  const common = Object.freeze({ root, attemptId, executor, source, corpus, actionCount, testOnly, orchestrationPins: pinnedRunner, toolchain });
  const build = await selectResumePhase({ ...common, phase: 'build', dependencies: Object.freeze([]), jsResult: undefined, buildSnapshot: null });
  const jsVerifier = await selectResumePhase({ ...common, phase: 'js-verifier', dependencies: Object.freeze([]), jsResult: undefined, buildSnapshot: null });
  const buildSnapshot = testOnly ? null : build.result.snapshot;
  const rustDependencies = Object.freeze(testOnly
    ? [build.reference, jsVerifier.reference]
    : [build.reference, jsVerifier.reference, stableReference(buildSnapshot)]);
  const rustVerifier = await selectResumePhase({
    ...common,
    phase: 'rust-verifier',
    dependencies: rustDependencies,
    jsResult: jsVerifier.result,
    buildSnapshot,
  });
  await recheckResumeInvariants(source, corpusPath, corpus);

  const runRecord = Object.freeze({
    schema: V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA,
    attemptId,
    ...resumeLabels(),
    orchestrationPins: pinnedRunner,
    testOnly,
    actionCount: String(actionCount),
    attempt: attemptArtifact,
    sourceSet: stableReference(sourceArtifact),
    sourceSetSha256: source.sourceSetSha256,
    machine: machineArtifact,
    corpus: Object.freeze({
      artifact: stableReference(corpus),
      preservedIdentity: corpus.identity,
    }),
    interruptedOrigin: interruptedOriginRecord(originPins),
    resumePhases: Object.freeze({
      build: resumePhaseRecord(build, attemptId),
      jsVerifier: resumePhaseRecord(jsVerifier, attemptId),
      rustVerifier: resumePhaseRecord(rustVerifier, attemptId),
    }),
    wallMs: Object.freeze({
      generator: null,
      originalJsVerifier: null,
      originalRustVerifier: null,
      total: null,
      resumeBuild: build.receipt.wallMs,
      resumeJsVerifier: jsVerifier.receipt.wallMs,
      resumeRustVerifier: rustVerifier.receipt.wallMs,
    }),
  });
  atomic(root, resumeName(attemptId, 'run.json'), Buffer.from(canonicalJson(runRecord), 'utf8'));
  const manifest = createResumeManifest(root, attemptId, pinnedRunner);
  atomic(root, 'manifest.json', Buffer.from(canonicalJson(manifest), 'utf8'));
  fsyncDirectory(root);
  fsyncDirectory(dirname(root));
  lease.release();
  leaseReleased = true;
  return verifyQ07LocalLifecycleBundle(root);
  } finally {
    if (!leaseReleased) lease.release();
  }
}

/**
 * Public recovery path: it accepts only an existing partial bundle. The source
 * checkout and exact action count come from the pinned v1 origin and v2 policy.
 */
export async function resumeQ07LocalLifecycle(options = {}) {
  if (options === null || Array.isArray(options) || typeof options !== 'object') fail('public resume options must be an object');
  for (const forbidden of ['actionCount', 'executor', 'sourceRoot', 'testOnly']) {
    if (Object.hasOwn(options, forbidden)) fail(`public resumeQ07LocalLifecycle rejects injected ${forbidden}`);
  }
  for (const key of Object.keys(options)) if (!['bundlePath', 'runnerGitCommit', 'runnerGitTree', 'runnerSha256'].includes(key)) fail(`public resumeQ07LocalLifecycle rejects unknown ${key}`);
  if (typeof options.bundlePath !== 'string' || options.bundlePath.length === 0) fail('public resume requires bundlePath');
  return resumeLifecycle({
    bundlePath: options.bundlePath,
    actionCount: V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS,
    executor: realResumeExecutor(),
    testOnly: false,
    orchestrationPins: {
      gitCommit: options.runnerGitCommit,
      gitTree: options.runnerGitTree,
      runnerSha256: options.runnerSha256,
    },
  });
}

/** Explicit bounded state-machine seam; never accepted by the production CLI. */
export async function resumeQ07LocalLifecycleForTest(options = {}) {
  return resumeLifecycle({ ...options, testOnly: true });
}

/** A narrow diagnostic probe used by the mandatory rootless-systemd smoke gate. */
export async function inspectQ07UserSystemdForTest() {
  const result = await captureCommand('systemctl', ['--user', 'show-environment'], { cwd: process.cwd() });
  if (result.exitCode === 0 && result.signal === null && result.failure === null) {
    return Object.freeze({ available: true, reason: null });
  }
  const reason = result.failure
    ?? (result.stderr.toString('utf8').trim() || `systemctl exited ${result.signal ?? result.exitCode}`);
  return Object.freeze({ available: false, reason });
}

/** Real rootless-systemd smoke seam. The production resume path never calls the skip probe. */
export async function runQ07SystemdSmokeForTest({ directory } = {}) {
  const root = resolve(directory);
  directDirectory(root, 'systemd smoke directory');
  const capture = await runSystemdChild({
    sourceRoot: root,
    bundleRoot: root,
    executable: process.execPath,
    executableArgs: ['-e', 'setTimeout(() => process.stdout.write("q07-systemd-smoke\\\\n"), 750)'],
    maximumPolls: 200,
    pollMilliseconds: 20,
  });
  if (capture.failure !== null || capture.exitCode !== 0 || capture.stderr.length !== 0) {
    fail(`real user-systemd smoke failed: ${capture.failure ?? capture.stderr.toString('utf8')}`);
  }
  assertSystemdEvidence(capture.systemd, 'real user-systemd smoke evidence');
  return Object.freeze({ stdout: capture.stdout.toString('utf8'), systemd: capture.systemd });
}

function manifestReferenceByRole(manifest, role) {
  const entry = manifest.artifacts.find((artifact) => artifact.role === role);
  if (entry === undefined) fail(`v2 resume manifest lacks ${role}`);
  const { role: _ignored, ...reference } = entry;
  return Object.freeze(reference);
}

function manifestHasReference(manifest, reference) {
  return manifest.artifacts.some((entry) => {
    const { role: _ignored, ...candidate } = entry;
    return canonicalJson(candidate) === canonicalJson(reference);
  });
}

function assertResumeRunRecord(run, root, manifest) {
  exact(run, [
    'actionCount', 'attempt', 'attemptId', 'chainAuthenticated', 'corpus', 'final',
    'interruptedOrigin', 'localOnly', 'machine', 'production', 'publishedMachine',
    'orchestrationPins', 'q07Qualified', 'qualification', 'releaseQualified', 'resumePhases', 'schema',
    'sourceSet', 'sourceSetSha256', 'testOnly', 'wallMs',
  ], 'v2 resume run');
  assertResumeLabels(run, 'v2 resume run');
  assertOrchestrationPins(run.orchestrationPins, 'v2 resume run orchestration pins');
  if (run.schema !== V2_Q07_LOCAL_LIFECYCLE_RESUME_SCHEMA || !RESUME_ID.test(run.attemptId)
    || typeof run.testOnly !== 'boolean') fail('v2 resume run identity is invalid');
  const actionCount = Number(run.actionCount);
  validActionCount(actionCount, run.testOnly);
  if (String(actionCount) !== run.actionCount) fail('v2 resume actionCount is not canonical');
  plainArtifact(run.attempt, 'v2 resume attempt reference');
  plainArtifact(run.sourceSet, 'v2 resume source reference');
  plainArtifact(run.machine, 'v2 resume machine reference');
  exact(run.corpus, ['artifact', 'preservedIdentity'], 'v2 resume corpus');
  plainArtifact(run.corpus.artifact, 'v2 resume corpus artifact');
  assertStableIdentity(run.corpus.preservedIdentity, 'v2 resume corpus preserved identity');
  assertInterruptedOrigin(run.interruptedOrigin, 'v2 resume interrupted origin');
  exact(run.wallMs, [
    'generator', 'originalJsVerifier', 'originalRustVerifier', 'resumeBuild',
    'resumeJsVerifier', 'resumeRustVerifier', 'total',
  ], 'v2 resume wall times');
  if (run.wallMs.generator !== null || run.wallMs.originalJsVerifier !== null
    || run.wallMs.originalRustVerifier !== null || run.wallMs.total !== null) {
    fail('v2 resume run synthesizes lost or total wall time');
  }
  for (const key of ['resumeBuild', 'resumeJsVerifier', 'resumeRustVerifier']) {
    finiteDuration(run.wallMs[key], `v2 resume wallMs.${key}`);
  }
  exact(run.resumePhases, ['build', 'jsVerifier', 'rustVerifier'], 'v2 resume phases');
  for (const [field, phase] of [['build', 'build'], ['jsVerifier', 'js-verifier'], ['rustVerifier', 'rust-verifier']]) {
    const selection = run.resumePhases[field];
    exact(selection, ['receipt', 'reusedFromAttemptId'], `v2 resume phase ${field}`);
    plainArtifact(selection.receipt, `v2 resume phase ${field} receipt`);
    if (selection.reusedFromAttemptId !== null && !RESUME_ID.test(selection.reusedFromAttemptId)) {
      fail(`v2 resume phase ${field} reuse identity is invalid`);
    }
    const receiptName = selection.receipt.path;
    const parsed = parseResumeName(receiptName);
    if (parsed === null || parsed.suffix !== `${phase}.receipt.json`
      || selection.reusedFromAttemptId !== (parsed.attemptId === run.attemptId ? null : parsed.attemptId)
      || !manifestHasReference(manifest, selection.receipt)) {
      fail(`v2 resume phase ${field} receipt reference is invalid`);
    }
  }
  return Object.freeze({ actionCount, testOnly: run.testOnly });
}

function verifyResumeBundle(root, manifest) {
  exact(manifest, [
    'artifacts', 'chainAuthenticated', 'final', 'localOnly', 'production', 'publishedMachine',
    'orchestrationPins', 'q07Qualified', 'qualification', 'releaseQualified', 'schema',
  ], 'v2 resume manifest');
  assertResumeLabels(manifest, 'v2 resume manifest');
  assertOrchestrationPins(manifest.orchestrationPins, 'v2 resume manifest orchestration pins');
  if (manifest.schema !== V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA
    || !Array.isArray(manifest.artifacts) || manifest.artifacts.length < 10) {
    fail('v2 resume manifest identity is invalid');
  }
  const names = new Set(['manifest.json']);
  const roles = new Set();
  for (const entry of manifest.artifacts) {
    exact(entry, ['bytes', 'path', 'role', 'sha256'], 'v2 resume manifest artifact');
    plainArtifact({ path: entry.path, bytes: entry.bytes, sha256: entry.sha256 }, 'v2 resume manifest artifact');
    if (typeof entry.role !== 'string' || entry.role.length === 0 || roles.has(entry.role) || names.has(entry.path)) {
      fail('v2 resume manifest artifact is ambiguous');
    }
    const current = resumeArtifactSnapshot(root, entry.path, `v2 resume artifact ${entry.path}`);
    if (canonicalJson(stableReference(current)) !== canonicalJson({ path: entry.path, bytes: entry.bytes, sha256: entry.sha256 })) {
      fail(`v2 resume artifact drifted: ${entry.path}`);
    }
    names.add(entry.path);
    roles.add(entry.role);
  }
  if (canonicalJson(list(root)) !== canonicalJson([...names].sort())) {
    fail('v2 resume bundle has missing or unreferenced artifacts');
  }
  for (const role of ['source-set', 'corpus', 'attempt', 'machine', 'run']) {
    if (!roles.has(role)) fail(`v2 resume manifest lacks ${role}`);
  }

  const runReference = manifestReferenceByRole(manifest, 'run');
  const run = json(readFileSync(directChild(root, runReference.path, 'v2 resume run')), 'v2 resume run');
  const { actionCount, testOnly } = assertResumeRunRecord(run, root, manifest);
  for (const entry of manifest.artifacts) {
    if (entry.role !== resumeArtifactRole(entry.path, run.attemptId)) {
      fail(`v2 resume manifest role does not match artifact history: ${entry.path}`);
    }
  }
  if (runReference.path !== resumeName(run.attemptId, 'run.json')
    || canonicalJson(run.attempt) !== canonicalJson(manifestReferenceByRole(manifest, 'attempt'))
    || canonicalJson(run.machine) !== canonicalJson(manifestReferenceByRole(manifest, 'machine'))
    || canonicalJson(run.sourceSet) !== canonicalJson(manifestReferenceByRole(manifest, 'source-set'))
    || canonicalJson(run.corpus.artifact) !== canonicalJson(manifestReferenceByRole(manifest, 'corpus'))) {
    fail('v2 resume run does not bind its selected manifest artifacts');
  }
  if (canonicalJson(run.orchestrationPins) !== canonicalJson(manifest.orchestrationPins)) {
    fail('v2 resume manifest runner pins differ from the selected run');
  }

  const state = inspectResumeDirectory(root);
  const source = json(readFileSync(directChild(root, run.sourceSet.path, 'source set')), 'v2 resume source set');
  assertRecordedSourceCheckoutSync(source);
  if (run.sourceSetSha256 !== source.sourceSetSha256) fail('v2 resume source-set hash differs');
  const corpus = stableFileSnapshot(directChild(root, run.corpus.artifact.path, 'corpus'), 'v2 resume preserved corpus');
  if (canonicalJson(stableReference(corpus)) !== canonicalJson(run.corpus.artifact)
    || canonicalJson(corpus.identity) !== canonicalJson(run.corpus.preservedIdentity)) {
    fail('v2 resume corpus inode/size/mtime/ctime/hash drifted');
  }
  const originPins = observedOriginPins(
    source,
    stableFileSnapshot(directChild(root, run.corpus.artifact.path, 'corpus'), 'v2 resume corpus line-count pin', { countLines: true }),
    run.sourceSet.sha256,
    testOnly,
  );
  if (canonicalJson(run.interruptedOrigin.originPins) !== canonicalJson(originPins)) {
    fail('v2 resume run origin pins differ from the independently checked corpus/source pins');
  }
  const firstAttempt = state.attempts[0];
  const currentAttempt = state.attempts.find((entry) => entry.attemptId === run.attemptId);
  if (currentAttempt === undefined || canonicalJson(currentAttempt.interruptedOrigin) !== canonicalJson(run.interruptedOrigin)
    || currentAttempt.testOnly !== testOnly || currentAttempt.actionCount !== String(actionCount)
    || canonicalJson(currentAttempt.sourceSet) !== canonicalJson(run.sourceSet)
    || currentAttempt.sourceSetSha256 !== source.sourceSetSha256
    || canonicalJson(currentAttempt.corpus) !== canonicalJson(corpus)
    || canonicalJson(currentAttempt.orchestrationPins) !== canonicalJson(run.orchestrationPins)
    || canonicalJson(firstAttempt.originArtifacts) !== canonicalJson(currentAttempt.originArtifacts)) {
    fail('v2 resume run and immutable attempt origin disagree');
  }
  for (const attempt of state.attempts) {
    if (attempt.testOnly !== testOnly || attempt.actionCount !== String(actionCount)
      || canonicalJson(attempt.sourceSet) !== canonicalJson(run.sourceSet)
      || attempt.sourceSetSha256 !== source.sourceSetSha256
      || canonicalJson(attempt.corpus) !== canonicalJson(corpus)
      || canonicalJson(attempt.orchestrationPins) !== canonicalJson(run.orchestrationPins)
      || canonicalJson(attempt.interruptedOrigin) !== canonicalJson(run.interruptedOrigin)
      || canonicalJson(attempt.originArtifacts) !== canonicalJson(firstAttempt.originArtifacts)) {
      fail('v2 resume history contains an incompatible attempt');
    }
  }
  const machine = json(readFileSync(directChild(root, run.machine.path, 'resume machine')), 'resume machine');
  assertResumeMachine(machine, run.attemptId, testOnly);
  if (canonicalJson(machine.orchestrationPins) !== canonicalJson(run.orchestrationPins)) {
    fail('v2 resume machine runner pins differ from the selected run');
  }
  if (!testOnly && (!machine.platform.cargo.startsWith(`cargo ${Q07_RUST_TOOLCHAIN} `)
    || !machine.platform.rustc.startsWith(`rustc ${Q07_RUST_TOOLCHAIN} `))) {
    fail('v2 resume machine does not bind the pinned Rust toolchain');
  }

  const buildReceipt = readReceipt(root, run.resumePhases.build.receipt.path);
  const build = validateCompletedReceipt({
    root,
    receipt: buildReceipt,
    expectedPhase: 'build',
    source,
    corpus,
    actionCount,
    testOnly,
    dependencies: Object.freeze([]),
    jsResult: undefined,
    orchestrationPins: run.orchestrationPins,
    toolchain: machine.toolchain,
    buildSnapshot: null,
  });
  if (build === null || build.receipt.wallMs !== run.wallMs.resumeBuild) fail('selected resume build receipt is invalid');
  if (!testOnly) {
    const snapshotReference = stableReference(build.result.snapshot);
    if (!manifestHasReference(manifest, snapshotReference)) {
      fail('v2 resume manifest does not bind the selected immutable build snapshot');
    }
  }
  const jsReceipt = readReceipt(root, run.resumePhases.jsVerifier.receipt.path);
  const js = validateCompletedReceipt({
    root,
    receipt: jsReceipt,
    expectedPhase: 'js-verifier',
    source,
    corpus,
    actionCount,
    testOnly,
    dependencies: Object.freeze([]),
    jsResult: undefined,
    orchestrationPins: run.orchestrationPins,
    toolchain: machine.toolchain,
    buildSnapshot: null,
  });
  if (js === null || js.receipt.wallMs !== run.wallMs.resumeJsVerifier) fail('selected resume JS receipt is invalid');
  const rustReceipt = readReceipt(root, run.resumePhases.rustVerifier.receipt.path);
  const rust = validateCompletedReceipt({
    root,
    receipt: rustReceipt,
    expectedPhase: 'rust-verifier',
    source,
    corpus,
    actionCount,
    testOnly,
    dependencies: Object.freeze(testOnly
      ? [run.resumePhases.build.receipt, run.resumePhases.jsVerifier.receipt]
      : [run.resumePhases.build.receipt, run.resumePhases.jsVerifier.receipt, stableReference(build.result.snapshot)]),
    jsResult: js.result,
    orchestrationPins: run.orchestrationPins,
    toolchain: machine.toolchain,
    buildSnapshot: testOnly ? null : build.result.snapshot,
  });
  if (rust === null || rust.receipt.wallMs !== run.wallMs.resumeRustVerifier) fail('selected resume Rust receipt is invalid');
  return Object.freeze({
    schema: `${V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA}/verification`,
    bundlePath: root,
    status: 'verified-resumed-local-only',
    actionCount: String(actionCount),
    testOnly,
    ...resumeLabels(),
  });
}
export function verifyQ07LocalLifecycleBundle(bundlePath) {
  const root = resolve(bundlePath); directDirectory(root, 'bundle root'); const manifestPath = directChild(root, 'manifest.json', 'manifest'); own(manifestPath, 'manifest'); const manifest = json(readFileSync(manifestPath), 'manifest');
  if (manifest.schema === V2_Q07_LOCAL_LIFECYCLE_RESUME_MANIFEST_SCHEMA) return verifyResumeBundle(root, manifest);
  exact(manifest, ['artifacts', 'chainAuthenticated', 'localOnly', 'q07Qualified', 'schema'], 'manifest'); if (manifest.schema !== V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA || manifest.localOnly !== true || manifest.chainAuthenticated !== false || manifest.q07Qualified !== false || !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 7) fail('manifest local-only identity is invalid');
  const names = new Set(['manifest.json']); const roles = new Set(); for (const item of manifest.artifacts) { exact(item, ['bytes', 'path', 'role', 'sha256'], 'manifest artifact'); if (typeof item.role !== 'string' || roles.has(item.role) || names.has(item.path) || typeof item.path !== 'string' || basename(item.path) !== item.path || !Number.isSafeInteger(item.bytes) || item.bytes < 0 || !HASH.test(item.sha256)) fail('manifest artifact is ambiguous'); const path = directChild(root, item.path, 'manifest artifact'); const s = own(path, `artifact ${item.role}`); const bytes = readFileSync(path); if (s.size !== item.bytes || bytes.length !== item.bytes || sha256(bytes) !== item.sha256) fail(`artifact ${item.role} hash differs`); names.add(item.path); roles.add(item.role); }
  if (canonicalJson(list(root)) !== canonicalJson([...names].sort())) fail('bundle has missing or unreferenced files'); for (const required of ['source-set', 'machine', 'corpus', 'generator-result', 'js-verifier-result', 'rust-verifier-result', 'run']) if (!roles.has(required)) fail(`manifest lacks ${required}`);
  const artifact = (role) => manifest.artifacts.find((entry) => entry.role === role);
  const reference = (role) => { const { role: _ignored, ...entry } = artifact(role); return entry; };
  const source = json(readFileSync(directChild(root, artifact('source-set').path, 'source')), 'source set');
  const machine = json(readFileSync(directChild(root, artifact('machine').path, 'machine')), 'machine');
  assertSourceSet(source);
  exact(machine, ['cgroupV2', 'chainAuthenticated', 'hardware', 'platform', 'q07Qualified', 'qualification', 'schema'], 'machine');
  exact(machine.platform, ['architecture', 'cargo', 'node', 'platform', 'release', 'rustc', 'v8'], 'machine platform');
  exact(machine.hardware, ['cpuModels', 'logicalCores', 'totalMemoryBytes'], 'machine hardware');
  if (machine.schema !== `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/machine` || machine.chainAuthenticated !== false || machine.q07Qualified !== false || machine.qualification !== 'local-non-chain-not-published-machine-qualification' || typeof machine.platform.node !== 'string' || typeof machine.platform.cargo !== 'string' || typeof machine.platform.rustc !== 'string' || !Array.isArray(machine.hardware.cpuModels) || machine.hardware.cpuModels.length === 0 || !machine.hardware.cpuModels.every((model) => typeof model === 'string' && model.length > 0) || !Number.isSafeInteger(machine.hardware.logicalCores) || machine.hardware.logicalCores <= 0 || !Number.isSafeInteger(machine.hardware.totalMemoryBytes) || machine.hardware.totalMemoryBytes <= 0 || machine.cgroupV2 === null || Array.isArray(machine.cgroupV2) || typeof machine.cgroupV2 !== 'object') fail('machine manifest is not self-consistent');
  const corpusSha = artifact('corpus').sha256;
  const runRecord = json(readFileSync(directChild(root, artifact('run').path, 'run')), 'run');
  exact(runRecord, ['actionCount', 'build', 'cgroupV2', 'chainAuthenticated', 'childCgroup', 'commands', 'corpus', 'generator', 'jsVerifier', 'localOnly', 'machine', 'q07Qualified', 'qualification', 'rustVerifier', 'schema', 'sourceSet', 'sourceSetSha256', 'testOnly', 'wallMs'], 'run');
  if (typeof runRecord.testOnly !== 'boolean') fail('run testOnly classification must be boolean');
  const testOnly = runRecord.testOnly;
  const expectedQualification = testOnly ? 'test-only-non-chain-local-run' : 'non-chain-local-run-not-final-or-published-machine-qualification';
  const matches = (field, role) => canonicalJson(runRecord[field]) === canonicalJson(reference(role));
  if (runRecord.schema !== V2_Q07_LOCAL_LIFECYCLE_SCHEMA || runRecord.localOnly !== true || runRecord.chainAuthenticated !== false || runRecord.q07Qualified !== false || runRecord.qualification !== expectedQualification || runRecord.sourceSetSha256 !== source.sourceSetSha256 || !matches('corpus', 'corpus') || !matches('sourceSet', 'source-set') || !matches('machine', 'machine') || !matches('generator', 'generator-result') || !matches('jsVerifier', 'js-verifier-result') || !matches('rustVerifier', 'rust-verifier-result')) fail('run record local-only identity is invalid');
  const actionCount = Number(runRecord.actionCount);
  if (!Number.isSafeInteger(actionCount) || String(actionCount) !== runRecord.actionCount || (testOnly ? actionCount < 3 || actionCount > 64 : actionCount !== V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS)) fail('run action count classification is invalid');
  if (runRecord.cgroupV2 === null || Array.isArray(runRecord.cgroupV2) || typeof runRecord.cgroupV2 !== 'object' || runRecord.cgroupV2.scope !== 'runner-cgroup-observation-not-child-private-peak') fail('runner cgroup observation is invalid');
  if (testOnly) {
    exact(runRecord.build, ['status'], 'test-only build');
    exact(runRecord.childCgroup, ['available', 'reason'], 'test-only child cgroup');
    exact(runRecord.wallMs, ['generator', 'jsVerifier', 'rustVerifier', 'total'], 'test-only wall times');
    for (const key of ['generator', 'jsVerifier', 'rustVerifier', 'total']) finiteDuration(runRecord.wallMs[key], `wallMs.${key}`);
    if (runRecord.build.status !== 'test-only-not-built' || runRecord.childCgroup.available !== false || runRecord.childCgroup.reason !== 'test-only-no-benchmark' || !Array.isArray(runRecord.commands)) fail('test-only execution provenance is invalid');
  } else {
    assertRealRunProvenance(runRecord, source, machine, root);
  }
  assertIdentity(json(readFileSync(directChild(root, artifact('generator-result').path, 'generator')), 'generator'), 'generator result', actionCount, corpusSha, testOnly);
  const js = json(readFileSync(directChild(root, artifact('js-verifier-result').path, 'js')), 'JS verifier');
  assertIdentity(js, 'JS verifier result', actionCount, corpusSha, testOnly);
  assertRust(json(readFileSync(directChild(root, artifact('rust-verifier-result').path, 'rust')), 'Rust verifier'), actionCount, js, testOnly);
  return Object.freeze({ schema: `${V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA}/verification`, bundlePath: root, status: 'verified-local-only', actionCount: runRecord.actionCount, testOnly, chainAuthenticated: false, q07Qualified: false, qualification: testOnly ? 'test-only-non-chain-local-run' : 'non-chain-local-run-not-final-or-published-machine-qualification' });
}
export function parseQ07LocalLifecycleArguments(argv, cwd = process.cwd()) {
  if (!Array.isArray(argv)) {
    fail('usage: v2-q07-local-lifecycle-run.mjs --output-directory <existing-mode-0700-directory> | --resume <existing-partial-bundle> --runner-git-commit <40-hex> --runner-git-tree <40-hex> --runner-file-sha256 <64-hex> | --verify <bundle>');
  }
  if (argv.length === 2 && argv[0] === '--verify' && typeof argv[1] === 'string' && argv[1].length !== 0 && !argv[1].startsWith('--')) {
    return Object.freeze({ mode: 'verify', bundlePath: resolve(cwd, argv[1]) });
  }
  if (argv.length === 2 && argv[0] === '--output-directory' && typeof argv[1] === 'string' && argv[1].length !== 0 && !argv[1].startsWith('--')) {
    return Object.freeze({ mode: 'run', outputDirectory: resolve(cwd, argv[1]), sourceRoot: resolve(cwd) });
  }
  if (argv.length === 8 && argv[0] === '--resume' && argv[2] === '--runner-git-commit'
    && argv[4] === '--runner-git-tree' && argv[6] === '--runner-file-sha256'
    && typeof argv[1] === 'string' && argv[1].length !== 0 && !argv[1].startsWith('--')
    && GIT.test(argv[3]) && GIT.test(argv[5]) && HASH.test(argv[7])) {
    return Object.freeze({
      mode: 'resume', bundlePath: resolve(cwd, argv[1]), runnerGitCommit: argv[3],
      runnerGitTree: argv[5], runnerSha256: argv[7],
    });
  }
  fail('usage: v2-q07-local-lifecycle-run.mjs --output-directory <existing-mode-0700-directory> | --resume <existing-partial-bundle> --runner-git-commit <40-hex> --runner-git-tree <40-hex> --runner-file-sha256 <64-hex> | --verify <bundle>');
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const args = parseQ07LocalLifecycleArguments(process.argv.slice(2));
    const result = args.mode === 'verify'
      ? verifyQ07LocalLifecycleBundle(args.bundlePath)
      : args.mode === 'resume'
        ? await resumeQ07LocalLifecycle({
          bundlePath: args.bundlePath,
          runnerGitCommit: args.runnerGitCommit,
          runnerGitTree: args.runnerGitTree,
          runnerSha256: args.runnerSha256,
        })
        : await runQ07LocalLifecycle({ outputDirectory: args.outputDirectory, sourceRoot: args.sourceRoot });
    process.stdout.write(`${canonicalJson(result)}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
