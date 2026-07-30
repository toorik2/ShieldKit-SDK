#!/usr/bin/env node

/*
 * Local-only Q07 lifecycle evidence. This deliberately produces a sealed
 * replay bundle, not chain evidence or a published-machine qualification.
 */
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, createReadStream, existsSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, realpathSync, renameSync, statSync,
  unlinkSync, writeSync,
} from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { canonicalJson, parseStrictJson } from '../packages/profile/load.mjs';

export const V2_Q07_LOCAL_LIFECYCLE_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-run/v1';
export const V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA = 'shieldkit-v2-direct/q07-local-lifecycle-bundle/v1';
export const V2_Q07_LOCAL_LIFECYCLE_EXACT_ACTIONS = 100_000;
const Q07_RUST_TOOLCHAIN = '1.97.1';
const HASH = /^[0-9a-f]{64}$/u;
const GIT = /^[0-9a-f]{40}$/u;
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
  try { fd = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0), 0o600); chmodSync(temporary, 0o600); writeFully(fd, bytes); fsyncSync(fd); closeSync(fd); fd = undefined; own(temporary, 'temporary artifact'); if (existsSync(path)) fail(`refusing to overwrite ${path}`); renameSync(temporary, path); own(path, 'artifact'); return Object.freeze({ path: name, bytes: bytes.length, sha256: sha256(bytes) }); }
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
    if (/^(?:CARGO_TARGET_DIR|CARGO_ENCODED_RUSTFLAGS|MISE_RUST_VERSION|RUSTFLAGS|RUSTUP_TOOLCHAIN|RUSTDOCFLAGS|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER)$/u.test(key)) continue;
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
async function machineManifest(sourceRoot, toolchain) { return Object.freeze({ schema: `${V2_Q07_LOCAL_LIFECYCLE_SCHEMA}/machine`, platform: { platform: process.platform, architecture: process.arch, release: os.release(), node: process.version, v8: process.versions.v8, cargo: toolchain.cargo, rustc: toolchain.rustc }, hardware: { cpuModels: [...new Set(os.cpus().map((cpu) => cpu.model))].sort(), logicalCores: os.availableParallelism(), totalMemoryBytes: os.totalmem() }, cgroupV2: cgroupV2(), chainAuthenticated: false, q07Qualified: false, qualification: 'local-non-chain-not-published-machine-qualification' }); }
function binarySnapshot(path, label) { const s = lstatSync(path); if (s.isSymbolicLink() || !s.isFile() || s.nlink !== 1 || (typeof process.getuid === 'function' && s.uid !== process.getuid()) || realpathSync(path) !== path) fail(`${label} must be a direct user-owned single-link regular file`); return Object.freeze({ path, bytes: s.size, sha256: sha256(readFileSync(path)) }); }
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
    if (canonicalJson(value.actionCounts) !== canonicalJson(expectedCounts) || value.schema !== 'shieldkit-v2-direct/q07-non-chain-lifecycle-corpus-result/v1' || value.status !== 'verified' || value.authority !== 'non-chain-lifecycle-corpus' || !HASH.test(value.profileId) || !HASH.test(value.instanceId) || !HASH.test(value.terminalNoteRoot) || !HASH.test(value.terminalNullifierRoot) || !/^[0-9a-f]{256}$/u.test(value.terminalStateHex) || value.terminalStateSha256 !== sha256(Buffer.from(value.terminalStateHex, 'hex')) || value.terminalStateHex.slice(0, 64) !== value.profileId || value.terminalStateHex.slice(64, 128) !== value.terminalNoteRoot || value.terminalStateHex.slice(128, 192) !== value.terminalNullifierRoot) fail('Rust verifier result schema, terminal roots, or lifecycle counts are invalid');
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
  exact(value, ['bytes', 'path', 'sha256'], label);
  if (value.path !== expectedPath || !Number.isSafeInteger(value.bytes) || value.bytes <= 0 || !HASH.test(value.sha256)) fail(`${label} is invalid`);
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
export function verifyQ07LocalLifecycleBundle(bundlePath) {
  const root = resolve(bundlePath); directDirectory(root, 'bundle root'); const manifestPath = directChild(root, 'manifest.json', 'manifest'); own(manifestPath, 'manifest'); const manifest = json(readFileSync(manifestPath), 'manifest'); exact(manifest, ['artifacts', 'chainAuthenticated', 'localOnly', 'q07Qualified', 'schema'], 'manifest'); if (manifest.schema !== V2_Q07_LOCAL_LIFECYCLE_MANIFEST_SCHEMA || manifest.localOnly !== true || manifest.chainAuthenticated !== false || manifest.q07Qualified !== false || !Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 7) fail('manifest local-only identity is invalid');
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
export function parseQ07LocalLifecycleArguments(argv, cwd = process.cwd()) { if (!Array.isArray(argv) || argv.length !== 2 || !['--output-directory', '--verify'].includes(argv[0]) || typeof argv[1] !== 'string' || argv[1].startsWith('--')) fail('usage: v2-q07-local-lifecycle-run.mjs --output-directory <existing-mode-0700-directory> | --verify <bundle>'); return Object.freeze(argv[0] === '--verify' ? { mode: 'verify', bundlePath: resolve(cwd, argv[1]) } : { mode: 'run', outputDirectory: resolve(cwd, argv[1]), sourceRoot: resolve(cwd) }); }
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) { try { const args = parseQ07LocalLifecycleArguments(process.argv.slice(2)); const result = args.mode === 'verify' ? verifyQ07LocalLifecycleBundle(args.bundlePath) : await runQ07LocalLifecycle(args); process.stdout.write(`${canonicalJson(result)}\n`); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`); process.exitCode = 1; } }
