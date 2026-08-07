#!/usr/bin/env node
/** Build a pinned local rapidsnark binary. This setup path is never an action-time fallback. */
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { availableParallelism } from 'node:os';
import { chmod, copyFile, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';

export const V2_NATIVE_PROVER_MANIFEST_SCHEMA = 'shieldkit-v2-native-rapidsnark-manifest-v1';
export const RAPIDSNARK_REPOSITORY = 'https://github.com/iden3/rapidsnark.git';
export const RAPIDSNARK_COMMIT = '81eddf1a536d26497b237c0b8a04fe90baf7e439';
export const RAPIDSNARK_SUBMODULES = Object.freeze([
  '839785075f90a060a5ee5697c6c6e27f85aa35ee depends/circom_runtime',
  'aa90166dc4c5a075b835a398e15cc1e06ac90e95 depends/ffiasm',
  '350ff4f7ced7c4117eae2fb93df02823c8021fcb depends/json',
  'ae0da38cf1c26c3321b19a512e2faffb80ae9867 depends/pistache',
  'c99458533a9b4c743ed51537e25989ea55944908 depends/pistache/third-party/googletest',
  'f54b0e47a08782a6131cc3d60f94d038fa6e0a51 depends/pistache/third-party/rapidjson',
  '0a439623f75c029912728d80cb7f1b8b48739ca4 depends/pistache/third-party/rapidjson/thirdparty/gtest',
]);
export const GMP_VERSION = '6.3.0';
export const GMP_SHA256 = 'a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898';
const HASH = /^[0-9a-f]{64}$/u; const GIT = /^[0-9a-f]{40}$/u;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const fail = (m) => { throw new Error(`V2_NATIVE_PROVER_SETUP_FAILED: ${m}`); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const OUTPUT_TAIL_BYTES = 64 * 1024;
const LEGACY_OUTPUT_KILL_BYTES = 1024 * 1024;
const stable = async (filename, label) => { const s = await lstat(filename); if (!s.isFile() || s.isSymbolicLink() || await realpath(filename) !== filename) fail(`${label} is not a regular non-symlink file`); const bytes = await readFile(filename); const after = await lstat(filename); if (s.dev !== after.dev || s.ino !== after.ino || s.size !== after.size) fail(`${label} changed while hashing`); return Object.freeze({ bytes: bytes.length, sha256: sha256(bytes) }); };
const exact = (v, keys, label) => { if (v === null || Array.isArray(v) || typeof v !== 'object') fail(`${label} must be an object`); const a = Object.keys(v).sort(); const e = [...keys].sort(); if (a.length !== e.length || a.some((x, i) => x !== e[i])) fail(`${label} has missing or unknown properties`); return v; };
export function assertV2NativeProverManifest(value) { exact(value, ['binary', 'build', 'gmp', 'schema', 'source', 'toolchain'], 'native prover manifest'); if (value.schema !== V2_NATIVE_PROVER_MANIFEST_SCHEMA) fail('unsupported native prover manifest schema'); exact(value.source, ['commit', 'repository', 'submodules'], 'native prover manifest.source'); if (value.source.repository !== RAPIDSNARK_REPOSITORY || value.source.commit !== RAPIDSNARK_COMMIT || !Array.isArray(value.source.submodules) || value.source.submodules.length !== RAPIDSNARK_SUBMODULES.length || value.source.submodules.some((x, i) => x !== RAPIDSNARK_SUBMODULES[i])) fail('native prover source pin differs'); exact(value.gmp, ['archiveSha256', 'staticLibrarySha256', 'version'], 'native prover manifest.gmp'); if (value.gmp.version !== GMP_VERSION || value.gmp.archiveSha256 !== GMP_SHA256 || !HASH.test(value.gmp.staticLibrarySha256)) fail('native prover GMP pin differs'); exact(value.build, ['cxxFlagsRelease', 'nproc', 'sourceTreeUnchanged', 'useAsm', 'useOpenmp', 'wallMs'], 'native prover manifest.build'); if (value.build.useAsm !== false || value.build.useOpenmp !== true || value.build.sourceTreeUnchanged !== true || value.build.cxxFlagsRelease !== '-O3 -DNDEBUG -include cstdint' || !Number.isSafeInteger(value.build.nproc) || value.build.nproc < 1 || !Number.isSafeInteger(value.build.wallMs) || value.build.wallMs < 1) fail('native prover build policy differs'); exact(value.binary, ['bytes', 'path', 'sha256'], 'native prover manifest.binary'); if (value.binary.path !== 'bin/prover' || !Number.isSafeInteger(value.binary.bytes) || value.binary.bytes < 1 || !HASH.test(value.binary.sha256)) fail('native prover binary record is invalid'); exact(value.toolchain, ['cmake', 'compiler', 'node', 'platform'], 'native prover manifest.toolchain'); return Object.freeze(JSON.parse(JSON.stringify(value))); }
export function boundedOutputTail(tail, chunk, maximum = OUTPUT_TAIL_BYTES) { if (!Buffer.isBuffer(tail) || !Buffer.isBuffer(chunk) || !Number.isSafeInteger(maximum) || maximum < 1) fail('bounded output tail arguments are invalid'); const joined = Buffer.concat([tail, chunk]); return joined.length <= maximum ? joined : joined.subarray(joined.length - maximum); }
const progress = (phase, command, args, started, details = {}) => process.stderr.write(`SHIELDKIT_NATIVE_PROVER_SETUP_PROGRESS ${JSON.stringify({ phase, command: path.basename(command), argumentCount: args.length, elapsedMs: Date.now() - started, nodeRssBytes: process.memoryUsage().rss, ...details })}\n`);
function run(command, args, { cwd, env = {} } = {}) { return new Promise((resolve, reject) => { const started = Date.now(); progress('start', command, args, started); const child = spawn(command, args, { cwd, shell: false, env: { LANG: 'C', LC_ALL: 'C', PATH: process.env.PATH ?? '/usr/bin:/bin', TZ: 'UTC', ...env }, stdio: ['ignore', 'pipe', 'pipe'] }); let stdout = Buffer.alloc(0); let stderr = Buffer.alloc(0); let stdoutBytes = 0; let stderrBytes = 0; let legacyCapReported = false; child.stdout.on('data', (chunk) => { stdoutBytes += chunk.length; stdout = boundedOutputTail(stdout, chunk); if (!legacyCapReported && stdoutBytes > LEGACY_OUTPUT_KILL_BYTES) { legacyCapReported = true; progress('legacy-output-cap-crossed', command, args, started, { stream: 'stdout', streamBytes: stdoutBytes, setupKillReason: null }); } }); child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; stderr = boundedOutputTail(stderr, chunk); if (!legacyCapReported && stderrBytes > LEGACY_OUTPUT_KILL_BYTES) { legacyCapReported = true; progress('legacy-output-cap-crossed', command, args, started, { stream: 'stderr', streamBytes: stderrBytes, setupKillReason: null }); } }); child.once('error', (error) => { progress('error', command, args, started, { setupKillReason: null, error: error.message, stderrTailBytes: stderr.length, stdoutTailBytes: stdout.length }); reject(error); }); child.once('close', (code, signal) => { const details = { setupKillReason: null, stderrBytes, stderrTailBytes: stderr.length, stdoutBytes, stdoutTailBytes: stdout.length }; progress(code === 0 && signal === null ? 'complete' : 'failed', command, args, started, details); if (code === 0 && signal === null) resolve(stdout.toString('utf8')); else reject(new Error(`${command} ${args.join(' ')} failed (${signal ?? code}): ${stderr.toString('utf8').slice(-4096)}`)); }); }); }
async function version(command, args = ['--version']) { return (await run(command, args)).split('\n')[0]; }
async function privateParent(output) { const parent = path.dirname(output); const s = await lstat(parent).catch(() => fail('output parent does not exist')); if (!s.isDirectory() || s.isSymbolicLink() || await realpath(parent) !== parent || (s.mode & 0o077) !== 0) fail('output parent must be a private non-symlink directory'); if (await lstat(output).then(() => true, () => false)) fail('output directory must not already exist'); return parent; }
async function fsyncDirectory(directory) { const handle = await open(directory, 'r'); try { await handle.sync(); } finally { await handle.close(); } }

/** Write the loader-consumed installation manifest as exact durable JCS bytes. */
export async function writeV2NativeProverManifest(filename, value) {
  const target = path.resolve(filename);
  const manifest = assertV2NativeProverManifest(value);
  const bytes = Buffer.from(canonicalizeJcs(manifest), 'utf8');
  const temporary = path.join(path.dirname(target), `.${path.basename(target)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close(); handle = undefined;
    await rename(temporary, target);
    await chmod(target, 0o600);
    await fsyncDirectory(path.dirname(target));
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

export async function setupV2NativeProver({ outputDirectory, nproc = availableParallelism() }) {
  const started = Date.now(); if (typeof outputDirectory !== 'string' || !path.isAbsolute(outputDirectory) || path.normalize(outputDirectory) !== outputDirectory || !Number.isSafeInteger(nproc) || nproc < 1) fail('outputDirectory and nproc are invalid'); const parent = await privateParent(outputDirectory); const work = await mkdtemp(path.join(parent, '.shieldkit-v2-native-build-')); const stage = await mkdtemp(path.join(parent, '.shieldkit-v2-native-stage-')); await chmod(work, 0o700); await chmod(stage, 0o700);
  try { const source = path.join(work, 'rapidsnark'); await run('/usr/bin/git', ['clone', '--recurse-submodules', RAPIDSNARK_REPOSITORY, source]); await run('/usr/bin/git', ['-C', source, 'checkout', '--detach', RAPIDSNARK_COMMIT]); await run('/usr/bin/git', ['-C', source, 'submodule', 'update', '--init', '--recursive']); const commit = (await run('/usr/bin/git', ['-C', source, 'rev-parse', 'HEAD'])).trim(); if (commit !== RAPIDSNARK_COMMIT) fail('rapidsnark commit pin is unavailable'); const submodules = (await run('/usr/bin/git', ['-C', source, 'submodule', 'status', '--recursive'])).trim().split('\n').filter(Boolean).map((x) => { const m = /^[+\- ]?([0-9a-f]{40}) ([^ ]+)/u.exec(x); return m === null ? '' : `${m[1]} ${m[2]}`; }); if (submodules.length !== RAPIDSNARK_SUBMODULES.length || submodules.some((x, i) => x !== RAPIDSNARK_SUBMODULES[i])) fail('rapidsnark submodule pin differs');
    const archive = path.join(work, `gmp-${GMP_VERSION}.tar.xz`); await run('/usr/bin/curl', ['--fail', '--location', '--retry', '3', '--retry-all-errors', '--retry-delay', '1', '--connect-timeout', '15', '--max-time', '180', '--output', archive, `https://gmplib.org/download/gmp/gmp-${GMP_VERSION}.tar.xz`]); const archiveInfo = await stable(archive, 'GMP archive'); if (archiveInfo.sha256 !== GMP_SHA256) fail('GMP archive hash differs'); await run('/usr/bin/tar', ['-xf', archive, '-C', work]); const gmpSource = path.join(work, `gmp-${GMP_VERSION}`); const gmpBuild = path.join(work, 'gmp-build'); const gmpPrefix = path.join(source, 'depends', 'gmp', 'package'); await mkdir(gmpBuild); await mkdir(path.dirname(gmpPrefix), { recursive: true }); await run(path.join(gmpSource, 'configure'), [`--prefix=${gmpPrefix}`, '--with-pic', '--disable-fft', '--enable-fat'], { cwd: gmpBuild, env: { CFLAGS: '-O2 -std=gnu17 -fomit-frame-pointer' } }); await run('/usr/bin/make', [`-j${nproc}`], { cwd: gmpBuild }); await run('/usr/bin/make', ['install'], { cwd: gmpBuild }); const gmp = await stable(path.join(gmpPrefix, 'lib', 'libgmp.a'), 'GMP static library');
    const build = path.join(work, 'build'); await run('cmake', ['-S', source, '-B', build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DUSE_ASM=OFF', '-DUSE_OPENMP=ON', '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -include cstdint']); await run('cmake', ['--build', build, '--parallel', String(nproc)]); await run('/usr/bin/git', ['-C', source, 'diff', '--exit-code']); const built = path.join(build, 'src', 'prover'); const binary = await stable(built, 'native prover'); await mkdir(path.join(stage, 'bin')); await copyFile(built, path.join(stage, 'bin', 'prover')); await chmod(path.join(stage, 'bin', 'prover'), 0o700); const manifest = assertV2NativeProverManifest({ schema: V2_NATIVE_PROVER_MANIFEST_SCHEMA, source: { repository: RAPIDSNARK_REPOSITORY, commit, submodules }, gmp: { version: GMP_VERSION, archiveSha256: archiveInfo.sha256, staticLibrarySha256: gmp.sha256 }, build: { useAsm: false, useOpenmp: true, sourceTreeUnchanged: true, cxxFlagsRelease: '-O3 -DNDEBUG -include cstdint', nproc, wallMs: Date.now() - started }, toolchain: { compiler: await version('/usr/bin/g++'), cmake: await version('cmake'), node: process.version, platform: `${process.platform}/${process.arch}` }, binary: { path: 'bin/prover', bytes: binary.bytes, sha256: binary.sha256 } }); await writeV2NativeProverManifest(path.join(stage, 'manifest.json'), manifest); await rename(stage, outputDirectory); await fsyncDirectory(parent); return Object.freeze({ outputDirectory, manifest }); } catch (e) { throw e; } finally { await rm(work, { recursive: true, force: true }); await rm(stage, { recursive: true, force: true }).catch(() => {}); }
}
if (process.argv[1] === fileURLToPath(import.meta.url)) { const [flag, output] = process.argv.slice(2); if (flag !== '--output' || process.argv.length !== 4) fail('usage: setup-v2-native-prover.mjs --output <absolute-new-private-directory>'); setupV2NativeProver({ outputDirectory: output }).then((r) => process.stdout.write(`${JSON.stringify(r.manifest)}\n`), (e) => { process.stderr.write(`${e.message}\n`); process.exitCode = 1; }); }
