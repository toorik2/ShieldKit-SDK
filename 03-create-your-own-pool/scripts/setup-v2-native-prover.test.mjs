import assert from 'node:assert/strict';
import { chmod, lstat, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import { GMP_SHA256, GMP_VERSION, RAPIDSNARK_COMMIT, RAPIDSNARK_REPOSITORY, RAPIDSNARK_SUBMODULES, V2_NATIVE_PROVER_MANIFEST_SCHEMA, assertV2NativeProverManifest, boundedOutputTail, writeV2NativeProverManifest } from './setup-v2-native-prover.mjs';

const hash = (c) => c.repeat(64).slice(0, 64);
const manifest = () => ({ schema: V2_NATIVE_PROVER_MANIFEST_SCHEMA, source: { repository: RAPIDSNARK_REPOSITORY, commit: RAPIDSNARK_COMMIT, submodules: [...RAPIDSNARK_SUBMODULES] }, gmp: { version: GMP_VERSION, archiveSha256: GMP_SHA256, staticLibrarySha256: hash('b') }, build: { useAsm: false, useOpenmp: true, sourceTreeUnchanged: true, cxxFlagsRelease: '-O3 -DNDEBUG -include cstdint', nproc: 20, wallMs: 1 }, toolchain: { compiler: 'g++ test', cmake: 'cmake test', node: 'v22.test', platform: 'linux/x64' }, binary: { path: 'bin/prover', bytes: 1, sha256: hash('c') } });

test('native setup manifest binds source, GMP, source-unchanged compatibility flags, and binary', () => {
  assert.equal(assertV2NativeProverManifest(manifest()).source.commit, RAPIDSNARK_COMMIT);
  for (const mutate of [
    (v) => { v.build.useAsm = true; },
    (v) => { v.build.sourceTreeUnchanged = false; },
    (v) => { v.build.wallMs = 0; },
    (v) => { v.build.cxxFlagsRelease = '-O3'; },
    (v) => { v.gmp.archiveSha256 = hash('0'); },
    (v) => { v.binary.path = '../prover'; },
    (v) => { v.source.commit = hash('d').slice(0, 40); },
  ]) { const v = manifest(); mutate(v); assert.throws(() => assertV2NativeProverManifest(v), /V2_NATIVE_PROVER_SETUP_FAILED/u); }
});

test('setup retains bounded output tails without issuing an output-cap SIGKILL', () => {
  assert.equal(boundedOutputTail(Buffer.from('abc'), Buffer.from('def'), 4).toString('utf8'), 'cdef');
  assert.equal(boundedOutputTail(Buffer.alloc(0), Buffer.from('0123456789'), 4).toString('utf8'), '6789');
  assert.throws(() => boundedOutputTail(Buffer.alloc(0), Buffer.alloc(0), 0), /V2_NATIVE_PROVER_SETUP_FAILED/u);
});

test('setup writes a durable private exact-JCS installation manifest', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'shieldkit-native-manifest-'));
  await chmod(directory, 0o700);
  const filename = path.join(directory, 'manifest.json');
  try {
    const value = manifest();
    await writeV2NativeProverManifest(filename, value);
    const [bytes, stat] = await Promise.all([readFile(filename), lstat(filename)]);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.deepEqual(bytes, Buffer.from(canonicalizeJcs(value), 'utf8'));
    assert.equal(bytes.includes(Buffer.from('\n')), false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
