import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  buildV2FinalZkeySnarkjsCommands,
  collectV2FinalZkeyToolchainManifest,
  parseV2FinalZkeyToolchainManifest,
  V2_FINAL_ZKEY_RESOLUTION_SCHEMA,
  V2_FINAL_ZKEY_TOOLCHAIN_SCHEMA,
  V2_FINAL_ZKEY_VERIFICATION_SCHEMA,
  verifyV2FinalZkeyCryptographically,
  verifyV2FinalZkeyToolchainManifest,
  verifyV2HistoricalFinalZkeyToolchainManifest,
} from './final-zkey-verification.mjs';

const execFileAsync = promisify(execFile);
const snarkjsRoot = path.dirname(fileURLToPath(import.meta.resolve('snarkjs')));
const repositoryRoot = path.dirname(path.dirname(snarkjsRoot));
const snarkjsCli = path.join(snarkjsRoot, 'build', 'cli.cjs');
const circom2Cli = path.join(repositoryRoot, 'node_modules', 'circom2', 'cli.js');
const digest = async (filename) =>
  `sha256:${createHash('sha256').update(await readFile(filename)).digest('hex')}`;

test('publishes a distinct schema for successful cryptographic resolutions', () => {
  assert.equal(
    V2_FINAL_ZKEY_RESOLUTION_SCHEMA,
    'shieldkit-v2-direct-final-zkey-cryptographic-resolution-v1',
  );
});

test('collects and re-verifies the installed hash-pinned snarkjs toolchain', async () => {
  const manifest = await collectV2FinalZkeyToolchainManifest();
  assert.equal(manifest.schema, V2_FINAL_ZKEY_TOOLCHAIN_SCHEMA);
  assert.match(manifest.node.executableSha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(manifest.snarkjs.cliSha256, /^sha256:[0-9a-f]{64}$/);
  assert.match(manifest.snarkjs.packageJsonSha256, /^sha256:[0-9a-f]{64}$/);
  const resolved = await verifyV2FinalZkeyToolchainManifest(manifest);
  const historical = await verifyV2HistoricalFinalZkeyToolchainManifest(manifest);
  assert.match(resolved.nodeExecutable, /node/);
  assert.match(resolved.snarkjsCli, /snarkjs\/build\/cli\.cjs$/);
  assert.deepEqual(historical.manifest, manifest);
});

test('historical toolchain verification ignores only the enclosing lockfile byte envelope', async () => {
  const manifest = await collectV2FinalZkeyToolchainManifest();
  const withLockfile = (mutate) => {
    const value = structuredClone(manifest);
    mutate(value);
    return value;
  };
  for (const drifted of [
    withLockfile((value) => { value.npmClosure.lockfile.bytes += 1; }),
    withLockfile((value) => { value.npmClosure.lockfile.sha256 = '0'.repeat(64); }),
    withLockfile((value) => {
      value.npmClosure.lockfile.bytes += 1;
      value.npmClosure.lockfile.sha256 = '0'.repeat(64);
    }),
  ]) {
    await assert.rejects(
      () => verifyV2FinalZkeyToolchainManifest(drifted),
      { code: 'FINAL_ZKEY_TOOLCHAIN_MISMATCH' },
    );
    const resolved = await verifyV2HistoricalFinalZkeyToolchainManifest(drifted);
    assert.deepEqual(
      resolved.manifest,
      parseV2FinalZkeyToolchainManifest(drifted),
    );
  }

  const rejectedMutations = [
    (value) => { value.npmClosure.schema = 'wrong-schema'; },
    (value) => { value.npmClosure.roots.push('node_modules/not-installed'); },
    (value) => { value.npmClosure.lockfile.path = 'other-lock.json'; },
    (value) => { value.npmClosure.lockfile.lockfileVersion = 2; },
    (value) => { value.npmClosure.lockfile.extra = true; },
    (value) => { value.npmClosure.lockClosureSha256 = '0'.repeat(64); },
    (value) => { value.npmClosure.installedClosureSha256 = '0'.repeat(64); },
    (value) => { value.npmClosure.packages[0].lock.version = '999.0.0'; },
    (value) => { value.npmClosure.packages[0].lock.resolved = 'https://registry.npmjs.org/wrong/-/wrong-1.0.0.tgz'; },
    (value) => { value.npmClosure.packages[0].lock.integrity = 'sha512-wrong'; },
    (value) => { value.npmClosure.packages[0].lock.sha256 = '0'.repeat(64); },
    (value) => { value.npmClosure.packages[0].installed.files[0].path = 'wrong-file'; },
    (value) => { value.npmClosure.packages[0].installed.files[0].bytes += 1; },
    (value) => { value.npmClosure.packages[0].installed.files[0].sha256 = '0'.repeat(64); },
    (value) => { value.npmClosure.packages[0].installed.sha256 = '0'.repeat(64); },
    (value) => { value.node.version = 'v22.23.0'; },
    (value) => { value.node.executableSha256 = `sha256:${'0'.repeat(64)}`; },
    (value) => { value.snarkjs.version = '0.0.0'; },
    (value) => { value.snarkjs.cliSha256 = `sha256:${'0'.repeat(64)}`; },
    (value) => { value.snarkjs.packageJsonSha256 = `sha256:${'0'.repeat(64)}`; },
  ];
  for (const mutate of rejectedMutations) {
    await assert.rejects(
      () => verifyV2HistoricalFinalZkeyToolchainManifest(
        withLockfile(mutate),
      ),
    );
  }
});

test('fails closed on non-exact final-key toolchain metadata', async () => {
  const manifest = await collectV2FinalZkeyToolchainManifest();
  assert.throws(() => parseV2FinalZkeyToolchainManifest({ ...manifest, extra: true }), /missing or unknown/);
  assert.throws(() => parseV2FinalZkeyToolchainManifest({
    ...manifest,
    snarkjs: { ...manifest.snarkjs, cliSha256: 'sha256:ABC' },
  }), /lowercase sha256/);
  await assert.rejects(
    () => verifyV2FinalZkeyToolchainManifest({
      ...manifest,
      snarkjs: { ...manifest.snarkjs, version: '0.0.0' },
    }),
    /does not match/,
  );
});

test('constructs fixed no-shell snarkjs final-key commands', () => {
  const result = buildV2FinalZkeySnarkjsCommands({
    r1csPath: '/private/relation.r1cs',
    ptauPath: '/private/powers.ptau',
    zkeyPath: '/private/final.zkey',
    verificationKeyPath: '/private/vk.json',
  });
  assert.deepEqual(result.verify, ['zkey', 'verify', '/private/relation.r1cs', '/private/powers.ptau', '/private/final.zkey']);
  assert.deepEqual(result.exportVerificationKey, ['zkey', 'export', 'verificationkey', '/private/final.zkey', '/private/vk.json']);
  assert.throws(() => buildV2FinalZkeySnarkjsCommands({
    r1csPath: 'relative.r1cs', ptauPath: '/p', zkeyPath: '/z', verificationKeyPath: '/vk',
  }), /absolute path/);
});

test('final-key API rejects malformed input before a verifier process can run', async () => {
  await assert.rejects(
    () => verifyV2FinalZkeyCryptographically({ schema: V2_FINAL_ZKEY_VERIFICATION_SCHEMA }),
    /missing or unknown/,
  );
});

test('hash mismatch is fail-closed after private-copy setup and leaves no verifier directory', async () => {
  const fixtureDirectory = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-final-zkey-fixture-'));
  try {
    const artifactPath = path.join(fixtureDirectory, 'artifact.bin');
    await writeFile(artifactPath, 'not a Groth16 artifact', { mode: 0o600 });
    const before = new Set((await readdir(tmpdir())).filter((name) => name.startsWith('shieldkit-v2-final-zkey-')));
    const toolchain = await collectV2FinalZkeyToolchainManifest();
    const artifact = { path: artifactPath, sha256: `sha256:${'0'.repeat(64)}` };
    await assert.rejects(
      () => verifyV2FinalZkeyCryptographically({
        schema: V2_FINAL_ZKEY_VERIFICATION_SCHEMA,
        toolchain,
        r1cs: artifact,
        ptau: artifact,
        finalZkey: artifact,
        verificationKey: artifact,
      }),
      { code: 'FINAL_ZKEY_ARTIFACT_HASH_MISMATCH' },
    );
    const after = (await readdir(tmpdir())).filter((name) => name.startsWith('shieldkit-v2-final-zkey-'));
    assert.deepEqual(new Set(after), before);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('executes real pinned snarkjs verification and exact VK derivation on a tiny TEST-ONLY circuit', { timeout: 120_000 }, async () => {
  const fixtureDirectory = await mkdtemp(
    path.join(tmpdir(), 'shieldkit-v2-final-zkey-real-fixture-'),
  );
  try {
    const circuit = path.join(fixtureDirectory, 'square.circom');
    const r1cs = path.join(fixtureDirectory, 'square.r1cs');
    const initialPtau = path.join(fixtureDirectory, 'pot8-initial.ptau');
    const contributedPtau = path.join(
      fixtureDirectory,
      'pot8-contributed.ptau',
    );
    const finalPtau = path.join(fixtureDirectory, 'pot8-final.ptau');
    const zkey = path.join(fixtureDirectory, 'square-final.zkey');
    const exportedVk = path.join(fixtureDirectory, 'snarkjs-vk.json');
    const canonicalVk = path.join(fixtureDirectory, 'verification-key.json');
    await writeFile(
      circuit,
      [
        'pragma circom 2.0.0;',
        'template Square() {',
        '  signal input value;',
        '  signal output squared;',
        '  squared <== value * value;',
        '}',
        'component main = Square();',
        '',
      ].join('\n'),
      { mode: 0o600 },
    );
    const run = (arguments_) => execFileAsync(
      process.execPath,
      arguments_,
      {
        cwd: fixtureDirectory,
        env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
        maxBuffer: 8 * 1024 * 1024,
      },
    );
    await run([circom2Cli, circuit, '--r1cs', '--output', fixtureDirectory]);
    await run([
      snarkjsCli,
      'powersoftau',
      'new',
      'bn128',
      '8',
      initialPtau,
    ]);
    await run([
      snarkjsCli,
      'powersoftau',
      'contribute',
      initialPtau,
      contributedPtau,
      '--name=ShieldKit TEST-ONLY contribution',
      '--entropy=ShieldKit TEST-ONLY deterministic entropy',
    ]);
    await run([
      snarkjsCli,
      'powersoftau',
      'prepare',
      'phase2',
      contributedPtau,
      finalPtau,
    ]);
    await run([snarkjsCli, 'groth16', 'setup', r1cs, finalPtau, zkey]);
    await run([
      snarkjsCli,
      'zkey',
      'export',
      'verificationkey',
      zkey,
      exportedVk,
    ]);
    const verificationKey = JSON.parse(await readFile(exportedVk, 'utf8'));
    await writeFile(
      canonicalVk,
      canonicalizeJcs(verificationKey),
      { mode: 0o600 },
    );
    const toolchain = await collectV2FinalZkeyToolchainManifest();
    const result = await verifyV2FinalZkeyCryptographically({
      schema: V2_FINAL_ZKEY_VERIFICATION_SCHEMA,
      toolchain,
      r1cs: { path: r1cs, sha256: await digest(r1cs) },
      ptau: { path: finalPtau, sha256: await digest(finalPtau) },
      finalZkey: { path: zkey, sha256: await digest(zkey) },
      verificationKey: {
        path: canonicalVk,
        sha256: await digest(canonicalVk),
      },
    });
    assert.equal(result.schema, V2_FINAL_ZKEY_RESOLUTION_SCHEMA);
    assert.equal(result.r1csSha256, await digest(r1cs));
    assert.equal(result.ptauSha256, await digest(finalPtau));
    assert.equal(result.finalZkeySha256, await digest(zkey));
    assert.equal(result.verificationKeySha256, await digest(canonicalVk));
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});
