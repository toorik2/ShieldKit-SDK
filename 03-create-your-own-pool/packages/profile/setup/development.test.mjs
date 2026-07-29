// Development setup must never promote a convenient test relation to V2. Full
// V2 setup evidence belongs to the domain integration suite, where the pinned
// relation source graph and independently reproduced artifacts are available.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';

import {
  canonicalCircuitBuildAttestation,
  V2_BUILD_R1CS_PATH,
  V2_BUILD_SOURCE_MANIFEST_PATH,
  V2_BUILD_SYM_PATH,
  V2_BUILD_WASM_PATH,
} from '../v2/build-attestation.mjs';
import { collectNpmBuildClosure } from '../v2/npm-closure.mjs';
import { canonicalV2RelationSourceManifest } from '../v2/relation-source-manifest.mjs';
import {
  LocalSetupError,
  SNARKJS_VERSION,
  TRUSTED_DEVELOPMENT_PTAU,
  assertUnchangedSetupInputs,
  hashFileStreaming,
  initializeDevelopmentGroth16,
  resolveDevelopmentPtauVerification,
} from './development.mjs';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(here, '../../../../');
const testTmpParent = path.join(repositoryRoot, '.codex-build', 'setup-development-test-tmp');
const circomCli = fileURLToPath(import.meta.resolve('circom2/cli.js'));
const bareDigest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => `sha256:${bareDigest(bytes)}`;

async function prepareTmpParent() {
  await mkdir(testTmpParent, { recursive: true, mode: 0o700 });
  await chmod(testTmpParent, 0o700);
}

async function evidence(filename) {
  const bytes = await readFile(filename);
  return Object.freeze({ bytes: bytes.byteLength, sha256: bareDigest(bytes) });
}

function closureArtifact(closure, packagePath, relative) {
  const pkg = closure.packages.find((entry) => entry.packagePath === packagePath);
  const file = pkg?.installed.files.find((entry) => entry.path === relative);
  assert.ok(file, `missing ${packagePath}/${relative} from closure`);
  return Object.freeze({
    bytes: file.bytes,
    path: `${packagePath}/${relative}`,
    sha256: file.sha256,
  });
}

async function readR1csAbi(r1csPath) {
  const { fd, sections } = await readBinFile(r1csPath, 'r1cs', 1, 1 << 22, 1 << 24);
  try {
    const header = await readR1csHeader(fd, sections, true);
    return Object.freeze({
      constraints: header.nConstraints,
      field: 'bn254',
      privateInputs: header.nPrvInputs,
      publicInputs: header.nPubInputs,
      publicOutputs: header.nOutputs,
      wires: header.nVars,
    });
  } finally {
    await fd.close();
  }
}

async function compileTinyCircuit(root) {
  const source = path.join(root, 'tiny.circom');
  const output = path.join(root, 'tiny-compiled');
  await mkdir(output);
  const sourceBytes = Buffer.from([
    'pragma circom 2.0.0;',
    'template Tiny() {',
    '  signal input a;',
    '  signal input b;',
    '  signal input secret;',
    '  signal product;',
    '  product <== a * b + secret;',
    '}',
    'component main {public [a, b]} = Tiny();',
    '',
  ].join('\n'));
  await writeFile(source, sourceBytes, { mode: 0o600 });
  await execFileAsync(process.execPath, [
    circomCli,
    source,
    '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2',
    '--output', output,
  ], { cwd: root, env: {} });
  const r1cs = path.join(output, 'tiny.r1cs');
  const wasm = path.join(output, 'tiny_js', 'tiny.wasm');
  const sym = path.join(output, 'tiny.sym');
  const abi = await readR1csAbi(r1cs);
  assert.deepEqual(
    { publicInputs: abi.publicInputs, publicOutputs: abi.publicOutputs },
    { publicInputs: 2, publicOutputs: 0 },
  );
  assert.ok(abi.privateInputs >= 1, 'tiny circuit must retain a private input');
  return Object.freeze({ abi, r1cs, sourceBytes, sym, wasm });
}

async function makeTinySpoofedV2Build(root, compiled, { exactLayout = true } = {}) {
  const closure = await collectNpmBuildClosure({
    repositoryRoot,
    roots: ['circom2'],
  });
  // This manifest is structurally canonical but carries the tiny relation's
  // evidence under the V2 entrypoint. Live source-graph verification must
  // reject it; it is deliberately never a positive V2 fixture.
  const sourceManifest = canonicalV2RelationSourceManifest({
    compiler: {
      circom: '2.2.3', npmPackage: 'circom2@0.2.23', optimization: 'O1', sanityCheck: 2,
    },
    entrypoint: '03-create-your-own-pool/circuits/v2-direct/main-chipnet.circom',
    schema: 'shieldkit-v2-direct-relation-source-manifest-v2',
    sources: [{
      bytes: compiled.sourceBytes.byteLength,
      includes: [],
      path: '03-create-your-own-pool/circuits/v2-direct/main-chipnet.circom',
      sha256: bareDigest(compiled.sourceBytes),
    }],
  });
  const sourceManifestPath = path.join(root, 'relation-source-manifest.json');
  await writeFile(sourceManifestPath, sourceManifest.bytes, { mode: 0o600 });
  const [r1cs, wasm, sym] = await Promise.all([
    evidence(compiled.r1cs), evidence(compiled.wasm), evidence(compiled.sym),
  ]);
  const layout = exactLayout ? {
    r1cs: V2_BUILD_R1CS_PATH,
    sourceManifest: V2_BUILD_SOURCE_MANIFEST_PATH,
    sym: V2_BUILD_SYM_PATH,
    wasm: V2_BUILD_WASM_PATH,
  } : {
    r1cs: 'fixtures/tiny.r1cs',
    sourceManifest: 'fixtures/tiny-source-manifest.json',
    sym: 'fixtures/tiny.sym',
    wasm: 'fixtures/tiny.wasm',
  };
  const build = canonicalCircuitBuildAttestation({
    artifacts: {
      r1cs: { ...r1cs, path: layout.r1cs },
      sym: { ...sym, path: layout.sym },
      wasm: { ...wasm, path: layout.wasm },
    },
    claims: { developmentOnly: true, production: false, release: false },
    compilation: {
      argv: [
        'node_modules/circom2/cli.js',
        '03-create-your-own-pool/circuits/v2-direct/main-chipnet.circom',
        '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2', '--output', '$BUILD_OUTPUT',
      ],
      circomCompilerVersion: '2.2.3',
      circomPackageVersion: '0.2.23',
      cli: closureArtifact(closure, 'node_modules/circom2', 'cli.js'),
      executable: 'process.execPath',
      node: { modulesAbi: process.versions.modules, version: process.versions.node },
      optimization: 'O1',
      packageMetadata: closureArtifact(closure, 'node_modules/circom2', 'package.json'),
      sanityCheck: 2,
    },
    npmClosure: closure,
    r1csAbi: compiled.abi,
    schema: 'shieldkit-v2-direct-circuit-build-attestation-v1',
    sourceManifest: {
      bytes: sourceManifest.bytes.byteLength,
      path: layout.sourceManifest,
      sha256: sourceManifest.sha256,
    },
  });
  const buildPath = path.join(root, 'circuit-build-attestation.json');
  await writeFile(buildPath, build.bytes, { mode: 0o600 });
  return Object.freeze({ buildPath, compiled, sourceManifestPath });
}

async function tinySpoofFixture(t) {
  await prepareTmpParent();
  const root = await mkdtemp(path.join(testTmpParent, 'tiny-relation-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const compiled = await compileTinyCircuit(root);
  const build = await makeTinySpoofedV2Build(root, compiled);
  return Object.freeze({ root, ...build });
}

function spoofedSetupInput(data, destination) {
  return {
    buildAttestationPath: data.buildPath,
    destination,
    entropySource: { kind: 'stdin' },
    expectedPtauPower: 4,
    expectedPtauSha256: `sha256:${'0'.repeat(64)}`,
    expectedR1csSha256: digest(Buffer.from('not reached')),
    expectedSnarkjs: { version: SNARKJS_VERSION, cliSha256: `sha256:${'0'.repeat(64)}` },
    ptauPath: path.join(data.root, 'not-reached.ptau'),
    ptauSource: 'test-only-not-reached',
    repositoryRoot,
    r1csPath: data.compiled.r1cs,
    sourceManifestPath: data.sourceManifestPath,
    verifyPtau: true,
  };
}

test('resolveDevelopmentPtauVerification: pin policy remains explicit, while V2 setup forces full verification', () => {
  const hermez = TRUSTED_DEVELOPMENT_PTAU['hermez-powersOfTau28_hez_final_20'];
  const base = { ptauSource: hermez.source, ptauSha256: hermez.sha256, expectedPtauPower: hermez.power };
  assert.equal(resolveDevelopmentPtauVerification(base).mode, 'hash-only');
  assert.equal(resolveDevelopmentPtauVerification({ ...base, verifyPtau: true }).mode, 'full');
  assert.equal(resolveDevelopmentPtauVerification({ ...base, verifyPtau: false }).mode, 'hash-only');
  assert.throws(() => resolveDevelopmentPtauVerification({ ...base, ptauSource: 'unknown', verifyPtau: false }), /TRUSTED_DEVELOPMENT_PTAU/);
});

test('a real tiny relation cannot be labeled V2 or publish setup output', async (t) => {
  const data = await tinySpoofFixture(t);
  const destination = path.join(data.root, 'must-not-publish');
  await assert.rejects(
    () => initializeDevelopmentGroth16(spoofedSetupInput(data, destination)),
    /circuit build source manifest differs from the repository: relation sources differ from their manifest/,
  );
  await assert.rejects(() => lstat(destination), { code: 'ENOENT' });
  assert.deepEqual(
    (await readdir(data.root)).filter((name) => name.startsWith('.shieldkit-setup-stage-')),
    [],
  );
});

test('the build attestation parser requires the exact V2 artifact layout', async (t) => {
  await prepareTmpParent();
  const root = await mkdtemp(path.join(testTmpParent, 'layout-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const compiled = await compileTinyCircuit(root);
  await assert.rejects(
    () => makeTinySpoofedV2Build(root, compiled, { exactLayout: false }),
    /exact V2 build layout/,
  );
});

test('runner rejects missing, unknown, and symlinked relation-manifest inputs before setup', async (t) => {
  const data = await tinySpoofFixture(t);
  const missing = spoofedSetupInput(data, path.join(data.root, 'missing-manifest'));
  delete missing.sourceManifestPath;
  await assert.rejects(() => initializeDevelopmentGroth16(missing), /local setup input missing sourceManifestPath/);

  const unknown = spoofedSetupInput(data, path.join(data.root, 'unknown-property'));
  unknown.untrusted = true;
  await assert.rejects(() => initializeDevelopmentGroth16(unknown), /local setup input has unknown property: untrusted/);

  const manifestLink = path.join(data.root, 'relation-manifest-link.json');
  await symlink(data.sourceManifestPath, manifestLink);
  const linked = spoofedSetupInput(data, path.join(data.root, 'linked-manifest'));
  linked.sourceManifestPath = manifestLink;
  await assert.rejects(() => initializeDevelopmentGroth16(linked), /relation source manifest must be a unique regular non-symlink/);
});

test('post-execution direct-file revalidation detects content drift', async (t) => {
  await prepareTmpParent();
  const root = await mkdtemp(path.join(testTmpParent, 'input-drift-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const r1csPath = path.join(root, 'r1cs');
  const ptauPath = path.join(root, 'ptau');
  await Promise.all([writeFile(r1csPath, 'original'), writeFile(ptauPath, 'ptau')]);
  const r1csSha256 = digest(await readFile(r1csPath));
  const ptauSha256 = digest(await readFile(ptauPath));
  await writeFile(r1csPath, 'drift');
  await assert.rejects(
    () => assertUnchangedSetupInputs({ r1csPath, ptauPath, r1csSha256, ptauSha256 }),
    /r1cs changed during setup/,
  );
});

test('public setup errors are typed', () => {
  assert.equal(new LocalSetupError('x').name, 'LocalSetupError');
});

test('artifact hashing streams from FileHandle.createReadStream and returns real SHA-256', async (t) => {
  await prepareTmpParent();
  const root = await mkdtemp(path.join(testTmpParent, 'streaming-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'large-artifact.bin');
  const block = Buffer.alloc(1024 * 1024, 0xa5);
  await writeFile(artifact, Buffer.concat(Array.from({ length: 8 }, () => block)));
  assert.equal(await hashFileStreaming(artifact), digest(await readFile(artifact)));
  const moduleSource = await readFile(path.join(here, 'development.mjs'), 'utf8');
  const implementation = moduleSource.slice(moduleSource.indexOf('async function measureFile'), moduleSource.indexOf('/** Stream artifact hashes'));
  assert.match(implementation, /handle\.createReadStream/);
  assert.doesNotMatch(implementation, /readFile/);
});
