import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from './profile-core.mjs';
import {
  BuildAttestationError,
  CIRCUIT_BUILD_ATTESTATION_SCHEMA,
  DEVELOPMENT_ATTESTATION_SIGNER_DOMAIN,
  DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
  developmentAttestationSigningBytes,
  parseCircuitBuildAttestation,
  parseDevelopmentSetupAttestation,
  V2_BUILD_R1CS_PATH,
  V2_BUILD_SOURCE_MANIFEST_PATH,
  V2_BUILD_SYM_PATH,
  V2_BUILD_WASM_PATH,
  verifyDevelopmentSetupAttestationPair,
} from './build-attestation.mjs';
import {
  collectNpmBuildClosure,
  NPM_BUILD_CLOSURE_SCHEMA,
} from './npm-closure.mjs';
import {
  canonicalV2RelationSourceManifest,
  collectV2RelationSourceManifest,
} from './relation-source-manifest.mjs';

// Parser-only values. They do not represent a package, a circuit, a setup,
// trusted evidence, or a deployable artifact.
const h = (byte) => byte.repeat(64);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalHash = (value) => sha256(Buffer.from(canonicalizeJcs(value), 'utf8'));
const bytes = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const artifact = (pathname, byte, size = 1) => ({
  bytes: size,
  path: pathname,
  sha256: h(byte),
});

function packageEntry({ files, name, packagePath, version }) {
  const lock = {
    integrity: `sha512-${Buffer.from(`${name}@${version}`).toString('base64')}`,
    resolved: `https://registry.npmjs.org/${name.replace('/', '%2f')}/-/${name.replace('@', '').replace('/', '-')}-${version}.tgz`,
    version,
  };
  return {
    installed: { files, sha256: canonicalHash(files) },
    lock: { ...lock, sha256: canonicalHash(lock) },
    name,
    packagePath,
  };
}

function minimalClosure({ cliPath, cliHash, cliBytes, packageHash, packageBytes, packageName, root, version }) {
  const files = [
    artifact('.empty', '0', 0),
    artifact(cliPath, cliHash, cliBytes),
    artifact('package.json', packageHash, packageBytes),
  ].sort((left, right) => left.path.localeCompare(right.path));
  const packages = [packageEntry({ files, name: packageName, packagePath: root, version })];
  const lockClosure = packages.map((entry) => ({ lock: entry.lock, name: entry.name, packagePath: entry.packagePath }));
  const installedClosure = packages.map((entry) => ({ installed: entry.installed, name: entry.name, packagePath: entry.packagePath }));
  return {
    installedClosureSha256: canonicalHash(installedClosure),
    lockClosureSha256: canonicalHash(lockClosure),
    lockfile: {
      ...artifact('package-lock.json', '1', 913),
      lockfileVersion: 3,
    },
    packages,
    roots: [root],
    schema: NPM_BUILD_CLOSURE_SCHEMA,
  };
}

const circomClosure = () => minimalClosure({
  cliBytes: 71,
  cliHash: '2',
  cliPath: 'cli.js',
  packageBytes: 83,
  packageHash: '3',
  packageName: 'circom2',
  root: 'node_modules/circom2',
  version: '0.2.23',
});
const snarkjsClosure = () => minimalClosure({
  cliBytes: 97,
  cliHash: '4',
  cliPath: 'build/cli.cjs',
  packageBytes: 101,
  packageHash: '5',
  packageName: 'snarkjs',
  root: 'node_modules/snarkjs',
  version: '0.7.6',
});

function closureArtifact(closure, packagePath, relative) {
  const entry = closure.packages.find((candidate) => candidate.packagePath === packagePath);
  const file = entry.installed.files.find((candidate) => candidate.path === relative);
  return { bytes: file.bytes, path: `${packagePath}/${relative}`, sha256: file.sha256 };
}

function build({
  npmClosure = circomClosure(),
  r1cs = artifact(V2_BUILD_R1CS_PATH, '7', 20),
  sourceManifest = artifact(V2_BUILD_SOURCE_MANIFEST_PATH, '6', 50),
} = {}) {
  return {
    artifacts: {
      r1cs,
      sym: artifact(V2_BUILD_SYM_PATH, '8', 30),
      wasm: artifact(V2_BUILD_WASM_PATH, '9', 40),
    },
    claims: { developmentOnly: true, production: false, release: false },
    compilation: {
      argv: [
        'node_modules/circom2/cli.js',
        'shieldkit-groth/circuits/v2-direct/main-chipnet.circom',
        '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2', '--output', '$BUILD_OUTPUT',
      ],
      circomCompilerVersion: '2.2.3',
      circomPackageVersion: '0.2.23',
      cli: closureArtifact(npmClosure, 'node_modules/circom2', 'cli.js'),
      executable: 'process.execPath',
      node: { modulesAbi: '127', version: '22.16.0' },
      optimization: 'O1',
      packageMetadata: closureArtifact(npmClosure, 'node_modules/circom2', 'package.json'),
      sanityCheck: 2,
    },
    npmClosure,
    r1csAbi: {
      constraints: 458728,
      field: 'bn254',
      privateInputs: 705,
      publicInputs: 2,
      publicOutputs: 0,
      wires: 454978,
    },
    schema: CIRCUIT_BUILD_ATTESTATION_SCHEMA,
    sourceManifest,
  };
}

function setup({
  buildAttestation = artifact('artifacts/circuit-build-attestation.json', 'a', 340),
  npmClosure = snarkjsClosure(),
  r1cs = artifact(V2_BUILD_R1CS_PATH, '7', 20),
} = {}) {
  const initial = artifact('artifacts/v2-direct.initial.zkey', 'c', 100);
  const output = artifact('artifacts/v2-direct.final.zkey', 'd', 110);
  return {
    buildAttestation,
    claims: {
      contributionIndependence: 'not-established',
      developmentOnly: true,
      externalTranscript: false,
      finalCeremony: false,
      production: false,
      release: false,
    },
    commands: {
      contribute: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'contribute', '$INPUT_ZKEY', '$OUTPUT_ZKEY'],
      exportVerificationKey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'export', 'verificationkey', '$FINAL_ZKEY', '$VERIFICATION_KEY'],
      powersOfTauVerify: ['node_modules/snarkjs/build/cli.cjs', 'powersoftau', 'verify', '$PTAU'],
      setup: ['node_modules/snarkjs/build/cli.cjs', 'groth16', 'setup', '$R1CS', '$PTAU', '$INITIAL_ZKEY'],
      verifyFinalZkey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'verify', '$R1CS', '$PTAU', '$FINAL_ZKEY'],
    },
    finalEvidence: {
      finalZkeySha256: output.sha256,
      finalZkeyVerified: true,
      verificationKey: artifact('artifacts/v2-direct.vkey.json', 'e', 120),
      verificationKeyExported: true,
    },
    ptau: {
      artifact: artifact('prerequisites/pot17-final.ptau', 'b', 200),
      ceremonyPower: 17,
      power: 17,
      source: 'community-powers-of-tau',
      verified: true,
    },
    r1cs,
    schema: DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
    snarkjs: {
      cli: closureArtifact(npmClosure, 'node_modules/snarkjs', 'build/cli.cjs'),
      node: { modulesAbi: '127', version: '22.16.0' },
      npmClosure,
      packageMetadata: closureArtifact(npmClosure, 'node_modules/snarkjs', 'package.json'),
      version: '0.7.6',
    },
    zkeyChain: {
      contributions: [{
        entropyCommitment: h('f'),
        entropyCommitmentDomain: DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
        inputZkeySha256: initial.sha256,
        output,
        sequence: 1,
      }],
      initial,
    },
  };
}

function signDevelopment(value, pair, keyId = 'local-development') {
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
  value.signer = {
    algorithm: 'ed25519',
    domain: DEVELOPMENT_ATTESTATION_SIGNER_DOMAIN,
    evidence: 'development-only',
    keyId,
    publicKeyPem,
    signatureBase64: '',
  };
  value.signer.signatureBase64 = sign(null, developmentAttestationSigningBytes(value), pair.privateKey).toString('base64');
  return value;
}

test('parses an exact minimal npm closure and normalized portable commands', () => {
  const parsedBuild = parseCircuitBuildAttestation(bytes(build()));
  assert.equal(parsedBuild.npmClosure.schema, NPM_BUILD_CLOSURE_SCHEMA);
  assert.deepEqual(parsedBuild.npmClosure.roots, ['node_modules/circom2']);
  assert.equal(parsedBuild.npmClosure.packages[0].lock.version, '0.2.23');
  assert.equal(parsedBuild.compilation.argv.at(-1), '$BUILD_OUTPUT');
  assert.equal(parsedBuild.r1csAbi.publicInputs, 2);

  const parsedSetup = parseDevelopmentSetupAttestation(bytes(setup()));
  assert.deepEqual(parsedSetup.snarkjs.npmClosure.roots, ['node_modules/snarkjs']);
  assert.equal(parsedSetup.snarkjs.npmClosure.packages[0].lock.version, '0.7.6');
  assert.deepEqual(parsedSetup.commands.contribute.slice(-2), ['$INPUT_ZKEY', '$OUTPUT_ZKEY']);
  assert.equal(parsedSetup.zkeyChain.contributions.length, 1);
  assert.notEqual(parsedSetup.zkeyChain.initial.sha256, parsedSetup.zkeyChain.contributions[0].output.sha256);
  assert.equal(parsedSetup.zkeyChain.contributions[0].entropyCommitmentDomain, DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN);
});

test('rejects noncanonical bytes, nonportable evidence, and exact build mutations', () => {
  const cases = [
    [() => Buffer.from(JSON.stringify(build(), null, 2)), /RFC8785/],
    [() => bytes({ ...build(), profileId: h('f') }), /profileId/],
    [() => bytes({ ...build(), clock: '2026-07-29' }), /clock/],
    [() => bytes({ ...build(), sourceManifest: artifact('/tmp/source.json', '6', 50) }), /absolute or platform-specific/],
    [() => bytes({ ...build(), compilation: { ...build().compilation, argv: ['circom'] } }), /exact normalized/],
    [() => bytes({ ...build(), compilation: { ...build().compilation, argv: build().compilation.argv.map((entry) => entry === '--sanity_check' ? '--sanitycheck' : entry) } }), /exact normalized/],
    [() => bytes(build({ npmClosure: minimalClosure({
      cliBytes: 71,
      cliHash: '2',
      cliPath: 'cli.js',
      packageBytes: 83,
      packageHash: '3',
      packageName: 'circom2',
      root: 'node_modules/circom2',
      version: '0.2.22',
    }) })), /compiler files differ/],
    [() => bytes({ ...build(), r1csAbi: { ...build().r1csAbi, publicInputs: 3 } }), /two inputs/],
  ];
  for (const [make, pattern] of cases) assert.throws(() => parseCircuitBuildAttestation(make()), pattern);
  const cyclic = build(); cyclic.self = cyclic;
  assert.throws(() => developmentAttestationSigningBytes(cyclic), /cycles/);
});

test('rejects setup command, provenance, continuity, and final-link mutations', () => {
  const cases = [
    [() => ({ ...setup(), ptau: { ...setup().ptau, verified: false } }), /PTau/],
    [() => ({ ...setup(), commands: { ...setup().commands, contribute: ['snarkjs'] } }), /exact normalized/],
    [() => ({ ...setup(), zkeyChain: { ...setup().zkeyChain, contributions: [] } }), /exactly one/],
    [() => ({ ...setup(), zkeyChain: { ...setup().zkeyChain, contributions: [...setup().zkeyChain.contributions, structuredClone(setup().zkeyChain.contributions[0])] } }), /exactly one/],
    [() => ({ ...setup(), zkeyChain: { ...setup().zkeyChain, contributions: [{ ...setup().zkeyChain.contributions[0], inputZkeySha256: h('0') }] } }), /discontinuous/],
    [() => ({ ...setup(), zkeyChain: { ...setup().zkeyChain, contributions: [{ ...setup().zkeyChain.contributions[0], output: structuredClone(setup().zkeyChain.initial) }] } }), /must change/],
    [() => ({ ...setup(), zkeyChain: { ...setup().zkeyChain, contributions: [{ ...setup().zkeyChain.contributions[0], entropyCommitmentDomain: 'wrong-domain' }] } }), /entropy commitment domain/],
    [() => ({ ...setup(), finalEvidence: { ...setup().finalEvidence, finalZkeySha256: h('0') } }), /final zkey/],
    [() => ({ ...setup(), snarkjs: { ...setup().snarkjs, npmClosure: minimalClosure({
      cliBytes: 97,
      cliHash: '4',
      cliPath: 'build/cli.cjs',
      packageBytes: 101,
      packageHash: '5',
      packageName: 'snarkjs',
      root: 'node_modules/snarkjs',
      version: '0.7.5',
    }) } }), /SnarkJS files differ/],
  ];
  for (const [make, pattern] of cases) assert.throws(() => parseDevelopmentSetupAttestation(bytes(make())), pattern);
});

test('verifies optional domain-separated development Ed25519 evidence', () => {
  const pair = generateKeyPairSync('ed25519');
  const signed = signDevelopment(build(), pair);
  const trustedDevelopmentSigners = [{ keyId: 'local-development', publicKeyPem: signed.signer.publicKeyPem }];
  assert.equal(parseCircuitBuildAttestation(bytes(signed), { trustedDevelopmentSigners }).signer.evidence, 'development-only');
  const wrongDomain = structuredClone(signed); wrongDomain.signer.domain = 'release-attestation';
  assert.throws(() => parseCircuitBuildAttestation(bytes(wrongDomain), { trustedDevelopmentSigners }), BuildAttestationError);
  const slashPrefixedSignature = structuredClone(signed);
  const alteredPrefix = signed.signer.signatureBase64[0] === '/' ? '+' : '/';
  slashPrefixedSignature.signer.signatureBase64 = `${alteredPrefix}${signed.signer.signatureBase64.slice(1)}`;
  assert.throws(
    () => parseCircuitBuildAttestation(bytes(slashPrefixedSignature), { trustedDevelopmentSigners }),
    /signature or domain/u,
  );
  const tampered = structuredClone(signed); tampered.artifacts.r1cs.sha256 = h('0');
  assert.throws(() => parseCircuitBuildAttestation(bytes(tampered), { trustedDevelopmentSigners }), /signature or domain/);
});

const TEST_TMP_PARENT = path.resolve(import.meta.dirname, '../../../../.codex-build/build-attestation-test-tmp');
const REPOSITORY_ROOT = path.resolve(import.meta.dirname, '../../../..');
const integrity = (name) => `sha512-${Buffer.from(name).toString('base64')}`;

async function writePackage(root, packagePath, name, version, files) {
  const directory = path.join(root, ...packagePath.split('/'));
  await mkdir(directory, { recursive: true });
  await writeFile(path.join(directory, 'package.json'), `${JSON.stringify({ name, version })}\n`);
  for (const [relative, content] of Object.entries(files)) {
    const destination = path.join(directory, ...relative.split('/'));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(destination, content);
  }
}

async function writeCanonicalV2Relation(root) {
  const manifest = await collectV2RelationSourceManifest({
    repositoryRoot: REPOSITORY_ROOT,
  });
  await Promise.all(manifest.sources.map(async ({ path: relative }) => {
    const destination = path.join(root, ...relative.split('/'));
    await mkdir(path.dirname(destination), { recursive: true });
    await writeFile(
      destination,
      await readFile(
        path.join(REPOSITORY_ROOT, ...relative.split('/')),
      ),
    );
  }));
  return canonicalV2RelationSourceManifest(manifest).bytes;
}

test('verifies exact V2 setup/build linkage against live closures and the canonical V2 relation manifest', async (t) => {
  await mkdir(TEST_TMP_PARENT, { recursive: true, mode: 0o700 });
  const root = await mkdtemp(path.join(TEST_TMP_PARENT, 'fixture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const packages = {
    '': { lockfileVersion: 3, name: 'fixture', version: '1.0.0' },
    'node_modules/circom2': { integrity: integrity('circom2@0.2.23'), resolved: 'https://registry.npmjs.org/circom2/-/circom2-0.2.23.tgz', version: '0.2.23' },
    'node_modules/snarkjs': { integrity: integrity('snarkjs@0.7.6'), resolved: 'https://registry.npmjs.org/snarkjs/-/snarkjs-0.7.6.tgz', version: '0.7.6' },
  };
  await writeFile(path.join(root, 'package-lock.json'), `${JSON.stringify({ lockfileVersion: 3, packages })}\n`);
  await writePackage(root, 'node_modules/circom2', 'circom2', '0.2.23', { 'cli.js': 'fixture circom cli\n' });
  await writePackage(root, 'node_modules/snarkjs', 'snarkjs', '0.7.6', { 'build/cli.cjs': 'fixture snarkjs cli\n' });
  const sourceManifestBytes = await writeCanonicalV2Relation(root);
  const circom = await collectNpmBuildClosure({ repositoryRoot: root, roots: ['circom2'] });
  const snarkjs = await collectNpmBuildClosure({ repositoryRoot: root, roots: ['snarkjs'] });
  const sourceManifest = {
    bytes: sourceManifestBytes.byteLength,
    path: V2_BUILD_SOURCE_MANIFEST_PATH,
    sha256: sha256(sourceManifestBytes),
  };
  const buildBytes = bytes(build({ npmClosure: circom, sourceManifest }));
  const buildArtifact = { bytes: buildBytes.byteLength, path: 'artifacts/circuit-build-attestation.json', sha256: sha256(buildBytes) };
  const r1cs = build({ npmClosure: circom }).artifacts.r1cs;
  const setupBytes = bytes(setup({ buildAttestation: buildArtifact, npmClosure: snarkjs, r1cs }));
  await assert.rejects(
    () => verifyDevelopmentSetupAttestationPair(setupBytes, {
      buildAttestationBytes: buildBytes,
      repositoryRoot: root,
    }),
    /sourceManifestBytes are required/,
  );
  const verified = await verifyDevelopmentSetupAttestationPair(setupBytes, {
    buildAttestationBytes: buildBytes,
    repositoryRoot: root,
    sourceManifestBytes,
  });
  assert.equal(verified.build.artifacts.r1cs.sha256, verified.setup.r1cs.sha256);
  const mismatchedR1cs = bytes(setup({ buildAttestation: buildArtifact, npmClosure: snarkjs, r1cs: artifact(V2_BUILD_R1CS_PATH, '0', 20) }));
  await assert.rejects(() => verifyDevelopmentSetupAttestationPair(mismatchedR1cs, {
    buildAttestationBytes: buildBytes,
    repositoryRoot: root,
    sourceManifestBytes,
  }), /R1CS differs/);
});
