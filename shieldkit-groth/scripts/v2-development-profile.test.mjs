// A tiny relation is adversarial input only. It must never be accepted as
// evidence for the checked-in V2 source graph.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import test from 'node:test';
import { readBinFile } from '@iden3/binfileutils';
import { readR1csHeader } from 'r1csfile';

import {
  buildV2DevelopmentProfilePackage,
  inspectV2DevelopmentProfilePackage,
  V2DevelopmentProfileError,
} from '../packages/profile/v2/development-profile.mjs';
import {
  canonicalCircuitBuildAttestation,
  canonicalDevelopmentSetupAttestation,
  CIRCUIT_BUILD_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
  DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
} from '../packages/profile/v2/build-attestation.mjs';
import { collectNpmBuildClosure } from '../packages/profile/v2/npm-closure.mjs';
import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  collectV2RelationSourceManifest,
} from '../packages/profile/v2/relation-source-manifest.mjs';
import {
  initializeDevelopmentGroth16,
} from '../packages/profile/setup/development.mjs';
import {
  parseV2DevelopmentProfileArguments,
  runV2DevelopmentProfile,
} from './v2-development-profile.mjs';

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, '../..');
const circomCli = fileURLToPath(import.meta.resolve('circom2/cli.js'));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const requiredArguments = () => [
  '--build-attestation', 'proof/circuit-build-attestation.json',
  '--circuit-symbols', 'circuit/main.sym',
  '--initial-proving-key', 'proof/initial.zkey',
  '--ptau', 'proof/powers-of-tau.ptau',
  '--proving-key', 'proof/final.zkey',
  '--r1cs', 'circuit/main.r1cs',
  '--setup-attestation', 'proof/development-setup-attestation.json',
  '--verification-key', 'proof/verification_key.json',
  '--wasm', 'circuit/main.wasm',
  '--output', 'profile-package',
];

async function temporaryDirectory(t) {
  const root = path.join(repositoryRoot, '.tmp', 'v2-development-profile-test');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  const directory = await mkdtemp(path.join(root, 'v2-development-profile-test-'));
  await chmod(directory, 0o700);
  t.after(async () => {
    await rm(directory, { recursive: true, force: true });
  });
  return directory;
}

async function evidence(filename) {
  const bytes = await readFile(filename);
  return Object.freeze({ bytes: bytes.byteLength, sha256: sha256(bytes) });
}

function closureArtifact(closure, packagePath, relative) {
  const entry = closure.packages.find((candidate) => candidate.packagePath === packagePath);
  const file = entry?.installed.files.find((candidate) => candidate.path === relative);
  assert.ok(file, `missing ${packagePath}/${relative} from npm closure`);
  return Object.freeze({
    bytes: file.bytes,
    path: `${packagePath}/${relative}`,
    sha256: file.sha256,
  });
}

async function r1csAbi(filename) {
  const { fd, sections } = await readBinFile(filename, 'r1cs', 1, 1 << 22, 1 << 24);
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
  const source = path.join(root, 'main-chipnet.circom');
  const output = path.join(root, 'tiny-compiled');
  await mkdir(output, { mode: 0o700 });
  await writeFile(source, [
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
  ].join('\n'), { mode: 0o600 });
  await execFileAsync(process.execPath, [
    circomCli, source,
    '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2',
    '--output', output,
  ], { cwd: root, env: {} });
  const compiled = Object.freeze({
    r1cs: path.join(output, 'main-chipnet.r1cs'),
    sym: path.join(output, 'main-chipnet.sym'),
    wasm: path.join(output, 'main-chipnet_js', 'main-chipnet.wasm'),
  });
  const abi = await r1csAbi(compiled.r1cs);
  assert.deepEqual(
    { publicInputs: abi.publicInputs, publicOutputs: abi.publicOutputs },
    { publicInputs: 2, publicOutputs: 0 },
  );
  assert.ok(abi.privateInputs >= 1, 'fixture must retain at least one private input');
  return Object.freeze({ ...compiled, abi });
}

async function makeCanonicalBuildAttestation(root, compiled) {
  const closure = await collectNpmBuildClosure({
    repositoryRoot,
    roots: ['circom2'],
  });
  const relation = await collectV2RelationSourceManifest({ repositoryRoot });
  const relationBytes = Buffer.from(canonicalizeJcs(relation), 'utf8');
  const relationPath = path.join(root, 'relation-source-manifest.json');
  await writeFile(relationPath, relationBytes, { mode: 0o600 });
  const [r1cs, sym, wasm] = await Promise.all([
    evidence(compiled.r1cs), evidence(compiled.sym), evidence(compiled.wasm),
  ]);
  const build = canonicalCircuitBuildAttestation({
    schema: CIRCUIT_BUILD_ATTESTATION_SCHEMA,
    claims: { developmentOnly: true, production: false, release: false },
    compilation: {
      argv: [
        'node_modules/circom2/cli.js',
        'shieldkit-groth/circuits/v2-direct/main-chipnet.circom',
        '--r1cs', '--wasm', '--sym', '--O1', '--sanity_check', '2',
        '--output', '$BUILD_OUTPUT',
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
    sourceManifest: {
      bytes: relationBytes.byteLength,
      path: 'relation-source-manifest.json',
      sha256: sha256(relationBytes),
    },
    artifacts: {
      r1cs: { ...r1cs, path: 'main-chipnet.r1cs' },
      sym: { ...sym, path: 'main-chipnet.sym' },
      wasm: { ...wasm, path: 'main-chipnet_js/main-chipnet.wasm' },
    },
  });
  const filename = path.join(root, 'circuit-build-attestation.json');
  await writeFile(filename, build.bytes, { mode: 0o600 });
  return Object.freeze({ bytes: build.bytes, filename });
}

function attestationArtifact(pathname, value) {
  return Object.freeze({
    bytes: value.bytes,
    path: pathname,
    sha256: value.sha256,
  });
}

async function tinyArtifactFixture(t) {
  const root = await temporaryDirectory(t);
  const compiled = await compileTinyCircuit(root);
  const build = await makeCanonicalBuildAttestation(root, compiled);
  const relation = await collectV2RelationSourceManifest({ repositoryRoot });
  const sourceManifestPath = path.join(root, 'relation-source-manifest.json');
  await writeFile(
    sourceManifestPath,
    Buffer.from(canonicalizeJcs(relation), 'utf8'),
    { mode: 0o600 },
  );
  // These deliberately invalid ceremony artifacts are linked only to reach
  // profile verification. Independent V2 build reproduction must reject the
  // tiny R1CS before any of them can be consumed as setup evidence.
  const fakeArtifacts = Object.freeze({
    initialProvingKey: path.join(root, 'initial.zkey'),
    powersOfTau: path.join(root, 'powers-of-tau.ptau'),
    provingKey: path.join(root, 'final.zkey'),
    verificationKey: path.join(root, 'verification_key.json'),
  });
  await Promise.all([
    writeFile(fakeArtifacts.initialProvingKey, 'not-a-zkey-initial', { mode: 0o600 }),
    writeFile(fakeArtifacts.powersOfTau, 'not-a-ptau', { mode: 0o600 }),
    writeFile(fakeArtifacts.provingKey, 'not-a-zkey-final', { mode: 0o600 }),
    writeFile(fakeArtifacts.verificationKey, '{}', { mode: 0o600 }),
  ]);
  const [initialProvingKey, powersOfTau, provingKey, verificationKey] = await Promise.all([
    evidence(fakeArtifacts.initialProvingKey),
    evidence(fakeArtifacts.powersOfTau),
    evidence(fakeArtifacts.provingKey),
    evidence(fakeArtifacts.verificationKey),
  ]);
  const snarkjsClosure = await collectNpmBuildClosure({
    repositoryRoot,
    roots: ['snarkjs'],
  });
  const setup = canonicalDevelopmentSetupAttestation({
    schema: DEVELOPMENT_SETUP_ATTESTATION_SCHEMA,
    claims: {
      contributionIndependence: 'not-established',
      developmentOnly: true,
      externalTranscript: false,
      finalCeremony: false,
      production: false,
      release: false,
    },
    buildAttestation: attestationArtifact('circuit-build-attestation.json', {
      bytes: build.bytes.byteLength,
      sha256: sha256(build.bytes),
    }),
    r1cs: attestationArtifact('main-chipnet.r1cs', await evidence(compiled.r1cs)),
    ptau: {
      artifact: attestationArtifact('powers-of-tau.ptau', powersOfTau),
      ceremonyPower: 4,
      power: 4,
      source: 'tiny-artifact-rejection-test',
      verified: true,
    },
    snarkjs: {
      cli: closureArtifact(snarkjsClosure, 'node_modules/snarkjs', 'build/cli.cjs'),
      node: { modulesAbi: process.versions.modules, version: process.versions.node },
      npmClosure: snarkjsClosure,
      packageMetadata: closureArtifact(snarkjsClosure, 'node_modules/snarkjs', 'package.json'),
      version: '0.7.6',
    },
    commands: {
      powersOfTauVerify: ['node_modules/snarkjs/build/cli.cjs', 'powersoftau', 'verify', '$PTAU'],
      setup: ['node_modules/snarkjs/build/cli.cjs', 'groth16', 'setup', '$R1CS', '$PTAU', '$INITIAL_ZKEY'],
      contribute: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'contribute', '$INPUT_ZKEY', '$OUTPUT_ZKEY'],
      verifyFinalZkey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'verify', '$R1CS', '$PTAU', '$FINAL_ZKEY'],
      exportVerificationKey: ['node_modules/snarkjs/build/cli.cjs', 'zkey', 'export', 'verificationkey', '$FINAL_ZKEY', '$VERIFICATION_KEY'],
    },
    zkeyChain: {
      contributions: [{
        entropyCommitment: '11'.repeat(32),
        entropyCommitmentDomain: DEVELOPMENT_SETUP_ENTROPY_COMMITMENT_DOMAIN,
        inputZkeySha256: initialProvingKey.sha256,
        output: attestationArtifact('final.zkey', provingKey),
        sequence: 1,
      }],
      initial: attestationArtifact('initial.zkey', initialProvingKey),
    },
    finalEvidence: {
      finalZkeySha256: provingKey.sha256,
      finalZkeyVerified: true,
      verificationKey: attestationArtifact('verification_key.json', verificationKey),
      verificationKeyExported: true,
    },
  });
  const developmentSetupAttestationPath = path.join(
    root,
    'development-setup-attestation.json',
  );
  await writeFile(developmentSetupAttestationPath, setup.bytes, { mode: 0o600 });
  return Object.freeze({
    circuitBuildAttestationPath: build.filename,
    circuitSymbolPath: compiled.sym,
    developmentSetupAttestationPath,
    initialProvingKeyPath: fakeArtifacts.initialProvingKey,
    ptauPath: fakeArtifacts.powersOfTau,
    provingKeyPath: fakeArtifacts.provingKey,
    r1csPath: compiled.r1cs,
    root,
    sourceManifestPath,
    verificationKeyPath: fakeArtifacts.verificationKey,
    witnessWasmPath: compiled.wasm,
  });
}

test('development-profile CLI requires one exact explicit path for each input', () => {
  assert.deepEqual(
    parseV2DevelopmentProfileArguments(requiredArguments(), '/profile'),
    {
      circuitBuildAttestationPath: path.resolve('/profile/proof/circuit-build-attestation.json'),
      circuitSymbolPath: path.resolve('/profile/circuit/main.sym'),
      developmentSetupAttestationPath: path.resolve('/profile/proof/development-setup-attestation.json'),
      initialProvingKeyPath: path.resolve('/profile/proof/initial.zkey'),
      outputDirectory: path.resolve('/profile/profile-package'),
      provingKeyPath: path.resolve('/profile/proof/final.zkey'),
      ptauPath: path.resolve('/profile/proof/powers-of-tau.ptau'),
      r1csPath: path.resolve('/profile/circuit/main.r1cs'),
      verificationKeyPath: path.resolve('/profile/proof/verification_key.json'),
      witnessWasmPath: path.resolve('/profile/circuit/main.wasm'),
    },
  );
  for (const argv of [
    undefined,
    ['--r1cs', 'only.r1cs'],
    [...requiredArguments(), '--output', 'again'],
    ['--unknown', 'forbidden', ...requiredArguments()],
    requiredArguments().filter((value) => value !== '--ptau' && value !== 'proof/powers-of-tau.ptau'),
  ]) {
    assert.throws(
      () => parseV2DevelopmentProfileArguments(argv, '/profile'),
      (error) => error instanceof V2DevelopmentProfileError
        && error.code === 'PROFILE_ARGUMENT_INVALID',
    );
  }
});

// Parser-only malformed envelopes are intentionally synthetic. The rejection
// test below invokes live V2 source reproduction; it never treats Tiny as V2
// evidence.
test('development-profile package inspection refuses malformed schema envelopes', () => {
  for (const value of [
    null,
    [],
    {},
    {
      schema: 'shieldkit-v2-direct-development-profile-package-v0',
      eligibility: 'development-only',
      profileId: '00'.repeat(32),
      profileCoreSha256: '00'.repeat(32),
    },
    {
      schema: 'shieldkit-v2-direct-development-profile-package-v1',
      eligibility: 'final-qualified',
      profileId: '00'.repeat(32),
      profileCoreSha256: '00'.repeat(32),
    },
    {
      schema: 'shieldkit-v2-direct-development-profile-package-v1',
      eligibility: 'development-only',
      profileId: 'not-a-hash',
      profileCoreSha256: '00'.repeat(32),
    },
  ]) {
    assert.throws(
      () => inspectV2DevelopmentProfilePackage(value),
      (error) => error instanceof V2DevelopmentProfileError
        && error.code === 'PROFILE_PACKAGE_INVALID',
    );
  }
});

test('development-profile runner fails at argument validation before any builder work', async () => {
  await assert.rejects(
    runV2DevelopmentProfile(['--output', 'only-output']),
    (error) => error instanceof V2DevelopmentProfileError
      && error.code === 'PROFILE_ARGUMENT_INVALID',
  );
});

test('development-profile rejects a tiny artifact at V2 build, setup, and profile verification without publication', async (t) => {
  const inputs = await tinyArtifactFixture(t);
  const setupDestination = path.join(inputs.root, 'must-not-publish-setup');
  await assert.rejects(
    initializeDevelopmentGroth16({
      buildAttestationPath: inputs.circuitBuildAttestationPath,
      destination: setupDestination,
      entropySource: { kind: 'fd', fd: 0 },
      expectedPtauPower: 4,
      expectedPtauSha256: `sha256:${'00'.repeat(32)}`,
      expectedR1csSha256: `sha256:${sha256(await readFile(inputs.r1csPath))}`,
      expectedSnarkjs: { version: '0.7.6', cliSha256: '00'.repeat(32) },
      ptauPath: inputs.ptauPath,
      ptauSource: 'tiny-artifact-rejection-test',
      repositoryRoot,
      r1csPath: inputs.r1csPath,
      sourceManifestPath: inputs.sourceManifestPath,
      verifyPtau: true,
    }),
    /circuit build cannot be independently reproduced/,
  );
  await assert.rejects(() => lstat(setupDestination));

  const outputDirectory = path.join(inputs.root, 'must-not-publish-profile');
  await assert.rejects(
    buildV2DevelopmentProfilePackage({
      repositoryRoot,
      ...inputs,
      outputDirectory,
    }),
    (error) => error?.code === 'PROFILE_PACKAGE_INVALID',
  );
  await assert.rejects(() => lstat(outputDirectory));
  assert.deepEqual(
    (await readdir(inputs.root)).filter((name) => name.startsWith('.shieldkit-v2-development-profile-')),
    [],
  );
});

test('development-profile rejects symlinked/hardlinked evidence and cleans only its private staging directory', async (t) => {
  const inputs = await tinyArtifactFixture(t);
  const linkedR1cs = path.join(inputs.root, 'linked.r1cs');
  await symlink(inputs.r1csPath, linkedR1cs);
  await assert.rejects(
    buildV2DevelopmentProfilePackage({
      repositoryRoot,
      ...inputs,
      r1csPath: linkedR1cs,
      outputDirectory: path.join(inputs.root, 'symlink-output'),
    }),
    (error) => error?.code === 'PROFILE_PATH_INVALID',
  );
  const hardlinkedWasm = path.join(inputs.root, 'hardlinked.wasm');
  await link(inputs.witnessWasmPath, hardlinkedWasm);
  await assert.rejects(
    buildV2DevelopmentProfilePackage({
      repositoryRoot,
      ...inputs,
      witnessWasmPath: hardlinkedWasm,
      outputDirectory: path.join(inputs.root, 'hardlink-output'),
    }),
    (error) => error?.code === 'PROFILE_PATH_INVALID',
  );
  await unlink(hardlinkedWasm);
  assert.deepEqual(
    (await readdir(inputs.root)).filter((name) => name.startsWith('.shieldkit-v2-development-profile-')),
    [],
  );
});
