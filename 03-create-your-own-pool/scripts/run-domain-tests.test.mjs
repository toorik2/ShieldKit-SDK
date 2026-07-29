import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod as fsChmod,
  lstat,
  mkdir,
  mkdtemp,
  open as fsOpen,
  readFile,
  readdir,
  rm as fsRm,
  stat,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertCompleteSelection,
  assertLocalVerifierArtifactCoherence,
  assertQualificationPrerequisites,
  createDomainTestTemporaryDirectory,
  developmentProofQualificationArguments,
  discoverDomainTests,
  DomainTestRunnerError,
  ensureLocalVerifierQualificationArtifacts,
  fileTimeoutForDomainTest,
  preflightTestSources,
  runSelectedDomainTests,
  removeDomainTestTemporaryDirectory,
  selectDomainTests,
  withPrivateSetupEntropyFd,
} from './run-domain-tests.mjs';

async function fixture(files) {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-test-runner-'));
  const root = path.join(parent, 'project');
  await Promise.all(['packages', 'scripts'].map((name) => mkdir(path.join(root, name), { recursive: true })));
  for (const [relativePath, source] of Object.entries(files)) {
    const filename = path.join(root, relativePath);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, source);
  }
  return root;
}

const passingTest = "import test from 'node:test';\ntest('passes', () => {});\n";
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const evidence = (value) => ({ bytes: Buffer.byteLength(value), sha256: sha256(value) });

function observedPrivateFilesystem(observed) {
  return {
    async mkdtemp(prefix) {
      observed.directory = await mkdtemp(prefix);
      return observed.directory;
    },
    async chmod(filename, mode) {
      observed.modes.push([filename, mode]);
      await fsChmod(filename, mode);
    },
    async open(filename, flags, mode) {
      if (flags === 'wx') observed.filename = filename;
      return fsOpen(filename, flags, mode);
    },
    rm: fsRm,
  };
}

test('private setup entropy uses one private fd and removes it on success and failure', async () => {
  const parent = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-entropy-parent-'));
  const successful = { modes: [] };
  let source;
  let modes;
  await withPrivateSetupEntropyFd(async (value) => {
    source = value;
    modes = [
      (await stat(successful.directory)).mode & 0o777,
      (await stat(successful.filename)).mode & 0o777,
    ];
  }, {
    directoryPrefix: path.join(parent, 'entropy-'),
    filesystem: observedPrivateFilesystem(successful),
    random: () => Buffer.alloc(64, 0x5a),
  });
  assert.deepEqual(source, { kind: 'fd', fd: source.fd });
  assert.deepEqual(modes, [0o700, 0o600]);
  await assert.rejects(
    () => withPrivateSetupEntropyFd(() => {
      throw new Error('injected setup failure');
    }, {
      directoryPrefix: path.join(parent, 'entropy-'),
      filesystem: observedPrivateFilesystem({ modes: [] }),
      random: () => Buffer.alloc(64, 0x5a),
    }),
    /injected setup failure/,
  );
  assert.deepEqual(await readdir(parent), []);
  await fsRm(parent, { recursive: true, force: true });
});

test('development qualification invocation binds the completed profile and exact qualified instance', () => {
  const profileCore = '../.codex-build/v2-development-profile/profile-core.json';
  const instanceId = 'ab'.repeat(32);
  const maximumLiveNotes = '32';
  const args = developmentProofQualificationArguments('/project', {
    profileCore,
    instanceId,
    maximumLiveNotes,
  });
  assert.deepEqual(args, [
    '/project/scripts/v2-development-proof-qualification.mjs',
    '--single-thread',
    '--profile-core', profileCore,
    '--r1cs', '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '--wasm', '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '--zkey', '../.codex-build/v2-dev-groth16/final.zkey',
    '--verification-key', '../.codex-build/v2-dev-groth16/verification_key.json',
    '--instance-id', instanceId,
    '--maximum-live-notes', maximumLiveNotes,
    '--output', '../.codex-build/v2-dev-proof-qualification',
  ]);
  assert.equal(args.filter((value) => value === '--single-thread').length, 1);
});

test('local verifier provisioning is an attested PF10-only pipeline in dependency order', async () => {
  const source = await readFile(new URL('./run-domain-tests.mjs', import.meta.url), 'utf8');
  const start = source.indexOf('async function provisionMissingLocalVerifierArtifacts(');
  const end = source.indexOf('\nexport async function ensureLocalVerifierQualificationArtifacts(', start);
  assert.ok(start >= 0 && end > start, 'provisioning implementation must remain inspectable');
  const provisioner = source.slice(start, end);

  // This is deliberately a direct local-toolchain pipeline. `npx` may resolve
  // a different executable than the attested dependency closure.
  assert.equal(/\bnpx\b/i.test(provisioner), false, 'provisioning must never invoke npx');
  assert.equal(
    /(?:v2-pf7-verifier-qualification|\bpf7(?:-|\b)|PF7)/.test(provisioner),
    false,
    'the PF7 topology is not a V2 deployment dependency',
  );

  const requiredFragments = [
    "path.join(projectRoot, 'scripts/v2-circuit-model.mjs')",
    "'node_modules/snarkjs/build/cli.cjs'",
    "'powersoftau', 'new'",
    "'powersoftau', 'contribute'",
    "'powersoftau', 'prepare', 'phase2'",
    'initializeDevelopmentGroth16({',
    'repositoryRoot:',
    'buildAttestationPath:',
    'verifyPtau: true',
    "path.join(projectRoot, 'scripts/v2-development-profile.mjs')",
    "'--build-attestation'",
    "'--circuit-symbols'",
    "'--initial-proving-key'",
    "'--ptau'",
    "'--proving-key'",
    "'--r1cs'",
    "'--setup-attestation'",
    "'--verification-key'",
    "'--wasm'",
    "path.join(projectRoot, 'scripts/v2-pf10-development-runtime.mjs')",
    "'--instance-id'",
    "'--profile-core'",
    "'--profile-package'",
    "'--qualification-evidence'",
    "'--temporary-root'",
  ];
  for (const fragment of requiredFragments) {
    assert.ok(provisioner.includes(fragment), `provisioning omits required fragment: ${fragment}`);
  }

  const qualificationStart = source.indexOf('export function developmentProofQualificationArguments(');
  const qualificationEnd = source.indexOf('\nasync function provisionMissingLocalVerifierArtifacts(', qualificationStart);
  assert.ok(qualificationStart >= 0 && qualificationEnd > qualificationStart);
  const qualificationArguments = source.slice(qualificationStart, qualificationEnd);
  for (const flag of ['--profile-core', '--instance-id', '--maximum-live-notes']) {
    assert.ok(qualificationArguments.includes(`'${flag}'`), `qualification omits ${flag}`);
  }

  const orderedStages = [
    "path.join(projectRoot, 'scripts/v2-circuit-model.mjs')",
    "'powersoftau', 'prepare', 'phase2'",
    'initializeDevelopmentGroth16({',
    "path.join(projectRoot, 'scripts/v2-development-profile.mjs')",
    'developmentProofQualificationArguments(projectRoot,',
    "path.join(projectRoot, 'scripts/v2-pf10-development-runtime.mjs')",
  ];
  let previous = -1;
  for (const stage of orderedStages) {
    const position = provisioner.indexOf(stage);
    assert.ok(position > previous, `provisioning order is wrong or missing stage: ${stage}`);
    previous = position;
  }
});

async function materializeCoherentDirectV2Artifacts(root) {
  const artifactRoot = path.resolve(root, '../.codex-build');
  const files = {
    r1cs: path.join(artifactRoot, 'v2-circuit-model/main-chipnet.r1cs'),
    wasm: path.join(artifactRoot, 'v2-circuit-model/main-chipnet_js/main-chipnet.wasm'),
    zkey: path.join(artifactRoot, 'v2-dev-groth16/final.zkey'),
    verificationKey: path.join(artifactRoot, 'v2-dev-groth16/verification_key.json'),
    setup: path.join(artifactRoot, 'v2-dev-groth16/setup-metadata.json'),
    qualification: path.join(artifactRoot, 'v2-dev-proof-qualification/qualification-evidence.json'),
  };
  const source = {
    r1cs: 'current-r1cs',
    wasm: 'current-wasm',
    developmentZkey: 'current-zkey',
    verificationKey: 'current-verification-key',
  };
  await Promise.all([
    writeFile(files.r1cs, source.r1cs, { flag: 'wx' }).catch(async () => {
      await mkdir(path.dirname(files.r1cs), { recursive: true });
      await writeFile(files.r1cs, source.r1cs, { flag: 'wx' });
    }),
    writeFile(files.wasm, source.wasm, { flag: 'wx' }).catch(async () => {
      await mkdir(path.dirname(files.wasm), { recursive: true });
      await writeFile(files.wasm, source.wasm, { flag: 'wx' });
    }),
    writeFile(files.zkey, source.developmentZkey, { flag: 'wx' }).catch(async () => {
      await mkdir(path.dirname(files.zkey), { recursive: true });
      await writeFile(files.zkey, source.developmentZkey, { flag: 'wx' });
    }),
    writeFile(files.verificationKey, source.verificationKey, { flag: 'wx' }).catch(async () => {
      await mkdir(path.dirname(files.verificationKey), { recursive: true });
      await writeFile(files.verificationKey, source.verificationKey, { flag: 'wx' });
    }),
  ]);
  const actions = {};
  for (const name of ['deposit', 'transfer', 'withdrawal']) {
    const directory = path.join(artifactRoot, 'v2-dev-proof-qualification', name);
    await mkdir(directory, { recursive: true });
    const input = JSON.stringify({ publicInput0: '1', publicInput1: '2' });
    const publicSignals = JSON.stringify(['1', '2']);
    const contents = {
      packet: Buffer.alloc(552, name.charCodeAt(0)),
      input,
      witness: `${name}-witness`,
      proof: `${name}-proof`,
      publicSignals,
      v2DirectGroth16Adapter: `${name}-v2-direct-groth16-adapter`,
    };
    await Promise.all([
      writeFile(path.join(directory, 'packet.bin'), contents.packet),
      writeFile(path.join(directory, 'input.json'), contents.input),
      writeFile(path.join(directory, 'witness.wtns'), contents.witness),
      writeFile(path.join(directory, 'proof.json'), contents.proof),
      writeFile(path.join(directory, 'public.json'), contents.publicSignals),
      writeFile(path.join(directory, 'v2-direct-groth16-adapter.json'), contents.v2DirectGroth16Adapter),
    ]);
    actions[name] = {
      witnessValid: true,
      proofVerified: true,
      packetDigest: sha256(contents.packet),
      publicInputs: ['1', '2'],
      files: Object.fromEntries(Object.entries(contents).map(([field, value]) => [field, evidence(value)])),
    };
  }
  const sourceArtifacts = Object.fromEntries(Object.entries(source).map(([name, value]) => [name, evidence(value)]));
  const setup = {
    schema: 'shield.cash/local-development-setup/v1',
    mode: 'development-only',
    inputs: { r1cs: { sha256: `sha256:${sourceArtifacts.r1cs.sha256}` } },
    outputs: {
      provingKey: { sha256: `sha256:${sourceArtifacts.developmentZkey.sha256}` },
      verificationKey: { sha256: `sha256:${sourceArtifacts.verificationKey.sha256}` },
    },
    setup: { material: { phase2: { finalZkeySha256: `sha256:${sourceArtifacts.developmentZkey.sha256}` } } },
  };
  await mkdir(path.dirname(files.setup), { recursive: true });
  await writeFile(files.setup, JSON.stringify(setup));
  const qualification = {
    schema: 'shieldkit-v2-direct-development-groth16-qualification-v4',
    evidenceClass: 'deterministic-development-key-proof-test-evidence',
    claims: { developmentKey: true, finalKey: false, bchVm: false, production: false },
    sourceArtifacts,
    actions,
  };
  await writeFile(files.qualification, JSON.stringify(qualification));
  return files;
}

test('new nested V2 tests are mandatory and selection omissions fail closed', async () => {
  const root = await fixture({
    'packages/action/base.test.mjs': passingTest,
    'packages/action/v2/new-security.test.mjs': passingTest,
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  const selected = selectDomainTests(discovery);
  assert.deepEqual(selected.map((entry) => entry.relativePath), [
    'packages/action/base.test.mjs',
    'packages/action/v2/new-security.test.mjs',
  ]);
  assert.throws(
    () => assertCompleteSelection(discovery, selected.slice(0, 1)),
    /omitted=.*new-security/,
  );
});

test('heavy local V2 mutation campaigns are explicit, complete, and never silently portable', async () => {
  const strictCodec = 'packages/action/v2/strict-codec-qualification.test.mjs';
  const typescriptParity = 'packages/action/v2/typescript/parity.test.mjs';
  const depth4 = 'packages/action/v2/tree-qualification-depth4.test.mjs';
  const root = await fixture({
    'packages/action/v2/core.test.mjs': passingTest,
    [strictCodec]: passingTest,
    [typescriptParity]: passingTest,
    [depth4]: passingTest,
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  assert.deepEqual(
    selectDomainTests(discovery, 'portable').map((entry) => entry.relativePath),
    ['packages/action/v2/core.test.mjs'],
  );
  const codecCampaign = selectDomainTests(discovery, 'local-strict-codec-campaign');
  assert.deepEqual(codecCampaign.map((entry) => entry.relativePath), [
    strictCodec,
    typescriptParity,
  ]);
  assert.deepEqual(
    selectDomainTests(discovery, 'local-depth4-campaign').map((entry) => entry.relativePath),
    [depth4],
  );
  assert.throws(
    () => assertCompleteSelection(discovery, codecCampaign.slice(0, 1), 'local-strict-codec-campaign'),
    /omitted=.*typescript\/parity/,
  );
});

test('the exhaustive production depth-4 state-space campaign is mandatory and has an explicit supervisor deadline', async () => {
  const productionStateSpace = 'packages/pool/v2/qualification/depth4-production-state-space.test.mjs';
  const structuralDepth4 = 'packages/action/v2/tree-qualification-depth4.test.mjs';
  const root = await fixture({
    'packages/action/v2/core.test.mjs': passingTest,
    [productionStateSpace]: passingTest,
    [structuralDepth4]: passingTest,
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  const portable = selectDomainTests(discovery, 'portable');
  const depth4 = selectDomainTests(discovery, 'local-depth4-campaign');
  assert.deepEqual(portable.map((entry) => entry.relativePath), ['packages/action/v2/core.test.mjs']);
  assert.deepEqual(depth4.map((entry) => entry.relativePath), [
    structuralDepth4,
    productionStateSpace,
  ]);
  assert.equal(fileTimeoutForDomainTest(portable[0]), 180_000);
  for (const record of depth4) {
    assert.equal(fileTimeoutForDomainTest(record), 360_000);
  }
  assert.throws(
    () => assertCompleteSelection(discovery, depth4.slice(0, 1), 'local-depth4-campaign'),
    /omitted=.*depth4-production-state-space/,
  );
  assert.throws(
    () => fileTimeoutForDomainTest({ classification: 'portable' }, { defaultTimeoutMs: 0 }),
    /invalid default per-file timeout/,
  );
});

test('tracked pinned verifier-lane tests bypass the bulk vendor exclusion', async () => {
  const laneTest = `${'packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/test'}/new-v2.test.mjs`;
  const root = await fixture({
    'packages/action/base.test.mjs': passingTest,
    [laneTest]: passingTest,
    'packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/test/legacy-c7-config.test.mjs': passingTest,
    'packages/action/vendor/upstream.test.mjs': passingTest,
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  assert.deepEqual(
    selectDomainTests(discovery, 'local-verifier-lane').map((entry) => entry.relativePath),
    [laneTest],
  );
  assert.deepEqual(
    selectDomainTests(discovery, 'external-verifier-source').map((entry) => entry.relativePath),
    ['packages/unlock-builder/vendor/verifier/lanes/bn254-onetx/test/legacy-c7-config.test.mjs'],
  );
  assert.equal(discovery.tests.some((entry) => entry.relativePath.endsWith('upstream.test.mjs')), false);
  assert.equal(discovery.ignoredScopes[0].classification, 'third-party-vendor-excluded');
});

test('artifact-gated V2 verifier reality tests remain local qualifications', async () => {
  const pf10 = 'packages/unlock-builder/v2/pf10-withdrawal.test.mjs';
  const pairfold = 'packages/unlock-builder/v2/total-pairfold.test.mjs';
  const root = await fixture({
    'packages/action/base.test.mjs': passingTest,
    [pf10]: passingTest,
    [pairfold]: passingTest,
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  const selected = selectDomainTests(discovery, 'local-verifier-lane');
  assert.deepEqual(selected.map((entry) => entry.relativePath), [pf10, pairfold]);
  assert.match(selected[0].reason, /artifact-dependent/);
  await assert.rejects(
    () => assertQualificationPrerequisites(selected, {
      projectRoot: root,
      suite: 'local-verifier-lane',
    }),
    /BLOCKED.*\.\.\/\.codex-build\/v2-dev-groth16\/verification_key\.json/,
  );
});

test('local qualification preflight requires its materialized toolchain and proof artifacts', async () => {
  const pf10 = 'packages/unlock-builder/v2/pf10-withdrawal.test.mjs';
  const root = await fixture({ [pf10]: passingTest });
  const selected = selectDomainTests(
    discoverDomainTests({ projectRoot: root }),
    'local-verifier-lane',
  );
  const prerequisites = [
    'packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js',
    '../.codex-build/v2-circuit-model/main-chipnet.r1cs',
    '../.codex-build/v2-dev-groth16/verification_key.json',
    '../.codex-build/v2-dev-groth16/final.zkey',
    '../.codex-build/v2-dev-groth16/setup-metadata.json',
    '../.codex-build/v2-circuit-model/main-chipnet_js/main-chipnet.wasm',
    '../.codex-build/v2-dev-proof-qualification/qualification-evidence.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/packet.bin',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/input.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/proof.json',
    '../.codex-build/v2-dev-proof-qualification/withdrawal/public.json',
  ];
  await Promise.all(prerequisites.map(async (relativePath) => {
    const filename = path.join(root, relativePath);
    await mkdir(path.dirname(filename), { recursive: true });
    await writeFile(filename, 'fixture');
  }));
  await assert.rejects(
    () => assertQualificationPrerequisites(selected, {
      projectRoot: root,
      suite: 'local-verifier-lane',
    }),
    /artifact coherence is BLOCKED/,
  );
});

test('local verifier provisioning is mandatory before artifact-gated tests can run', async () => {
  const pf10 = 'packages/unlock-builder/v2/pf10-withdrawal.test.mjs';
  const root = await fixture({ [pf10]: passingTest });
  const selected = selectDomainTests(
    discoverDomainTests({ projectRoot: root }),
    'local-verifier-lane',
  );
  let invoked = false;
  await assert.rejects(
    () => ensureLocalVerifierQualificationArtifacts(selected, {
      projectRoot: root,
      provision: async ({ selected: received }) => {
        invoked = true;
        assert.deepEqual(received, selected);
        return { provisioned: true, missing: ['required-artifact'] };
      },
    }),
    /BLOCKED/,
  );
  assert.equal(invoked, true);
});

test('artifact-gated local verifier tests require one coherent current artifact set', async () => {
  const pf10 = 'packages/unlock-builder/v2/pf10-withdrawal.test.mjs';
  const root = await fixture({ [pf10]: passingTest });
  const files = await materializeCoherentDirectV2Artifacts(root);
  await mkdir(path.join(
    root,
    'packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist',
  ), { recursive: true });
  await writeFile(path.join(
    root,
    'packages/unlock-builder/vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js',
  ), 'toolchain');
  const selected = selectDomainTests(
    discoverDomainTests({ projectRoot: root }),
    'local-verifier-lane',
  );
  await assert.doesNotReject(() => assertLocalVerifierArtifactCoherence({ projectRoot: root }));
  const artifactPaths = Object.freeze({
    evidence: path.resolve(files.qualification),
    evidenceRoot: path.resolve(path.dirname(files.qualification)),
    r1cs: path.resolve(files.r1cs),
    setupMetadata: path.resolve(files.setup),
    verificationKey: path.resolve(files.verificationKey),
    wasm: path.resolve(files.wasm),
    zkey: path.resolve(files.zkey),
  });
  await assert.doesNotReject(() =>
    assertLocalVerifierArtifactCoherence({ artifactPaths }));
  await assert.rejects(
    () => assertLocalVerifierArtifactCoherence({
      artifactPaths: { ...artifactPaths, unknown: '/tmp/unknown' },
    }),
    /missing or unknown properties/,
  );
  await assert.doesNotReject(() => ensureLocalVerifierQualificationArtifacts(selected, {
    projectRoot: root,
    provision: async () => ({ provisioned: false, missing: [] }),
  }));
  await writeFile(files.r1cs, 'drifted-r1cs');
  await assert.rejects(
    () => ensureLocalVerifierQualificationArtifacts(selected, {
      projectRoot: root,
      provision: async () => ({ provisioned: false, missing: [] }),
    }),
    /setup metadata does not bind the current R1CS/,
  );
  await writeFile(files.r1cs, 'current-r1cs');
  await writeFile(
    path.join(path.dirname(files.qualification), 'withdrawal/proof.json'),
    'drifted-proof',
  );
  await assert.rejects(
    () => assertLocalVerifierArtifactCoherence({ projectRoot: root }),
    /files\.proof differs from the qualification evidence/,
  );
});

test('CI provisions local verifier artifacts before executing the lane', async () => {
  const workflow = await readFile(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const packageJson = JSON.parse(await readFile(new URL('../../package.json', import.meta.url), 'utf8'));
  const provision = 'npm run qualification:local-verifier-artifacts';
  const lane = 'npm run test:qualification:local-verifier-lane';
  assert.ok(workflow.indexOf(provision) >= 0);
  assert.ok(workflow.indexOf(provision) < workflow.indexOf(lane));
  assert.equal(
    packageJson.scripts['qualification:local-verifier-artifacts'],
    'node 03-create-your-own-pool/scripts/run-domain-tests.mjs --provision-local-verifier-artifacts',
  );
  assert.match(workflow, /run_local_verifier_qualification/);
  assert.match(
    workflow,
    /if: github\.event_name == 'workflow_dispatch' && inputs\.run_local_verifier_qualification/,
  );
  assert.equal(
    packageJson.scripts['test:v2:campaign:strict-codec'],
    'node 03-create-your-own-pool/scripts/run-domain-tests.mjs --suite local-strict-codec-campaign',
  );
  assert.equal(
    packageJson.scripts['test:v2:campaign:depth4'],
    'node 03-create-your-own-pool/scripts/run-domain-tests.mjs --suite local-depth4-campaign',
  );
  assert.equal(
    packageJson.scripts['qualification:v2:crash10k'],
    'node 03-create-your-own-pool/scripts/v2-crash-qualification.mjs',
  );
  assert.equal(
    packageJson.scripts['qualification:v2:reorg-concurrency'],
    'node 03-create-your-own-pool/scripts/v2-reorg-concurrency-qualification.mjs',
  );
  assert.equal(
    packageJson.scripts['qualification:v2:pf10-libauth'],
    'node 03-create-your-own-pool/scripts/v2-pf10-libauth-qualification.mjs',
  );
});

test('CI runs both V2 campaigns as mandatory immutable jobs', async () => {
  const workflow = await readFile(new URL('../../.github/workflows/ci.yml', import.meta.url), 'utf8');
  const campaigns = [
    ['strict-codec-campaign', 'npm run test:v2:campaign:strict-codec'],
    ['depth4-campaign', 'npm run test:v2:campaign:depth4'],
  ];
  for (const [job, command] of campaigns) {
    const marker = `  ${job}:\n`;
    const start = workflow.indexOf(marker);
    assert.notEqual(start, -1, `workflow must define ${job}`);
    const remainder = workflow.slice(start + marker.length);
    const nextJob = /^  [a-z0-9-]+:\n/m.exec(remainder);
    const block = remainder.slice(0, nextJob?.index ?? remainder.length);
    const install = block.indexOf('run: npm ci');
    const campaign = block.indexOf(`run: ${command}`);
    assert.notEqual(install, -1, `${job} must install from the immutable lockfile`);
    assert.notEqual(campaign, -1, `${job} must run ${command}`);
    assert.ok(install < campaign, `${job} must install before running the campaign`);
    assert.doesNotMatch(block, /^\s+(?:if|continue-on-error):/m);
  }
});

test('empty files and explicit fixture gating fail before execution', async () => {
  const emptyRoot = await fixture({ 'packages/action/empty.test.mjs': "import test from 'node:test';\n" });
  const empty = selectDomainTests(discoverDomainTests({ projectRoot: emptyRoot }));
  assert.throws(() => preflightTestSources(empty), /declares no tests/);

  const gatedRoot = await fixture({
    'packages/action/gated.test.mjs': [
      "import test from 'node:test';",
      "test('gated', { " + "sk" + "ip: 'fixture absent' }, () => {});",
      '',
    ].join('\n'),
  });
  const gated = selectDomainTests(discoverDomainTests({ projectRoot: gatedRoot }));
  assert.throws(() => preflightTestSources(gated), /fixture gating/);
});

test('only explicitly classified external fixtures may contain source gates', async () => {
  const root = await fixture({
    'packages/action/witness.test.mjs': [
      "import test from 'node:test';",
      "test('fixture', { " + "sk" + "ip: 'fixture absent' }, () => {});",
      '',
    ].join('\n'),
  });
  const discovery = discoverDomainTests({ projectRoot: root });
  const selected = selectDomainTests(discovery, 'external-fixtures');
  assert.throws(() => preflightTestSources(selected), /fixture gating/);
  assert.doesNotThrow(() => preflightTestSources(selected, {
    allowClassifiedFixtureGates: true,
  }));
  assert.throws(
    () => runSelectedDomainTests(selected, { cwd: root }),
    /was not fully executed/,
  );
});

test('runtime skips and todos fail even if hidden from source preflight', async () => {
  const root = await fixture({
    'packages/action/runtime.test.mjs': [
      "import test from 'node:test';",
      "const option = { ['sk' + 'ip']: 'hidden gate' };",
      "test('hidden', option, () => {});",
      '',
    ].join('\n'),
  });
  const selected = selectDomainTests(discoverDomainTests({ projectRoot: root }));
  assert.doesNotThrow(() => preflightTestSources(selected));
  assert.throws(
    () => runSelectedDomainTests(selected, { cwd: root }),
    DomainTestRunnerError,
  );
});

test('domain-test child temporary roots are contained, private, and refuse unmanaged cleanup', async () => {
  const root = await fixture({});
  const temporary = createDomainTestTemporaryDirectory(root);
  const expectedBuildRoot = path.resolve(root, '../.codex-build');
  assert.equal(temporary.root, expectedBuildRoot);
  assert.equal(path.dirname(temporary.directory), expectedBuildRoot);
  assert.equal(path.basename(temporary.directory).startsWith('domain-test-run-'), true);
  assert.equal((await lstat(temporary.directory)).mode & 0o777, 0o700);
  assert.throws(
    () => removeDomainTestTemporaryDirectory({
      root: expectedBuildRoot,
      directory: expectedBuildRoot,
    }),
    /refusing unmanaged/,
  );
  assert.equal((await lstat(expectedBuildRoot)).isDirectory(), true);
  removeDomainTestTemporaryDirectory(temporary);
  await assert.rejects(lstat(temporary.directory), /ENOENT/);
});

test('domain-test runner propagates only a private child temp root and cleans it on success and error', async () => {
  const successRoot = await fixture({
    'packages/action/temp-success.test.mjs': [
      "import assert from 'node:assert/strict';",
      "import { writeFileSync } from 'node:fs';",
      "import test from 'node:test';",
      "test('private temp', () => {",
      "  assert.equal(process.env.TMPDIR, process.env.TMP);",
      "  assert.equal(process.env.TMPDIR, process.env.TEMP);",
      "  writeFileSync(process.env.DOMAIN_TEST_MARKER, process.env.TMPDIR);",
      "});",
      '',
    ].join('\n'),
  });
  const successMarker = path.join(path.dirname(successRoot), 'success-marker');
  const successSelected = selectDomainTests(
    discoverDomainTests({ projectRoot: successRoot }),
  );
  const inherited = {
    ...process.env,
    DOMAIN_TEST_MARKER: successMarker,
    TMPDIR: '/shared-tmp',
    TMP: '/shared-tmp',
    TEMP: '/shared-tmp',
  };
  runSelectedDomainTests(successSelected, {
    cwd: successRoot,
    environment: inherited,
  });
  const successTemporary = await readFile(successMarker, 'utf8');
  assert.equal(path.dirname(successTemporary), path.resolve(successRoot, '../.codex-build'));
  assert.equal(path.basename(successTemporary).startsWith('domain-test-run-'), true);
  await assert.rejects(lstat(successTemporary), /ENOENT/);
  assert.equal(inherited.TMPDIR, '/shared-tmp');

  const errorRoot = await fixture({
    'packages/action/temp-error.test.mjs': [
      "import { writeFileSync } from 'node:fs';",
      "import test from 'node:test';",
      "test('private temp failure', () => {",
      "  writeFileSync(process.env.DOMAIN_TEST_MARKER, process.env.TMPDIR);",
      "  throw new Error('injected child failure');",
      "});",
      '',
    ].join('\n'),
  });
  const errorMarker = path.join(path.dirname(errorRoot), 'error-marker');
  const errorSelected = selectDomainTests(
    discoverDomainTests({ projectRoot: errorRoot }),
  );
  assert.throws(
    () => runSelectedDomainTests(errorSelected, {
      cwd: errorRoot,
      environment: { ...process.env, DOMAIN_TEST_MARKER: errorMarker },
    }),
    /node test runner failed/,
  );
  const errorTemporary = await readFile(errorMarker, 'utf8');
  await assert.rejects(lstat(errorTemporary), /ENOENT/);
});
