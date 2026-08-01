import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
} from 'node:crypto';
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import { canonicalJson } from '../packages/profile/load.mjs';
import {
  BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
  createBetaSingleContributorContributionRequest,
} from '../packages/profile/setup/external-contribution.mjs';
import {
  BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
} from '../packages/profile/setup/beta-single-contributor-entropy.mjs';
import {
  collectV2FinalZkeyToolchainManifest,
} from '../packages/profile/v2/final-zkey-verification.mjs';
import {
  assertV2BetaSingleContributorCleanCheckout,
  assertV2BetaSingleContributorSourceBinding,
  collectV2BetaSingleContributorImplementationManifest,
  contributeV2BetaSingleContributorCeremony,
  parseV2BetaSingleContributorArguments,
  preflightV2BetaSingleContributorCeremony,
  V2_BETA_SINGLE_CONTRIBUTOR_PREPARATION_SCHEMA,
  V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA,
  V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA,
  verifyV2BetaSingleContributorCeremony,
} from './v2-beta-single-contributor-ceremony.mjs';

const execFileAsync = promisify(execFile);
const snarkjsRoot = path.dirname(fileURLToPath(import.meta.resolve('snarkjs')));
const repositoryRoot = path.dirname(path.dirname(snarkjsRoot));
const snarkjsCli = path.join(snarkjsRoot, 'build', 'cli.cjs');
const circom2Cli = path.join(repositoryRoot, 'node_modules', 'circom2', 'cli.js');
const digest = async (filename) =>
  `sha256:${createHash('sha256').update(await readFile(filename)).digest('hex')}`;
const digestBytes = (bytes) =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const FALSE_CLAIMS = Object.freeze({
  b02Qualified: false,
  ceremonyQualified: false,
  d01Qualified: false,
  d02Qualified: false,
  finalKey: false,
  participantIndependenceEstablished: false,
  production: false,
  q01FinalReplayQualified: false,
  q02Qualified: false,
  q03Qualified: false,
  q07Qualified: false,
  q08Qualified: false,
  q09Qualified: false,
  releaseQualified: false,
});

test('historical ceremony Git reads disable local replace objects', async () => {
  const source = await readFile(
    new URL('./v2-beta-single-contributor-ceremony.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /\['--no-replace-objects', \.\.\.args\]/u);
});

async function writeCanonical(filename, value) {
  await writeFile(filename, canonicalJson(value), { mode: 0o600, flag: 'wx' });
}

async function createCleanGitFixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-beta-git-'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const git = (args) => execFileAsync('/usr/bin/git', args, {
    cwd: root,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
    maxBuffer: 1024 * 1024,
  });
  await git(['init', '--quiet']);
  await writeFile(path.join(root, 'tracked.txt'), 'committed\n', { mode: 0o600 });
  await git(['add', '--', 'tracked.txt']);
  await git([
    '-c', 'user.name=ShieldKit Test',
    '-c', 'user.email=shieldkit-test@example.invalid',
    'commit', '--quiet', '-m', 'test fixture',
  ]);
  return { git, root };
}

async function createTinyPreparedCeremony(root) {
  await chmod(root, 0o700);
  const circuit = path.join(root, 'relation.circom');
  const initialPtau = path.join(root, 'pot8-initial.ptau');
  const contributedPtau = path.join(root, 'pot8-contributed.ptau');
  const r1cs = path.join(root, 'relation.r1cs');
  const ptau = path.join(root, 'powers-of-tau.ptau');
  const initialZkey = path.join(root, 'initial.zkey');
  await writeFile(circuit, [
    'pragma circom 2.0.0;',
    'template Square() {',
    '  signal input value;',
    '  signal output squared;',
    '  squared <== value * value;',
    '}',
    'component main = Square();',
    '',
  ].join('\n'), { mode: 0o600 });
  const run = (arguments_) => execFileAsync(process.execPath, arguments_, {
    cwd: root,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '', TZ: 'UTC' },
    maxBuffer: 8 * 1024 * 1024,
  });
  await run([circom2Cli, circuit, '--r1cs', '--output', root]);
  await run([snarkjsCli, 'powersoftau', 'new', 'bn128', '8', initialPtau]);
  await run([
    snarkjsCli, 'powersoftau', 'contribute', initialPtau, contributedPtau,
    '--name=ShieldKit TEST-ONLY phase-1 fixture',
    '--entropy=ShieldKit TEST-ONLY non-secret fixture entropy',
  ]);
  await run([snarkjsCli, 'powersoftau', 'prepare', 'phase2', contributedPtau, ptau]);
  await run([snarkjsCli, 'groth16', 'setup', r1cs, ptau, initialZkey]);
  for (const filename of [r1cs, ptau, initialZkey]) await chmod(filename, 0o600);

  const toolchain = await collectV2FinalZkeyToolchainManifest();
  const { privateKey } = generateKeyPairSync('ed25519');
  const keyBytes = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'pem' }));
  await writeFile(path.join(root, 'participant-signing-key.pem'), keyBytes, {
    mode: 0o600,
    flag: 'wx',
  });
  keyBytes.fill(0);
  const artifacts = {
    initialZkey: {
      bytes: String((await stat(initialZkey)).size),
      file: 'initial.zkey',
      sha256: await digest(initialZkey),
    },
    ptau: {
      bytes: String((await stat(ptau)).size),
      file: 'powers-of-tau.ptau',
      sha256: await digest(ptau),
    },
    r1cs: {
      bytes: String((await stat(r1cs)).size),
      file: 'relation.r1cs',
      sha256: await digest(r1cs),
    },
  };
  const implementation = await collectV2BetaSingleContributorImplementationManifest();
  const implementationSha256 = digestBytes(Buffer.from(canonicalJson(implementation), 'utf8'));
  const request = createBetaSingleContributorContributionRequest({
    ceremonyId: 'shieldkit-v2-beta-test',
    entropyPolicySha256: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
    implementationSha256,
    sequence: 1,
    r1csSha256: artifacts.r1cs.sha256,
    ptauSha256: artifacts.ptau.sha256,
    previousZkeySha256: artifacts.initialZkey.sha256,
  });
  const preparation = {
    schema: V2_BETA_SINGLE_CONTRIBUTOR_PREPARATION_SCHEMA,
    status: 'prepared-awaiting-local-secret-contribution',
    assurance: BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE,
    claims: FALSE_CLAIMS,
    ceremonyId: request.ceremonyId,
    participant: {
      id: 'beta-test-operator',
      publicKeySpkiBase64: createPublicKey(privateKey)
        .export({ type: 'spki', format: 'der' })
        .toString('base64'),
    },
    source: implementation.source,
    b01: {
      bundleStatus: 'verified-b01-pre-freeze-candidate-awaiting-independent-review',
      manifestSha256: `sha256:${'3'.repeat(64)}`,
    },
    entropyPolicySha256: BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256,
    implementation,
    implementationSha256,
    artifacts,
    request,
    toolchain,
    toolchainSha256: digestBytes(Buffer.from(canonicalJson(toolchain), 'utf8')),
  };
  await writeCanonical(path.join(root, 'preparation.json'), preparation);
  await rm(circuit, { force: true });
  await rm(initialPtau, { force: true });
  await rm(contributedPtau, { force: true });
  return preparation;
}

async function waitForStage(directory, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const stage = (await readdir(directory))
      .find((name) => name.startsWith('.contribution-stage-'));
    if (stage !== undefined) return stage;
    await delay(10);
  }
  throw new Error('timed out waiting for beta contribution stage');
}

async function collectChild(child, timeoutMs = 20_000) {
  const stdout = [];
  const stderr = [];
  child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
  child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
  let timer;
  try {
    const result = await Promise.race([
      new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('close', (code, signal) => resolve({ code, signal }));
      }),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(
          `timed out waiting for child; stdout=${Buffer.concat(stdout).toString('utf8')} stderr=${Buffer.concat(stderr).toString('utf8')}`,
        )), timeoutMs);
      }),
    ]);
    return {
      ...result,
      stderr: Buffer.concat(stderr).toString('utf8'),
      stdout: Buffer.concat(stdout).toString('utf8'),
    };
  } finally {
    clearTimeout(timer);
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  }
}

test('implementation provenance rejects unstaged, staged, and untracked checkout changes', async (t) => {
  await t.test('clean checkout passes', async (t) => {
    const { root } = await createCleanGitFixture(t);
    assert.doesNotThrow(() => assertV2BetaSingleContributorCleanCheckout(root));
  });
  await t.test('unstaged tracked change fails', async (t) => {
    const { root } = await createCleanGitFixture(t);
    await writeFile(path.join(root, 'tracked.txt'), 'unstaged\n', { mode: 0o600 });
    assert.throws(
      () => assertV2BetaSingleContributorCleanCheckout(root),
      { code: 'BETA_IMPLEMENTATION_DIRTY' },
    );
  });
  await t.test('staged tracked change fails', async (t) => {
    const { git, root } = await createCleanGitFixture(t);
    await writeFile(path.join(root, 'tracked.txt'), 'staged\n', { mode: 0o600 });
    await git(['add', '--', 'tracked.txt']);
    assert.throws(
      () => assertV2BetaSingleContributorCleanCheckout(root),
      { code: 'BETA_IMPLEMENTATION_DIRTY' },
    );
  });
  await t.test('untracked path fails', async (t) => {
    const { root } = await createCleanGitFixture(t);
    await writeFile(path.join(root, 'untracked.txt'), 'untracked\n', { mode: 0o600 });
    assert.throws(
      () => assertV2BetaSingleContributorCleanCheckout(root),
      { code: 'BETA_IMPLEMENTATION_DIRTY' },
    );
  });
});

test('B-01 source binding compares Git identity without conflating repository metadata', () => {
  const gitCommit = '1'.repeat(40);
  const gitTree = '2'.repeat(40);
  const implementationSource = { gitCommit, gitTree };
  const b01Source = { gitCommit, gitTree, repositoryRoot };
  assert.doesNotThrow(() => assertV2BetaSingleContributorSourceBinding({
    b01Source,
    implementationSource,
  }));
  for (const [label, changedB01, changedImplementation] of [
    ['commit', { ...b01Source, gitCommit: '3'.repeat(40) }, implementationSource],
    ['tree', { ...b01Source, gitTree: '4'.repeat(40) }, implementationSource],
    ['root', { ...b01Source, repositoryRoot: path.dirname(repositoryRoot) }, implementationSource],
    ['B-01 shape', { ...b01Source, extra: true }, implementationSource],
    ['implementation shape', b01Source, { ...implementationSource, extra: true }],
  ]) {
    assert.throws(
      () => assertV2BetaSingleContributorSourceBinding({
        b01Source: changedB01,
        implementationSource: changedImplementation,
      }),
      { code: 'BETA_IMPLEMENTATION_INVALID' },
      label,
    );
  }
});

test('CLI has a separate exact beta contract and has no entropy argument', () => {
  assert.deepEqual(parseV2BetaSingleContributorArguments([
    'prepare',
    '--b01-bundle', '/private/b01',
    '--ceremony-id', 'shieldkit-beta',
    '--participant-id', 'alice',
    '--output-dir', '/private/output',
  ]), {
    command: 'prepare',
    b01Bundle: '/private/b01',
    ceremonyId: 'shieldkit-beta',
    participantId: 'alice',
    outputDirectory: '/private/output',
  });
  assert.deepEqual(parseV2BetaSingleContributorArguments([
    'contribute', '--ceremony-dir', '/private/output',
  ]), { command: 'contribute', ceremonyDirectory: '/private/output' });
  assert.throws(
    () => parseV2BetaSingleContributorArguments([
      'contribute', '--ceremony-dir', '/private/output', '--entropy', 'secret',
    ]),
    /missing or unknown properties/u,
  );
  assert.throws(
    () => parseV2BetaSingleContributorArguments([
      'verify', '--ceremony-dir', 'relative',
    ]),
    /absolute canonical path/u,
  );
});

test('real tiny beta contribution is atomic, signed, cryptographically verified, and non-qualifying', { timeout: 180_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-ceremony-test-'));
  try {
    const preparation = await createTinyPreparedCeremony(root);
    const preparationPath = path.join(root, 'preparation.json');
    const ready = await preflightV2BetaSingleContributorCeremony({ ceremonyDirectory: root });
    assert.equal(ready.status, 'ready-for-local-secret-contribution');
    assert.equal(ready.entropyPolicySha256, preparation.entropyPolicySha256);
    assert.equal(ready.implementationSha256, preparation.implementationSha256);

    const legacy = { ...preparation, schema: 'shieldkit-v2-beta-single-contributor-preparation-v1' };
    await writeFile(preparationPath, canonicalJson(legacy), { mode: 0o600 });
    await assert.rejects(
      () => preflightV2BetaSingleContributorCeremony({ ceremonyDirectory: root }),
      /claim or identity boundary is invalid/u,
    );
    await writeFile(preparationPath, canonicalJson(preparation), { mode: 0o600 });

    const substituted = structuredClone(preparation);
    substituted.implementation.files[0].sha256 = `sha256:${'4'.repeat(64)}`;
    substituted.implementationSha256 = digestBytes(Buffer.from(
      canonicalJson(substituted.implementation),
      'utf8',
    ));
    substituted.request.implementationSha256 = substituted.implementationSha256;
    await writeFile(preparationPath, canonicalJson(substituted), { mode: 0o600 });
    await assert.rejects(
      () => preflightV2BetaSingleContributorCeremony({ ceremonyDirectory: root }),
      /implementation source or entropy policy changed/u,
    );
    await writeFile(preparationPath, canonicalJson(preparation), { mode: 0o600 });

    for (const length of [99, 129]) {
      const outOfRangeDice = Buffer.alloc(length, 0x31);
      await assert.rejects(
        () => contributeV2BetaSingleContributorCeremony({
          ceremonyDirectory: root,
          dice: outOfRangeDice,
          osRandomBytes: Buffer.alloc(64, 1),
        }),
        /dice must be 100 through 128 ASCII bytes from 1 through 6/u,
      );
      assert.equal(outOfRangeDice.every((byte) => byte === 0), true);
    }
    const invalidDice = Buffer.from('7'.repeat(100), 'ascii');
    await assert.rejects(
      () => contributeV2BetaSingleContributorCeremony({
        ceremonyDirectory: root,
        dice: invalidDice,
        osRandomBytes: Buffer.alloc(64, 1),
      }),
      /dice must be 100 through 128 ASCII bytes from 1 through 6/u,
    );
    assert.equal(invalidDice.every((byte) => byte === 0), true);
    assert.equal((await readdir(root)).includes('result'), false);
    const staleStage = await mkdtemp(path.join(root, '.contribution-stage-'));
    await chmod(staleStage, 0o700);
    const staleDice = Buffer.from('1'.repeat(100), 'ascii');
    await assert.rejects(
      () => contributeV2BetaSingleContributorCeremony({
        ceremonyDirectory: root,
        dice: staleDice,
        osRandomBytes: Buffer.alloc(64, 2),
      }),
      /interrupted beta stage exists/u,
    );
    assert.equal(staleDice.every((byte) => byte === 0), true);
    await rm(staleStage, { recursive: true, force: true });
    const signingKeyPath = path.join(root, 'participant-signing-key.pem');
    const signingKeyBytes = await readFile(signingKeyPath);
    await writeFile(signingKeyPath, 'not-a-private-key', { mode: 0o600 });
    const preflightDice = Buffer.from('2'.repeat(100), 'ascii');
    const preflightOs = Buffer.alloc(64, 3);
    await assert.rejects(
      () => contributeV2BetaSingleContributorCeremony({
        ceremonyDirectory: root,
        dice: preflightDice,
        osRandomBytes: preflightOs,
      }),
      /valid private key/u,
    );
    assert.equal(preflightDice.every((byte) => byte === 0), true);
    assert.equal(preflightOs.every((byte) => byte === 0), true);
    await writeFile(signingKeyPath, signingKeyBytes, { mode: 0o600 });
    signingKeyBytes.fill(0);
    const diceMarker = '123456'.repeat(21) + '12';
    const osMarker = Buffer.from('ab'.repeat(64), 'hex');
    const dice = Buffer.from(diceMarker, 'ascii');
    const contributed = await contributeV2BetaSingleContributorCeremony({
      ceremonyDirectory: root,
      dice,
      osRandomBytes: osMarker,
    });
    assert.equal(contributed.status, 'beta-single-contributor-cryptographically-verified-unqualified');
    assert.deepEqual(contributed.claims, FALSE_CLAIMS);
    assert.equal(dice.every((byte) => byte === 0), true);
    assert.equal(osMarker.every((byte) => byte === 0), true);
    const verified = await verifyV2BetaSingleContributorCeremony({ ceremonyDirectory: root });
    assert.equal(verified.schema, V2_BETA_SINGLE_CONTRIBUTOR_VERIFICATION_SCHEMA);
    assert.equal(verified.status, 'beta-single-contributor-reverified-unqualified');
    assert.deepEqual(verified.claims, FALSE_CLAIMS);

    const resultDirectory = path.join(root, 'result');
    const files = (await readdir(resultDirectory)).sort();
    assert.deepEqual(files, [
      'beta-proving-key.zkey',
      'receipt.json',
      'result.json',
      'transcript.json',
      'verification-key.json',
    ]);
    for (const filename of files) {
      assert.equal((await stat(path.join(resultDirectory, filename))).mode & 0o777, 0o600);
    }
    assert.equal((await stat(resultDirectory)).mode & 0o777, 0o700);
    await assert.rejects(
      () => stat(path.join(root, 'participant-signing-key.pem')),
      { code: 'ENOENT' },
    );
    const retained = Buffer.concat(await Promise.all([
      'preparation.json',
      ...files.filter((name) => name.endsWith('.json')),
    ].map(async (name) => readFile(
      name === 'preparation.json' ? path.join(root, name) : path.join(resultDirectory, name),
    )))).toString('utf8');
    assert.equal(retained.includes(diceMarker), false);
    assert.equal(retained.includes('ab'.repeat(64)), false);
    assert.equal(retained.includes('SKV2P2:'), false);
    const result = JSON.parse(await readFile(path.join(resultDirectory, 'result.json'), 'utf8'));
    assert.equal(result.schema, V2_BETA_SINGLE_CONTRIBUTOR_RESULT_SCHEMA);
    assert.equal(result.ceremonyId, preparation.ceremonyId);
    assert.equal(result.claims.d01Qualified, false);
    assert.equal(result.claims.finalKey, false);
    assert.equal(result.claims.production, false);
    assert.equal(result.claims.releaseQualified, false);

    const resultPath = path.join(resultDirectory, 'result.json');
    const originalResultBytes = await readFile(resultPath);
    const changedResult = JSON.parse(originalResultBytes.toString('utf8'));
    changedResult.claims.production = true;
    await writeFile(resultPath, canonicalJson(changedResult), { mode: 0o600 });
    await assert.rejects(
      () => verifyV2BetaSingleContributorCeremony({ ceremonyDirectory: root }),
      /claim or verification boundary is invalid/u,
    );
    await writeFile(resultPath, originalResultBytes, { mode: 0o600 });

    const linkDirectory = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-link-test-'));
    try {
      const receiptPath = path.join(resultDirectory, 'receipt.json');
      await link(receiptPath, path.join(linkDirectory, 'receipt-hardlink.json'));
      await assert.rejects(
        () => verifyV2BetaSingleContributorCeremony({ ceremonyDirectory: root }),
        /single-link file/u,
      );
    } finally {
      await rm(linkDirectory, { recursive: true, force: true });
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('contribution deadline preserves a private stale stage and refuses in-place retry', { timeout: 180_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-timeout-test-'));
  try {
    await createTinyPreparedCeremony(root);
    const dice = Buffer.from('3'.repeat(100), 'ascii');
    const osRandomBytes = Buffer.alloc(64, 4);
    await assert.rejects(
      () => contributeV2BetaSingleContributorCeremony({
        ceremonyDirectory: root,
        dice,
        osRandomBytes,
        snarkjsTimeoutMs: 1,
      }),
      (error) => error?.code === 'BETA_SNARKJS_ABORTED',
    );
    assert.equal(dice.every((byte) => byte === 0), true);
    assert.equal(osRandomBytes.every((byte) => byte === 0), true);
    const entries = await readdir(root);
    assert.equal(entries.includes('result'), false);
    assert.equal(entries.some((name) => name.startsWith('.contribution-stage-')), true);
    assert.equal(entries.includes('participant-signing-key.pem'), true);

    const retryDice = Buffer.from('4'.repeat(100), 'ascii');
    await assert.rejects(
      () => contributeV2BetaSingleContributorCeremony({
        ceremonyDirectory: root,
        dice: retryDice,
        osRandomBytes: Buffer.alloc(64, 5),
      }),
      (error) => error?.code === 'BETA_STALE_STAGE',
    );
    assert.equal(retryDice.every((byte) => byte === 0), true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('operator SIGTERM after private staging clears publication and preserves diagnostics', { timeout: 180_000 }, async () => {
  const parent = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-signal-test-'));
  const ceremony = await mkdtemp(path.join(parent, 'ceremony-'));
  const helper = path.join(parent, 'signal-helper.mjs');
  try {
    await createTinyPreparedCeremony(ceremony);
    const moduleUrl = pathToFileURL(fileURLToPath(new URL(
      './v2-beta-single-contributor-ceremony.mjs',
      import.meta.url,
    ))).href;
    await writeFile(helper, [
      `import { contributeV2BetaSingleContributorCeremony } from ${JSON.stringify(moduleUrl)};`,
      `const ceremonyDirectory = ${JSON.stringify(ceremony)};`,
      "const dice = Buffer.from('5'.repeat(100), 'ascii');",
      'const osRandomBytes = Buffer.alloc(64, 6);',
      'try {',
      '  await contributeV2BetaSingleContributorCeremony({ ceremonyDirectory, dice, osRandomBytes });',
      "  process.stdout.write('unexpected-success\\n');",
      '  process.exitCode = 2;',
      '} catch (error) {',
      "  process.stdout.write(`${error?.code ?? 'unknown'}\\n`);",
      '  process.exitCode = error?.code === \'BETA_SNARKJS_ABORTED\' || error?.code === \'BETA_OPERATOR_ABORTED\' ? 0 : 3;',
      '}',
      '',
    ].join('\n'), { mode: 0o600 });
    const childEnvironment = { ...process.env };
    for (const name of Object.keys(childEnvironment)) {
      if (name === 'NODE_OPTIONS'
        || name === 'NODE_PATH'
        || name === 'NODE_V8_COVERAGE'
        || name.startsWith('LD_')
        || name.startsWith('DYLD_')) delete childEnvironment[name];
    }
    const child = spawn(process.execPath, [helper], {
      cwd: parent,
      env: childEnvironment,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    await waitForStage(ceremony);
    assert.equal(child.kill('SIGTERM'), true);
    const result = await collectChild(child);
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /BETA_(?:SNARKJS|OPERATOR)_ABORTED/u);
    const entries = await readdir(ceremony);
    assert.equal(entries.includes('result'), false);
    assert.equal(entries.some((name) => name.startsWith('.contribution-stage-')), true);
    assert.equal(entries.includes('participant-signing-key.pem'), true);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test('PTY accepts more than 100 dice rolls, suppresses echo, and restores the exact terminal state', { timeout: 30_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-tty-test-'));
  const helper = path.join(root, 'tty-helper.mjs');
  const diceText = '123456'.repeat(19) + '123';
  try {
    const moduleUrl = pathToFileURL(fileURLToPath(new URL(
      './v2-beta-single-contributor-ceremony.mjs',
      import.meta.url,
    ))).href;
    await writeFile(helper, [
      "import { createHash } from 'node:crypto';",
      "import { spawnSync } from 'node:child_process';",
      `import { readV2BetaDiceFromControllingTerminal } from ${JSON.stringify(moduleUrl)};`,
      "const state = () => String(spawnSync('/usr/bin/stty', ['--file=/dev/tty', '-g'], { encoding: 'utf8' }).stdout).trim();",
      'const before = state();',
      'const dice = await readV2BetaDiceFromControllingTerminal();',
      'const after = state();',
      "const sha256 = createHash('sha256').update(dice).digest('hex');",
      "process.stdout.write(`SHIELDKIT_TTY_RESULT:${JSON.stringify({ before, after, length: dice.length, sha256 })}\\n`);",
      'dice.fill(0);',
      '',
    ].join('\n'), { mode: 0o600 });
    const command = `'${process.execPath.replaceAll("'", "'\\''")}' '${helper.replaceAll("'", "'\\''")}'`;
    const child = spawn('/usr/bin/script', [
      '--quiet', '--return', '--flush', '--command', command, '/dev/null',
    ], { stdio: ['pipe', 'pipe', 'pipe'] });
    const completed = collectChild(child);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out waiting for hidden dice prompt')), 10_000);
      child.stdout.on('data', (chunk) => {
        if (!String(chunk).includes('Nothing will echo:')) return;
        clearTimeout(timer);
        resolve();
      });
    });
    child.stdin.end(`${diceText}\n`);
    const result = await completed;
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(result.stdout.includes(diceText), false);
    const match = /SHIELDKIT_TTY_RESULT:(\{[^\r\n]+\})/u.exec(result.stdout);
    assert.notEqual(match, null, result.stdout);
    const report = JSON.parse(match[1]);
    assert.equal(report.length, 117);
    assert.equal(report.before, report.after);
    assert.equal(report.sha256, createHash('sha256').update(diceText, 'ascii').digest('hex'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('PTY rejects more than 128 dice rolls without echo and restores the exact terminal state', { timeout: 30_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-tty-overflow-test-'));
  const helper = path.join(root, 'tty-overflow-helper.mjs');
  const diceText = '1'.repeat(129);
  try {
    const moduleUrl = pathToFileURL(fileURLToPath(new URL(
      './v2-beta-single-contributor-ceremony.mjs',
      import.meta.url,
    ))).href;
    await writeFile(helper, [
      "import { spawnSync } from 'node:child_process';",
      `import { readV2BetaDiceFromControllingTerminal } from ${JSON.stringify(moduleUrl)};`,
      "const state = () => String(spawnSync('/usr/bin/stty', ['--file=/dev/tty', '-g'], { encoding: 'utf8' }).stdout).trim();",
      'const before = state();',
      'let code;',
      'try {',
      '  await readV2BetaDiceFromControllingTerminal();',
      "  code = 'unexpected-success';",
      '} catch (error) {',
      "  code = error?.code ?? 'unknown';",
      '}',
      'const after = state();',
      "process.stdout.write(`SHIELDKIT_TTY_OVERFLOW:${JSON.stringify({ before, after, code })}\\n`);",
      '',
    ].join('\n'), { mode: 0o600 });
    const command = `'${process.execPath.replaceAll("'", "'\\''")}' '${helper.replaceAll("'", "'\\''")}'`;
    const child = spawn('/usr/bin/script', [
      '--quiet', '--return', '--flush', '--command', command, '/dev/null',
    ], { stdio: ['pipe', 'pipe', 'pipe'] });
    const completed = collectChild(child);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out waiting for hidden dice prompt')), 10_000);
      child.stdout.on('data', (chunk) => {
        if (!String(chunk).includes('Nothing will echo:')) return;
        clearTimeout(timer);
        resolve();
      });
    });
    child.stdin.end(`${diceText}\n`);
    const result = await completed;
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    assert.equal(result.stdout.includes(diceText), false);
    const match = /SHIELDKIT_TTY_OVERFLOW:(\{[^\r\n]+\})/u.exec(result.stdout);
    assert.notEqual(match, null, result.stdout);
    const report = JSON.parse(match[1]);
    assert.equal(report.code, 'BETA_DICE_INVALID');
    assert.equal(report.before, report.after);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('PTY interruption restores the exact terminal state before terminating the reader', { timeout: 30_000 }, async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-v2-beta-tty-signal-test-'));
  const reader = path.join(root, 'tty-reader.mjs');
  const supervisor = path.join(root, 'tty-supervisor.mjs');
  try {
    const moduleUrl = pathToFileURL(fileURLToPath(new URL(
      './v2-beta-single-contributor-ceremony.mjs',
      import.meta.url,
    ))).href;
    await writeFile(reader, [
      `import { readV2BetaDiceFromControllingTerminal } from ${JSON.stringify(moduleUrl)};`,
      "process.on('SIGTERM', () => process.stdout.write('SHIELDKIT_HOST_SIGNAL_LISTENER_RAN\\n'));",
      'try {',
      '  await readV2BetaDiceFromControllingTerminal();',
      '  process.exitCode = 9;',
      '} catch (error) {',
      "  process.stdout.write(`SHIELDKIT_TTY_READER_ERROR:${error?.code ?? 'unknown'}\\n`);",
      "  process.exitCode = error?.code === 'BETA_TTY_INTERRUPTED' ? 0 : 10;",
      '}',
      '',
    ].join('\n'), { mode: 0o600 });
    await writeFile(supervisor, [
      "import { spawn, spawnSync } from 'node:child_process';",
      `const reader = ${JSON.stringify(reader)};`,
      "const state = () => String(spawnSync('/usr/bin/stty', ['--file=/dev/tty', '-g'], { encoding: 'utf8' }).stdout).trim();",
      'const before = state();',
      "const child = spawn(process.execPath, [reader], { stdio: 'inherit' });",
      "process.stdout.write(`SHIELDKIT_TTY_READER_PID:${child.pid}\\n`);",
      "child.once('error', (error) => { throw error; });",
      "child.once('close', (code, signal) => {",
      '  const after = state();',
      "  process.stdout.write(`SHIELDKIT_TTY_SIGNAL_RESULT:${JSON.stringify({ before, after, code, signal })}\\n`);",
      '  process.exit(code === 0 && signal === null && before === after ? 0 : 8);',
      '});',
      '',
    ].join('\n'), { mode: 0o600 });
    const command = `'${process.execPath.replaceAll("'", "'\\''")}' '${supervisor.replaceAll("'", "'\\''")}'`;
    const child = spawn('/usr/bin/script', [
      '--quiet', '--return', '--flush', '--command', command, '/dev/null',
    ], { stdio: ['pipe', 'pipe', 'pipe'] });
    const completed = collectChild(child);
    const readerPid = await new Promise((resolve, reject) => {
      let observed = '';
      const timer = setTimeout(() => reject(new Error('timed out waiting for no-echo reader')), 10_000);
      child.stdout.on('data', (chunk) => {
        observed += String(chunk);
        const pid = /SHIELDKIT_TTY_READER_PID:([0-9]+)/u.exec(observed)?.[1];
        if (pid === undefined || !observed.includes('Nothing will echo:')) return;
        clearTimeout(timer);
        resolve(Number(pid));
      });
    });
    process.kill(readerPid, 'SIGTERM');
    const result = await completed;
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /SHIELDKIT_HOST_SIGNAL_LISTENER_RAN/u);
    assert.match(result.stdout, /SHIELDKIT_TTY_READER_ERROR:BETA_TTY_INTERRUPTED/u);
    const match = /SHIELDKIT_TTY_SIGNAL_RESULT:(\{[^\r\n]+\})/u.exec(result.stdout);
    assert.notEqual(match, null, result.stdout);
    const report = JSON.parse(match[1]);
    assert.equal(report.signal, null);
    assert.equal(report.code, 0);
    assert.equal(report.before, report.after);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
