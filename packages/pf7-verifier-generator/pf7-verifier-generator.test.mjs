import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';
import { loadCliConfig } from './cli.mjs';
import { encodeActionPacket, OUTPUT_RECORD_BYTES } from '../action-packet/action-packet.mjs';
import {
  assertBuildComplete,
  assertCleanGitRepository,
  assertSeamMeasured,
  assertSeamRedteam,
  deriveFreshDevelopmentActions,
  extractVerifierSet,
  generatePf7FreshDevelopmentCorpus,
  Pf7VerifierGeneratorError,
  validatePf7FreshDevelopmentInput,
  validateAdapter,
  validateProvenance,
  validateRuntimePackageVersions,
  validateSeamProvenance,
} from './pf7-verifier-generator.mjs';

const execFileAsync = promisify(execFile);
const hash256 = (bytes) => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
const lockFor = (redeem) => Buffer.concat([Buffer.from([0xaa, 0x20]), hash256(redeem), Buffer.from([0x87])]).toString('hex');
const push = (bytes) => Buffer.concat([Buffer.from([bytes.length]), bytes]).toString('hex');
const names = ['exec0', 'exec1', 'exec2', 'exec3', 'exec4', 'genesis', 'terminal'];

test('retained PF7 format-patch chain is hash-pinned and complete', async () => {
  const reference = await validateProvenance();
  assert.equal(reference.patches.length, 7);
  assert.equal(reference.terminal.commit, '17c6b9552c48b0fc5271be626a1578fb0065df09');
  const seam = await validateSeamProvenance();
  assert.equal(seam.patches.length, 8);
  assert.equal(seam.referenceTerminal.commit, reference.terminal.commit);
  assert.equal(seam.terminal.commit, '1d543756602edfd92081a0b58dba62d33d0aea34');
  assert.equal(seam.terminal.tree, '1c1efb23e95bf51a715f8ab29f3cf698a359303d');
  assert.equal(seam.patches[7].sha256, 'c40db1abc1cb54fca82c5754f985d6ede22d236f8bf1404771ae105ab438bd83');
});

test('seven exact P2SH32 source/redeem pairs are canonicalized in role order', () => {
  const inputs = names.map((name, index) => { const redeem = Buffer.from([0x51, index]); return { name, lock: lockFor(redeem), unlock: push(redeem) }; });
  const set = extractVerifierSet(inputs);
  assert.equal(set.length, 7);
  assert.equal(set[6].name, 'terminal');
  assert.equal(set[0].redeemBytecodeHex, '5100');
});

test('source/redeem tampering and generic topology are rejected before output', () => {
  const inputs = names.map((name) => { const redeem = Buffer.from([0x51]); return { name, lock: lockFor(redeem), unlock: push(redeem) }; });
  inputs[3].lock = `${inputs[3].lock.slice(0, -2)}86`;
  assert.throws(() => extractVerifierSet(inputs), Pf7VerifierGeneratorError);
  assert.throws(() => extractVerifierSet(inputs.slice(0, 6)), Pf7VerifierGeneratorError);
});

test('adapter parser rejects non-complete or wrong-schema input', () => {
  assert.throws(() => validateAdapter(Buffer.from('{"schema":"wrong"}')), Pf7VerifierGeneratorError);
});

test('all provenance repositories must have neither tracked nor untracked changes', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-clean-git-'));
  try {
    await execFileAsync('git', ['init', '-q', directory]);
    await execFileAsync('git', ['-C', directory, 'config', 'user.email', 'pf7@example.invalid']);
    await execFileAsync('git', ['-C', directory, 'config', 'user.name', 'PF7 test']);
    await writeFile(path.join(directory, 'tracked.txt'), 'clean\n');
    await execFileAsync('git', ['-C', directory, 'add', 'tracked.txt']);
    await execFileAsync('git', ['-C', directory, 'commit', '-qm', 'initial']);
    assert.equal(await assertCleanGitRepository(directory, 'fixture'), directory);
    await writeFile(path.join(directory, 'tracked.txt'), 'changed\n');
    await assert.rejects(assertCleanGitRepository(directory, 'fixture'), Pf7VerifierGeneratorError);
    await execFileAsync('git', ['-C', directory, 'checkout', '--', 'tracked.txt']);
    await writeFile(path.join(directory, 'untracked.txt'), 'present\n');
    await assert.rejects(assertCleanGitRepository(directory, 'fixture'), Pf7VerifierGeneratorError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('CLI accepts only direct strict-JSON configuration files', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-cli-config-'));
  try {
    const valid = path.join(directory, 'valid.json');
    await writeFile(valid, '{}');
    assert.equal(JSON.stringify(await loadCliConfig(valid)), '{}');
    for (const [name, contents] of [['duplicate.json', '{"a":1,"a":2}'], ['trailing.json', '{}{}'], ['bom.json', Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d])]]) {
      const file = path.join(directory, name);
      await writeFile(file, contents);
      await assert.rejects(loadCliConfig(file));
    }
    const linked = path.join(directory, 'linked.json');
    await symlink(valid, linked);
    await assert.rejects(loadCliConfig(linked), /regular non-symlink/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('runtime package closure rejects a symlink boundary and version drift', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-runtime-'));
  try {
    const expected = { '@fixture/runtime': '1.2.3' };
    const direct = path.join(directory, 'node_modules');
    const packageDirectory = path.join(direct, '@fixture', 'runtime');
    await mkdir(packageDirectory, { recursive: true });
    await writeFile(path.join(packageDirectory, 'package.json'), '{"version":"1.2.3"}');
    assert.deepEqual(await validateRuntimePackageVersions(direct, expected, 'fixture'), expected);
    await writeFile(path.join(packageDirectory, 'package.json'), '{"version":"1.2.4"}');
    await assert.rejects(validateRuntimePackageVersions(direct, expected, 'fixture'), Pf7VerifierGeneratorError);
    const linked = path.join(directory, 'linked-node_modules');
    await symlink(direct, linked);
    await assert.rejects(validateRuntimePackageVersions(linked, expected, 'fixture'), Pf7VerifierGeneratorError);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('an incomplete PF7 boundary build fails before downstream artifact tools', () => {
  assert.throws(() => assertBuildComplete({ built: false, errors: { terminal: 'optimizer dependency missing' } }), /incomplete boundary.*optimizer dependency missing/);
  assert.doesNotThrow(() => assertBuildComplete({ built: true }));
});

test('seam measurements require seven accepted verifier roles in one ten-input context', () => {
  const contextNames = [...names, 'packet', 'state', 'fee'];
  const result = {
    built: true,
    gateOk: true,
    verifierInputCount: 7,
    structuralRoleCount: 3,
    structuralRolesUnevaluated: true,
    wire: 55311,
    manual: contextNames.map((name, i) => ({ i, name, accepts: i < 7, unlockLen: i === 6 ? 9277 : 755 })),
    packet: { index: 7, bytes: 752, unlockBytes: 755, sha256: '0'.repeat(64) },
    projectionSignalCarrier: { genesisIndex: 5, pushHeader: '4de001', projectionOffset: 3, projectionBytes: 448, digestOffset: 451, digestBytes: 32 },
  };
  const standardness = {
    standardVm: 'createVirtualMachineBch2026(true)',
    contextInputCount: 10,
    evaluatedInputCount: 7,
    scope: 'verifier roles only; structural packet/state/fee roles explicitly unevaluated',
    allAccept: true,
    rows: names.map((name, index) => ({ index, name, accepts: true, unlockingBytes: 9277 })),
  };
  const attacks = { honest: { allAccept: true }, total: 18, rejected: 18, falseAccepts: 0, setupErrors: 0, results: Array.from({ length: 18 }, (_, index) => ({ index })) };
  assert.equal(assertSeamMeasured({ result, standardness, attacks }), true);
  const tooLarge = structuredClone(result); tooLarge.wire = 59001;
  assert.throws(() => assertSeamMeasured({ result: tooLarge, standardness, attacks }), /normal-VM/);
  const evaluatedStructural = structuredClone(result); evaluatedStructural.structuralRolesUnevaluated = false;
  assert.throws(() => assertSeamMeasured({ result: evaluatedStructural, standardness, attacks }), /normal-VM/);
});

test('seam redteam requires thirteen local and four cross-action rejections', () => {
  const row = (accepts = true) => names.map((name, index) => ({ index, name, accepts: index === 6 ? accepts : true }));
  const attacks = Object.fromEntries([
    'altered-in0', 'altered-in1', 'carrier-digest-byte', 'carrier-header',
    'carrier-high-bit', 'carrier-little-endian-halves', 'carrier-swapped-halves',
    'input5-input7-swap', 'packet-byte', 'packet-header',
    'packet-nonminimal-push', 'packet-short', 'packet-trailing',
  ].map((name) => [name, row(false)]));
  const report = {
    schema: 'verifier.cash/bn254-onetx-shield-action-seam-redteam/v1',
    scope: 'seven verifier roles evaluated in complete ten-input context; packet/state/fee structural roles unevaluated',
    verdict: 'pass',
    attackCount: 17,
    honest: row(true),
    attacks,
    crossAction: Array.from({ length: 2 }, () => ({ packetSubstitution: row(false), genesisSubstitution: row(false) })),
  };
  assert.equal(assertSeamRedteam(report), true);
  report.attackCount = 16;
  assert.throws(() => assertSeamRedteam(report), /cross-action redteam/);
});

const freshHash = 'a'.repeat(64);
const freshRecord = (name) => ({ path: `/fresh/${name}`, sha256: freshHash });
const freshInput = (mode = 'discovery') => {
  const value = {
    mode,
    destination: '/fresh/out',
    scratchDirectory: '/fresh/scratch',
    preProfile: {
      schema: 'shield.cash/pf7-fresh-development-preprofile/v1',
      setupMetadata: freshRecord('setup-metadata.json'), r1cs: freshRecord('action.r1cs'), verificationKey: freshRecord('verification_key.json'),
    },
    actions: ['deposit', 'transfer', 'withdrawal'].map((kind) => ({ kind, packet: freshRecord(`${kind}.packet`), proof: freshRecord(`${kind}.proof.json`), publicSignals: freshRecord(`${kind}.public.json`), verificationKey: freshRecord('verification_key.json') })),
    verifier: { checkout: '/fresh/verifier', cashcRoot: '/fresh/cashc', cashcCommit: '1'.repeat(40), leanBchRoot: '/fresh/lean', leanBchCommit: '2'.repeat(40) },
  };
  if (mode === 'final-replay') {
    value.expected = { sourceSetSha256: 'b'.repeat(64), outputSha256: 'c'.repeat(64) };
    value.finalProfile = { profileId: `sha256:${'d'.repeat(64)}`, instanceId: `sha256:${'e'.repeat(64)}`, bundleDirectory: '/fresh/profile-bundle' };
  }
  return value;
};

test('fresh development PF7 input is strict, two-stage, and cannot accept copied adapter metadata', () => {
  assert.equal(validatePf7FreshDevelopmentInput(freshInput()).mode, 'discovery');
  assert.equal(validatePf7FreshDevelopmentInput(freshInput('final-replay')).mode, 'final-replay');
  const cases = [
    ['unknown top-level key', (value) => { value.adapter = freshRecord('forged-adapter.json'); }],
    ['forged action adapter metadata', (value) => { value.actions[0].adapter = freshRecord('forged-adapter.json'); }],
    ['wrong action order', (value) => { value.actions[1].kind = 'withdrawal'; }],
    ['packet traversal', (value) => { value.actions[0].packet.path = '/fresh/../escape.packet'; }],
    ['missing final replay identity', (value) => { delete value.finalProfile; }],
    ['invalid final replay profile', (value) => { value.finalProfile.profileId = 'not-an-id'; }],
  ];
  for (const [name, mutate] of cases) {
    const value = freshInput(name.includes('final replay') ? 'final-replay' : 'discovery'); mutate(value);
    assert.throws(() => validatePf7FreshDevelopmentInput(value), Pf7VerifierGeneratorError, name);
  }
});

test('fresh development entrypoint rejects a symlinked pre-profile source before any verifier build', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-fresh-symlink-'));
  try {
    const actual = path.join(directory, 'actual.json'); const linked = path.join(directory, 'setup.json');
    await writeFile(actual, '{}'); await symlink(actual, linked);
    const value = freshInput(); value.preProfile.setupMetadata = { path: linked, sha256: createHash('sha256').update('{}').digest('hex') };
    value.preProfile.r1cs = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
    value.preProfile.verificationKey = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
    for (const action of value.actions) {
      action.packet = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
      action.proof = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
      action.publicSignals = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
      action.verificationKey = { path: actual, sha256: createHash('sha256').update('{}').digest('hex') };
    }
    value.destination = path.join(directory, 'out'); value.scratchDirectory = directory;
    await assert.rejects(() => generatePf7FreshDevelopmentCorpus(value), /fresh setup metadata.path has the wrong filesystem type/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const actionHex = (byte) => byte.repeat(32);
const actionState = (sequence, reserve, commitment) => ({
  profileId: actionHex('11'), instanceId: actionHex('22'), noteRoot: actionHex('33'), nullifierRoot: actionHex('44'),
  nextLeafIndex: '1', actionSequence: sequence, liveNoteCount: reserve === '0' ? '0' : '1', reserveSats: reserve, maximumReserve: '30000000', stateCommitment: actionHex(commitment),
});
const canonicalDepositPacket = () => encodeActionPacket({
  kind: 'deposit', networkId: 2, preState: actionState('0', '0', '55'), postState: actionState('1', '10000000', '66'),
  inputCommitment: actionHex('00'), inputNullifier: actionHex('00'), outputCommitment: actionHex('77'), outputRecord: Buffer.alloc(OUTPUT_RECORD_BYTES, 0x88),
  boundaryAmount: '10000000', withdrawalScriptHash: actionHex('00'), transactionContextDigest: actionHex('99'),
});

test('fresh path reads raw proof/signal/VK itself and rejects symlink swaps before a build', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'pf7-fresh-raw-'));
  try {
    const fixtureDirectory = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../snarkjs-adapter/test-fixtures/two-public');
    const proof = path.join(directory, 'proof.json'); const signals = path.join(directory, 'public.json'); const vk = path.join(directory, 'verification_key.json'); const packet = path.join(directory, 'packet.bin');
    await writeFile(proof, await readFile(path.join(fixtureDirectory, 'proof.json'))); await writeFile(signals, await readFile(path.join(fixtureDirectory, 'public.json'))); await writeFile(vk, await readFile(path.join(fixtureDirectory, 'verification_key.json'))); await writeFile(packet, canonicalDepositPacket());
    const record = async (filename) => ({ path: filename, sha256: createHash('sha256').update(await readFile(filename)).digest('hex') });
    const raw = { kind: 'deposit', proof: await record(proof), publicSignals: await record(signals), verificationKey: await record(vk), packet: await record(packet) };
    const setup = { verificationKey: { sha256: raw.verificationKey.sha256 } };
    // The trusted adapter does parse the supplied raw tuple; this test reaches
    // the packet/public-input binding rather than accepting copied metadata.
    await assert.rejects(() => deriveFreshDevelopmentActions({ actions: [raw] }, setup), /packet digest limbs do not match re-derived public inputs/);
    for (const key of ['proof', 'publicSignals', 'packet']) {
      const linked = path.join(directory, `${key}-link`); await symlink(raw[key].path, linked);
      const swapped = structuredClone(raw); swapped[key] = { path: linked, sha256: raw[key].sha256 };
      await assert.rejects(() => deriveFreshDevelopmentActions({ actions: [swapped] }, setup), /wrong filesystem type/, `${key} symlink swap`);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('fresh path rejects verification-key and final-profile swaps at schema boundary', () => {
  const vkSwap = freshInput(); vkSwap.actions[2].verificationKey.sha256 = 'f'.repeat(64);
  assert.throws(() => validatePf7FreshDevelopmentInput(vkSwap), /pre-profile verification key/);
  const profileSwap = freshInput('final-replay'); profileSwap.finalProfile.instanceId = `sha256:${'0'.repeat(64)}`;
  assert.doesNotThrow(() => validatePf7FreshDevelopmentInput(profileSwap));
  // A different profile identity is syntactically allowed only as a separately
  // caller-pinned final replay; it can never be inferred from discovery.
  assert.throws(() => validatePf7FreshDevelopmentInput({ ...freshInput(), finalProfile: profileSwap.finalProfile }), /missing or unknown properties/);
});
