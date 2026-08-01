import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  PF10_BETA_LIBAUTH_EVIDENCE_SCHEMA,
  parseBetaOptions,
  validatePf10BetaActionProofBinding,
  validatePf10BetaLibauthEvidence,
} from './v2-pf10-libauth-qualification.mjs';
import {
  actionPacketPublicLimbs,
  encodeActionPacket,
} from '../packages/action/v2/packet.mjs';
import {
  canonicalizeJcs,
} from '../packages/profile/v2/profile-core.mjs';
import {
  BetaLibauthQualificationError,
  main,
} from './v2-pf10-beta-libauth-qualification.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hex = (byte) => byte.repeat(32);
const fr = (value) => value.toString(16).padStart(64, '0');
const state = (noteCount, sequence, root, reserveSats) => ({
  profileId: hex('11'), noteRoot: fr(root), nullifierRoot: fr(2n),
  noteCount, nullifierCount: '0', maximumLiveNotes: '32', reserveSats,
  actionSequence: sequence,
});
const betaAction = () => {
  const packet = encodeActionPacket({
    kind: 'deposit', networkId: 2, instanceId: hex('22'),
    preState: state('0', '0', 1n, '0'),
    postState: state('1', '1', 3n, '10000000'),
    publicNullifier: hex('00'), outputNoteLeaf: fr(5n),
    encryptedRecord: Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: hex('00'),
    transactionContextHash: hex('55'),
  }, { denominationSats: '10000000' });
  const packetSha256 = sha256(packet);
  const publicInputs = actionPacketPublicLimbs(packet, {
    denominationSats: '10000000',
  });
  const proof = {
    curve: 'bn128', protocol: 'groth16',
    pi_a: ['1', '2', '1'], pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
    pi_c: ['7', '8', '1'],
  };
  return {
    construction: {}, feeRateSatsPerByte: '1', feeSats: '1', inputCount: 13,
    inputSources: [], kind: 'deposit', localVmEvidence: {}, mutationChecks: [],
    outputCount: 13, proofGenerationMs: 1, proofVerified: true,
    rawTransactionHex: '00', rawTransactionSha256: hex('aa'), rows: [],
    sourceOutputs: [], sourceParents: {}, transactionBytes: 1,
    transactionHeadroomBytes: 99_999, transactionId: hex('bb'),
    transactionLimitBytes: 100_000,
    contextHash: hex('55'), packetHex: packet.toString('hex'), packetSha256,
    proof, publicInputs,
    proofBindingSha256: sha256(Buffer.from(canonicalizeJcs({
      packetSha256, proof, publicInputs,
    }), 'utf8')),
  };
};

test('beta PF10 Libauth CLI has a distinct beta-zkey-only interface', () => {
  const root = '/tmp/shieldkit-beta-pf10-cli';
  const parsed = parseBetaOptions([
    '--output', `${root}/output`,
    '--profile-core', `${root}/profile.json`,
    '--qualification-root', `${root}/proofs`,
    '--r1cs', `${root}/circuit.r1cs`,
    '--verification-key', `${root}/vk.json`,
    '--wasm', `${root}/circuit.wasm`,
    '--beta-zkey', `${root}/beta.zkey`,
  ]);
  assert.equal(parsed.zkey, `${root}/beta.zkey`);
  assert.equal(Object.hasOwn(parsed, 'setupMetadata'), false);
  assert.throws(
    () => parseBetaOptions([
      '--output', `${root}/output`,
      '--profile-core', `${root}/profile.json`,
      '--qualification-root', `${root}/proofs`,
      '--r1cs', `${root}/circuit.r1cs`,
      '--verification-key', `${root}/vk.json`,
      '--wasm', `${root}/circuit.wasm`,
      '--beta-zkey', `${root}/beta.zkey`,
      '--setup-metadata', `${root}/forbidden.json`,
    ]),
    /unknown option/u,
  );
});

test('beta PF10 evidence validator cannot accept development outer labels', () => {
  assert.throws(
    () => validatePf10BetaLibauthEvidence({
      schema: 'shieldkit-v2-direct-pf10-local-libauth-evidence-v2',
      eligibility: 'development-only',
    }),
    /beta evidence\.schema/u,
  );
  assert.notEqual(
    PF10_BETA_LIBAUTH_EVIDENCE_SCHEMA,
    'shieldkit-v2-direct-pf10-local-libauth-evidence-v2',
  );
});

test('beta action packet/proof binding is exact and rejects every lineage mutation', () => {
  const action = betaAction();
  const checked = validatePf10BetaActionProofBinding({
    action, expectedKind: 'deposit', instanceId: hex('22'), profileId: hex('11'),
  });
  assert.equal(checked.packet.length, 552);
  assert.equal(checked.packetSha256, action.packetSha256);
  const mutations = [
    (value) => { value.packetHex = `${value.packetHex.slice(0, -2)}00`; },
    (value) => { value.packetSha256 = hex('ff'); },
    (value) => { value.publicInputs[0] = '0'; },
    (value) => { value.proof.pi_a[0] = '9'; },
    (value) => { value.proofBindingSha256 = hex('ee'); },
    (value) => { value.contextHash = hex('dd'); },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(action);
    mutate(changed);
    assert.throws(() => validatePf10BetaActionProofBinding({
      action: changed, expectedKind: 'deposit', instanceId: hex('22'),
      profileId: hex('11'),
    }));
  }
});

test('beta PF10 verifier refuses an incomplete output directory before evaluation', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'shieldkit-beta-pf10-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await assert.rejects(
    main([
      '--verify', root,
      '--beta-proof-evidence', path.join(root, 'proof.json'),
    ]),
    BetaLibauthQualificationError,
  );
});

test('beta PF10 verifier accepts only an explicit independently-verifiable proof-evidence option', async () => {
  await assert.rejects(
    main(['--verify', '/tmp/beta-output']),
    /usage: --verify/u,
  );
  await assert.rejects(
    main(['--verify', '/tmp/beta-output', '--wrong-proof-option', '/tmp/evidence.json']),
    /usage: --verify/u,
  );
});
