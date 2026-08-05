/* TEST-ONLY: ephemeral keys exercise the nonqualifying structural seam only. */
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';
import {
  createV2Q08HostSignatureEnvelope,
  inspectV2Q08HostSignatureEnvelope,
  V2_Q08_HOST_STATEMENT_SCHEMA,
} from '../packages/profile/v2/q08-host-evidence.mjs';
import { parseV2RawTransaction } from '../packages/kit/v2/transaction-policy.mjs';
import {
  parseV2Q08PairArguments,
  runV2Q08PairQualification,
  V2Q08PairQualificationError,
} from './v2-q08-pair-qualification.mjs';

const h = (byte) => byte.repeat(64);
const c = (value) => Buffer.from(canonicalizeJcs(value));
const digest = (value) => createHash('sha256').update(c(value)).digest('hex');
const rawFor = (seed) => {
  const outpoint = createHash('sha256').update(seed).digest('hex');
  return `0200000001${outpoint}0000000000ffffffff01e8030000000000000000000000`;
};
const laneEvidenceFor = (step) => ({
  bchn: {
    mempool: { path: `evidence/${step}/bchn-mempool.json`, sha256: h('1') },
    mined: { path: `evidence/${step}/bchn-mined.json`, sha256: h('2') },
  },
  leanbch: { path: `evidence/${step}/leanbch.json`, sha256: h('3') },
  libauth: { path: `evidence/${step}/libauth.json`, sha256: h('4') },
  maintainer: { path: `evidence/${step}/maintainer.json`, sha256: h('5') },
});

function statement(identity, hostIdentity, fundingCheckpointSha256) {
  const value = {
    schema: V2_Q08_HOST_STATEMENT_SCHEMA,
    status: 'host-journey-complete-awaiting-independent-pair-verification',
    profileId: identity.profileId, profileSha256: identity.profileSha256,
    instanceId: identity.instanceId, carrierCount: identity.carrierCount,
    descriptorSha256: identity.descriptorSha256,
    manifestSha256: identity.manifestSha256, runtimeMaterialSha256: identity.runtimeMaterialSha256,
    releaseRootId: identity.releaseRootId, releaseBootstrapSha256: identity.releaseBootstrapSha256,
    d02AuditPolicySha256: identity.d02AuditPolicySha256,
    d02ClosureSha256: identity.d02ClosureSha256,
    git: { commit: 'a'.repeat(40), tree: 'b'.repeat(40) }, hostIdentity,
    commandPlanSha256: h('7'), sourcePinSha256: h('8'), fundingCheckpointSha256, steps: [],
  };
  let previousSha256 = null; let recoveredNoteId;
  for (const [sequence, step] of ['npmCi', 'wallet', 'fundingAddress', 'sync', 'deposit', 'transfer', 'withdraw', 'deleteLocalState', 'recover', 'recoveredSpend'].entries()) {
    let result;
    if (step === 'npmCi') result = { status: 'installed-immutable' };
    else if (step === 'wallet') result = { status: 'wallet-ready' };
    else if (step === 'fundingAddress') result = { status: 'funding-address-displayed', fundingAddress: `bitcoincash:qtestfunding${hostIdentity.slice(0, 8)}` };
    else if (step === 'sync') result = { status: 'synced-from-genesis' };
    else if (step === 'deleteLocalState') result = { status: 'local-state-deleted' };
    else if (step === 'recover') { recoveredNoteId = h('d'); result = { status: 'recovered-from-chain-history', recoveredNoteId }; }
    else {
      const rawTransactionHex = rawFor(`${hostIdentity}:${step}`);
      result = {
        status: 'confirmed', action: step === 'withdraw' || step === 'recoveredSpend' ? 'withdrawal' : step,
        rawTransactionHex, transactionId: parseV2RawTransaction(rawTransactionHex).txid,
        laneEvidence: laneEvidenceFor(step),
        ...(step === 'recoveredSpend' ? { spentNoteId: recoveredNoteId } : {}),
      };
    }
    const command = { executable: step === 'npmCi' ? 'npm' : 'q08-command', arguments: step === 'npmCi' ? ['ci', '--ignore-scripts', '--no-audit', '--no-fund'] : [step] };
    const payload = { sequence, step, previousSha256, command, result, stdoutSha256: h('9'), stderrSha256: h('a') };
    previousSha256 = digest(payload); value.steps.push({ ...payload, entrySha256: previousSha256 });
  }
  return value;
}

// The nonqualifying seam is deliberately tested before valid transaction
// material is needed: its result must remain false and it must not write.
test('TEST-ONLY structural seam never writes a qualifying pair record', async (t) => {
  const root = mkdtempSync('/dev/shm/shieldkit-q08-pair-test-');
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const identity = { profileId: h('1'), profileSha256: h('2'), instanceId: h('3'), carrierCount: 7, d02AuditPolicySha256: h('0'), descriptorSha256: h('4'), manifestSha256: h('5'), runtimeMaterialSha256: h('6'), releaseBootstrapSha256: h('7'), releaseRootId: 'test-root', topologyId: 'pf10-test', verifierRoles: [] };
  const d02Closure = { testOnly: true };
  const d02ClosureSha256 = digest(d02Closure);
  const statementIdentity = { ...identity, d02ClosureSha256 };
  const pairA = generateKeyPairSync('ed25519'); const pairB = generateKeyPairSync('ed25519');
  const authority = (role, pair) => ({ role, signerId: `test-${role}`, organizationId: `test-org-${role}`, independenceDomain: `test-domain-${role}`, publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString() });
  const a = authority('clean-host-a', pairA); const b = authority('clean-host-b', pairB);
  const envelopeA = createV2Q08HostSignatureEnvelope({ authority: a, privateKey: pairA.privateKey, statement: statement(statementIdentity, h('c'), h('f')) });
  const envelopeB = createV2Q08HostSignatureEnvelope({ authority: b, privateKey: pairB.privateKey, statement: statement(statementIdentity, h('d'), h('e')) });
  const pathA = join(root, 'a.json'); const pathB = join(root, 'b.json'); const d02ClosurePath = join(root, 'd02.json');
  writeFileSync(pathA, envelopeA.bytes); writeFileSync(pathB, envelopeB.bytes); writeFileSync(d02ClosurePath, c(d02Closure)); chmodSync(pathA, 0o600); chmodSync(pathB, 0o600);
  const options = { profileCorePath: join(root, 'profile.json'), descriptorPath: join(root, 'descriptor.json'), d02ClosurePath, hostAEnvelopePath: pathA, hostBEnvelopePath: pathB, outputDirectory: join(root, 'out'), expectedCommit: 'a'.repeat(40), expectedTree: 'b'.repeat(40), releaseRootId: 'test-root' };
  const result = await runV2Q08PairQualification(options, {
    testOnly: true,
    verifyD02Closure: async (material) => material,
    verifyFinalInputs: async () => identity,
    verifyEnvelope: (bytes) => inspectV2Q08HostSignatureEnvelope({ authority: bytes.equals(envelopeA.bytes) ? a : b, envelopeBytes: bytes }),
  });
  assert.equal(result.q08Qualified, false); assert.equal(existsSync(join(root, 'out')), false);
});

test('rejects two signatures over one copied host journey', async (t) => {
  const root = mkdtempSync('/dev/shm/shieldkit-q08-pair-copy-');
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const identity = { profileId: h('1'), profileSha256: h('2'), instanceId: h('3'), carrierCount: 7, d02AuditPolicySha256: h('0'), descriptorSha256: h('4'), manifestSha256: h('5'), runtimeMaterialSha256: h('6'), releaseBootstrapSha256: h('7'), releaseRootId: 'test-root', topologyId: 'pf10-test', verifierRoles: [] };
  const d02Closure = { testOnly: true };
  const d02ClosureSha256 = digest(d02Closure);
  const statementIdentity = { ...identity, d02ClosureSha256 };
  const pairA = generateKeyPairSync('ed25519'); const pairB = generateKeyPairSync('ed25519');
  const authority = (role, pair) => ({ role, signerId: `test-${role}`, organizationId: `test-org-${role}`, independenceDomain: `test-domain-${role}`, publicKey: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString() });
  const a = authority('clean-host-a', pairA); const b = authority('clean-host-b', pairB);
  const statementA = statement(statementIdentity, h('c'), h('f'));
  const statementB = structuredClone(statementA);
  statementB.hostIdentity = h('d');
  const envelopeA = createV2Q08HostSignatureEnvelope({ authority: a, privateKey: pairA.privateKey, statement: statementA });
  const envelopeB = createV2Q08HostSignatureEnvelope({ authority: b, privateKey: pairB.privateKey, statement: statementB });
  const pathA = join(root, 'a.json'); const pathB = join(root, 'b.json'); const d02ClosurePath = join(root, 'd02.json');
  writeFileSync(pathA, envelopeA.bytes); writeFileSync(pathB, envelopeB.bytes); writeFileSync(d02ClosurePath, c(d02Closure));
  const options = { profileCorePath: join(root, 'profile.json'), descriptorPath: join(root, 'descriptor.json'), d02ClosurePath, hostAEnvelopePath: pathA, hostBEnvelopePath: pathB, outputDirectory: join(root, 'out'), expectedCommit: 'a'.repeat(40), expectedTree: 'b'.repeat(40), releaseRootId: 'test-root' };
  await assert.rejects(
    runV2Q08PairQualification(options, {
      testOnly: true,
      verifyD02Closure: async (material) => material,
      verifyFinalInputs: async () => identity,
      verifyEnvelope: (bytes) => inspectV2Q08HostSignatureEnvelope({ authority: bytes.equals(envelopeA.bytes) ? a : b, envelopeBytes: bytes }),
    }),
    /independently funded|reuse an action transaction/u,
  );
  assert.equal(existsSync(join(root, 'out')), false);
});

test('rejects dependency injection outside explicit TEST-ONLY mode and exact CLI path violations', async (t) => {
  const root = mkdtempSync('/dev/shm/shieldkit-q08-pair-test-');
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const options = { profileCorePath: join(root, 'p'), descriptorPath: join(root, 'd'), d02ClosurePath: join(root, 'd02'), hostAEnvelopePath: join(root, 'a'), hostBEnvelopePath: join(root, 'b'), outputDirectory: join(root, 'out'), expectedCommit: 'a'.repeat(40), expectedTree: 'b'.repeat(40), releaseRootId: 'test-root' };
  await assert.rejects(runV2Q08PairQualification(options, { verifyFinalInputs: async () => ({}) }), /TEST-ONLY/u);
  assert.throws(() => parseV2Q08PairArguments(['--profile-core', 'relative']), /usage|malformed/u);
});
