/* TEST-ONLY: rejection/schema tests never create a Q-02 corpus or result. */
import assert from 'node:assert/strict';
import test from 'node:test';
import { ACTION_PACKET_OFFSETS } from '../packages/action/v2/packet.mjs';
import {
  assertV2Q02ExternalLaneMapForTestOnly,
  isV2Q02GenericPacketMutation,
  isV2Q02IsolatedOutpointMutation,
  parseV2Q02Arguments,
  requiredV2Q02ExternalLanesForExpectation,
  V2_Q02_ACCEPTANCE_EXTERNAL_LANES,
  V2_Q02_REJECTION_EXTERNAL_LANES,
  V2Q02FinalKeyCorpusError,
  verifyV2Q02FinalKeyCorpus,
} from './v2-q02-final-key-corpus.mjs';
test('Q-02 requires a compiled release-root and rejects legacy trusted-signers', () => {
  assert.throws(() => parseV2Q02Arguments([]), V2Q02FinalKeyCorpusError);
  assert.throws(() => parseV2Q02Arguments([
    '--corpus', 'relative',
    '--descriptor', '/d',
    '--profile-core', '/p',
    '--release-root', 'final-chipnet',
  ]), /absolute normalized/u);
  assert.throws(() => parseV2Q02Arguments([
    '--corpus', '/c',
    '--descriptor', '/d',
    '--profile-core', '/p',
    '--trusted-signers', '/s',
  ]), /malformed|usage/u);
  assert.deepEqual(parseV2Q02Arguments([
    '--corpus', '/c',
    '--descriptor', '/d',
    '--profile-core', '/p',
    '--release-root', 'final-chipnet',
  ]), {
    corpusPath: '/c',
    descriptorPath: '/d',
    profileCorePath: '/p',
    releaseRootId: 'final-chipnet',
  });
});
test('Q-02 refuses injected doubles before accepting any qualification path', async () => {
  await assert.rejects(() => verifyV2Q02FinalKeyCorpus({}, { fake: true }), /refuses injected test doubles/u);
});

test('Q-02 lane sets are exact and case-specific: mined inclusion is acceptance-only', () => {
  assert.deepEqual(V2_Q02_ACCEPTANCE_EXTERNAL_LANES, [
    'maintainer',
    'bchn-mempool',
    'bchn-mined',
    'leanbch',
  ]);
  assert.deepEqual(V2_Q02_REJECTION_EXTERNAL_LANES, [
    'maintainer',
    'bchn-mempool',
    'leanbch',
  ]);
  assert.equal(
    requiredV2Q02ExternalLanesForExpectation('accept'),
    V2_Q02_ACCEPTANCE_EXTERNAL_LANES,
  );
  assert.equal(
    requiredV2Q02ExternalLanesForExpectation('reject'),
    V2_Q02_REJECTION_EXTERNAL_LANES,
  );
  const acceptance = Object.fromEntries(
    V2_Q02_ACCEPTANCE_EXTERNAL_LANES.map((lane) => [lane, null]),
  );
  const rejection = Object.fromEntries(
    V2_Q02_REJECTION_EXTERNAL_LANES.map((lane) => [lane, null]),
  );
  assert.equal(
    assertV2Q02ExternalLaneMapForTestOnly(acceptance, 'accept'),
    acceptance,
  );
  assert.equal(
    assertV2Q02ExternalLaneMapForTestOnly(rejection, 'reject'),
    rejection,
  );
  assert.throws(
    () => assertV2Q02ExternalLaneMapForTestOnly(
      { ...acceptance, 'bchn-mined': undefined },
      'reject',
    ),
    /missing or unknown properties/u,
  );
  const missingMined = { ...acceptance };
  delete missingMined['bchn-mined'];
  assert.throws(
    () => assertV2Q02ExternalLaneMapForTestOnly(missingMined, 'accept'),
    /missing or unknown properties/u,
  );
  assert.throws(
    () => requiredV2Q02ExternalLanesForExpectation('unknown'),
    /expectation is invalid/u,
  );
});

test('Q-02 empty compiled release registry fails before descriptor or corpus work', async () => {
  await assert.rejects(() => verifyV2Q02FinalKeyCorpus({
    corpusPath: '/this/must/not/be/opened/corpus.json',
    descriptorPath: '/this/must/not/be/opened/instance.json',
    profileCorePath: '/this/must/not/be/opened/profile-core.json',
    releaseRootId: 'final-chipnet',
  }), /no approved V2 Direct final release roots/u);
});

test('Q-02 rejects a malformed release root ID before descriptor or corpus work', async () => {
  await assert.rejects(() => verifyV2Q02FinalKeyCorpus({
    corpusPath: '/this/must/not/be/opened/corpus.json',
    descriptorPath: '/this/must/not/be/opened/instance.json',
    profileCorePath: '/this/must/not/be/opened/profile-core.json',
    releaseRootId: '../caller-root',
  }), /root id is malformed/u);
});

test('Q-02 generic packet mutations are disjoint from profileId mutations', () => {
  const base = Buffer.alloc(552);
  const generic = Buffer.from(base);
  generic[ACTION_PACKET_OFFSETS.publicNullifier] = 1;
  assert.equal(isV2Q02GenericPacketMutation(base, generic), true);

  const profileOnly = Buffer.from(base);
  profileOnly[ACTION_PACKET_OFFSETS.preState + 4] = 1;
  profileOnly[ACTION_PACKET_OFFSETS.postState + 4] = 1;
  assert.equal(isV2Q02GenericPacketMutation(base, profileOnly), false);

  const mixed = Buffer.from(generic);
  mixed[ACTION_PACKET_OFFSETS.preState + 4] = 1;
  assert.equal(isV2Q02GenericPacketMutation(base, mixed), false);
});

function inputsForOutpointMutation() {
  return [0, 1, 2].map((index) => ({
    outpoint: { txid: String(index).repeat(64), vout: index },
    sequence: 0xfffffffe,
    sourceOutput: {
      lockingBytecodeHex: `51${index}`,
      token: null,
      tokenPrefixHex: '',
      valueSatoshis: '1000',
    },
    sourceOutputSerializedHex: `e8030000000000000251${index}`,
    sourceTransactionSha256: String(index + 3).repeat(64),
  }));
}

test('Q-02 outpoint mutation isolates one outpoint and preserves all source bytes', () => {
  const base = inputsForOutpointMutation();
  const mutant = structuredClone(base);
  mutant[1].outpoint.txid = 'f'.repeat(64);
  assert.equal(isV2Q02IsolatedOutpointMutation(base, mutant), true);

  const changedSequence = structuredClone(mutant);
  changedSequence[1].sequence = 0;
  assert.equal(isV2Q02IsolatedOutpointMutation(base, changedSequence), false);

  const changedOtherSourceBytes = structuredClone(mutant);
  changedOtherSourceBytes[2].sourceOutputSerializedHex = '00';
  assert.equal(isV2Q02IsolatedOutpointMutation(base, changedOtherSourceBytes), false);

  const changedOtherSourceTransaction = structuredClone(mutant);
  changedOtherSourceTransaction[0].sourceTransactionSha256 = 'e'.repeat(64);
  assert.equal(isV2Q02IsolatedOutpointMutation(base, changedOtherSourceTransaction), false);

  const twoOutpoints = structuredClone(mutant);
  twoOutpoints[2].outpoint.txid = 'd'.repeat(64);
  assert.equal(isV2Q02IsolatedOutpointMutation(base, twoOutpoints), false);
});
