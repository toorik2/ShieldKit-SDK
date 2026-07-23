import assert from 'node:assert/strict';
import test from 'node:test';
import { actionFixturePaths, evaluateStructuralRoles } from './real-deposit-leanbch-fixture.mjs';

test('public real deposit fixture canonically replays structural inputs 7 and 8 in Libauth', async () => {
  const result = await evaluateStructuralRoles();
  assert.equal(result.fixture.provenance.transactionId, '56563c2c3a81857216853b53293c0cedc8f4baaa15b2430553be57a0d57a6cf1');
  assert.equal(result.fixture.provenance.sourceArtifactSha256, '771976408387139d186833de5fad17d8b58853358080d5164c9a196bff0e8e95');
  assert.equal(result.fixture.transaction.sha256, '2db2737e254731e0bede2c09332e418e724746be93e26a2dde45ddb50d7f1c8e');
  assert.equal(result.fixture.transaction.bytes, 56_767);
  assert.equal(result.sourceOutputs.length, 10);
  assert.equal(result.fixture.sourceOutputsWire.sha256, result.sourceOutputsSha256);
  assert.equal(result.fixture.sourceOutputsWire.sha256, '762f553bfa655a5ca57cfadfabea54553a7339e6c7e08e14e79e3800a0331e32');
  assert.equal(result.fixture.sourceOutputsWire.bytes, result.sourceOutputsWire.length);
  assert.deepEqual(result.libauth.map(({ inputIndex, accepted }) => ({ inputIndex, accepted })), [
    { inputIndex: 7, accepted: true },
    { inputIndex: 8, accepted: true },
  ]);
  assert.equal(Object.hasOwn(result.fixture, 'proof'), false);
  assert.equal(Object.hasOwn(result.fixture, 'wallet'), false);
});

test('public real transfer and withdrawal fixtures canonically replay structural inputs 7 and 8 in Libauth', async () => {
  for (const path of actionFixturePaths.slice(1)) {
    const result = await evaluateStructuralRoles(path);
    assert.deepEqual(result.libauth.map((row) => [row.inputIndex, row.accepted]), [[7, true], [8, true]]);
  }
});
