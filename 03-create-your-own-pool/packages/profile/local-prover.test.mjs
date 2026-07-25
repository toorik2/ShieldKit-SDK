import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalProverProfileError, parseLocalProverProfileBinding } from './local-prover-profile.mjs';
const hash = (byte) => `sha256:${byte.repeat(64)}`;
const valid = () => ({ bundleDirectory: '/profiles/chipnet-a', expected: { network: 'chipnet', profileId: hash('a'), instanceId: hash('b') } });
test('local prover binding requires an absolute bundle and all immutable coordinates', () => {
  assert.equal(parseLocalProverProfileBinding(valid()).expected.network, 'chipnet');
  const relative = valid(); relative.bundleDirectory = 'relative'; assert.throws(() => parseLocalProverProfileBinding(relative), LocalProverProfileError);
  const partial = valid(); delete partial.expected.instanceId; assert.throws(() => parseLocalProverProfileBinding(partial), /unexpected keys/);
  const nonChipnet = valid(); nonChipnet.expected.network = 'mainnet'; assert.throws(() => parseLocalProverProfileBinding(nonChipnet), /must be chipnet/);
});
