import assert from 'node:assert/strict';
import { createShieldedTransitionReference, frToBytes } from '../../../packages/core/shielded-transition.mjs';

const profileId = '8f153701118a339f1d1fd41f7c0c5afc4c15f505f74631a3264647f6d1f7e39b';
const instanceId = '3f5aa57b81dd8e4f8be305dbef75c5265baf9a24f0d746e75bfd49f2a990a3ff';
const reference = await createShieldedTransitionReference();
const note = reference.deriveNote({
  profileId, instanceId,
  sk: '000000000000000000000000000000000000000000000000000000000000000b',
  rho: '000000000000000000000000000000000000000000000000000000000000000c',
  r: '000000000000000000000000000000000000000000000000000000000000000d',
});
const nf = BigInt(`0x${note.nf}`);
const expected = BigInt(`0x${frToBytes(nf).subarray(0, 16).toString('hex')}`);
let circuitKey = 0n;
for (let bit = 0; bit < 126; bit += 1) circuitKey |= ((nf >> BigInt(128 + bit)) & 1n) << BigInt(bit);
// Bits 126 and 127 are zero because canonical BN254 Fr values use <=254 bits.
assert.equal(circuitKey, expected);
assert.equal((circuitKey >> 126n) & 3n, 0n);
console.log(JSON.stringify({ nullifier: note.nf, key: circuitKey.toString(16).padStart(32, '0') }));
