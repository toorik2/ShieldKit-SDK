import assert from 'node:assert/strict';
import { createShieldedTransitionReference, frToBytes } from '../../../packages/core/shielded-transition.mjs';
import { BABYJUB_BASE8, babyJubMul, bytesToHex, packBabyJubPoint } from '../../../packages/recovery/portable-core.mjs';

const profileId = '8f153701118a339f1d1fd41f7c0c5afc4c15f505f74631a3264647f6d1f7e39b';
const instanceId = '3f5aa57b81dd8e4f8be305dbef75c5265baf9a24f0d746e75bfd49f2a990a3ff';
const reference = await createShieldedTransitionReference();
const note = reference.deriveNote({
  profileId, instanceId,
  sk: '000000000000000000000000000000000000000000000000000000000000000b',
  recoveryPublicKey: bytesToHex(packBabyJubPoint(babyJubMul(BABYJUB_BASE8, 31n))),
  rho: '000000000000000000000000000000000000000000000000000000000000000c',
  r: '000000000000000000000000000000000000000000000000000000000000000d',
});
const nf = BigInt(`0x${note.nf}`);
const expected = BigInt(`0x${frToBytes(nf).subarray(16, 32).toString('hex')}`);
let circuitKey = 0n;
for (let bit = 0; bit < 128; bit += 1) circuitKey |= ((nf >> BigInt(bit)) & 1n) << BigInt(bit);
assert.equal(circuitKey, expected);
console.log(JSON.stringify({ nullifier: note.nf, key: circuitKey.toString(16).padStart(32, '0') }));
