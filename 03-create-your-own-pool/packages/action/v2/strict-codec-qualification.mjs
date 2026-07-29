import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const q01Vectors = Object.freeze(JSON.parse(readFileSync(
  fileURLToPath(new URL('./vectors/q01-state-packet-public-input.json', import.meta.url)),
  'utf8',
)));

// This oracle intentionally does not call either codec. It is the frozen
// SKS2/SDA2 field contract used to classify every single-byte replacement.
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const DENOMINATION = 10_000_000n;
const MAX_MONEY = 2_100_000_000_000_000n;
const ZERO_32 = Buffer.alloc(32);
const ZERO_128 = Buffer.alloc(128);
const hex = (byte) => byte.repeat(32);
const fr = (value) => value.toString(16).padStart(64, '0');
const readLe = (bytes, offset, size) => {
  let value = 0n;
  for (let index = 0; index < size; index += 1) value |= BigInt(bytes[offset + index]) << BigInt(index * 8);
  return value;
};
const readBe = (bytes, offset, size) => BigInt(`0x${Buffer.from(bytes.subarray(offset, offset + size)).toString('hex')}`);
const equal = (left, right) => Buffer.from(left).equals(Buffer.from(right));
const allZero = (bytes) => Buffer.from(bytes).equals(Buffer.alloc(bytes.length));

const fixture = Object.freeze({
  context: Object.freeze({ denominationSats: '10000000' }),
  postState: Object.freeze({
    profileId: hex('11'), noteRoot: fr(3n), nullifierRoot: fr(2n),
    noteCount: '1', nullifierCount: '0', maximumLiveNotes: '7',
    reserveSats: '10000000', actionSequence: '1',
  }),
  packet: Object.freeze({
    kind: 'deposit', networkId: 2, instanceId: hex('22'),
    preState: Object.freeze({ profileId: hex('11'), noteRoot: fr(1n), nullifierRoot: fr(2n), noteCount: '0', nullifierCount: '0', maximumLiveNotes: '7', reserveSats: '0', actionSequence: '0' }),
    postState: Object.freeze({ profileId: hex('11'), noteRoot: fr(3n), nullifierRoot: fr(2n), noteCount: '1', nullifierCount: '0', maximumLiveNotes: '7', reserveSats: '10000000', actionSequence: '1' }),
    publicNullifier: hex('00'), outputNoteLeaf: fr(5n), encryptedRecord: Buffer.alloc(128, 0x44),
    withdrawalLockingBytecodeHash: hex('00'), transactionContextHash: hex('55'),
  }),
});

function stateAccepted(bytes, offset = 0) {
  if (!equal(bytes.subarray(offset, offset + 4), Buffer.from('SKS2'))) return false;
  const noteRoot = readBe(bytes, offset + 36, 32);
  const nullifierRoot = readBe(bytes, offset + 68, 32);
  if (noteRoot >= FR || nullifierRoot >= FR) return false;
  const noteCount = readLe(bytes, offset + 100, 4);
  const nullifierCount = readLe(bytes, offset + 104, 4);
  const maximumLiveNotes = readLe(bytes, offset + 108, 4);
  const reserveSats = readLe(bytes, offset + 112, 8);
  const actionSequence = readLe(bytes, offset + 120, 8);
  if (nullifierCount > noteCount || nullifierCount > 0xffff_fffen) return false;
  if (maximumLiveNotes === 0n || maximumLiveNotes > MAX_MONEY / DENOMINATION) return false;
  const live = noteCount - nullifierCount;
  if (live > maximumLiveNotes || reserveSats !== live * DENOMINATION) return false;
  return actionSequence < (1n << 33n)
    && actionSequence >= (noteCount > nullifierCount ? noteCount : nullifierCount)
    && actionSequence <= noteCount + nullifierCount;
}

function packetAccepted(bytes) {
  if (!equal(bytes.subarray(0, 4), Buffer.from('SDA2'))) return false;
  const network = bytes[4];
  const kind = bytes[5];
  if ((network !== 1 && network !== 2) || (kind !== 1 && kind !== 2 && kind !== 3) || bytes[6] !== 0 || bytes[7] !== 0) return false;
  if (!stateAccepted(bytes, 40) || !stateAccepted(bytes, 168)) return false;
  if (readBe(bytes, 296, 32) >= FR || readBe(bytes, 328, 32) >= FR) return false;
  if (!equal(bytes.subarray(44, 76), bytes.subarray(172, 204))) return false;
  if (!equal(bytes.subarray(148, 152), bytes.subarray(276, 280))) return false;
  if (kind === 1 && (!allZero(bytes.subarray(296, 328)) || !allZero(bytes.subarray(488, 520)))) return false;
  if (kind === 2 && !allZero(bytes.subarray(488, 520))) return false;
  return kind !== 3 || (allZero(bytes.subarray(328, 360)) && equal(bytes.subarray(360, 488), ZERO_128));
}

function expectedDigestAndLimbs(bytes) {
  const digest = createHash('sha256').update(bytes).digest();
  return Object.freeze({
    digest,
    limbs: Object.freeze([
      BigInt(`0x${digest.subarray(0, 16).toString('hex')}`).toString(),
      BigInt(`0x${digest.subarray(16, 32).toString('hex')}`).toString(),
    ]),
  });
}

function expectOutcome(expected, decode, encode, bytes, context, original, label) {
  if (expected) {
    const decoded = decode(bytes, context);
    assert.notDeepEqual(decoded, original, `${label}: accepted mutation must decode to a semantically distinct object`);
    assert.deepEqual(Buffer.from(encode(decoded, context)), Buffer.from(bytes), `${label}: accepted bytes must round-trip exactly`);
  } else {
    assert.throws(() => decode(bytes, context), `${label}: frozen semantics require rejection`);
  }
}

function sweep(bytes, accepted, decode, encode, context, label) {
  const baselineDecoded = decode(bytes, context);
  let accepts = 0;
  let rejects = 0;
  for (let offset = 0; offset < bytes.length; offset += 1) {
    const originalByte = bytes[offset];
    for (let replacement = 0; replacement < 256; replacement += 1) {
      if (replacement === originalByte) continue;
      const changed = Buffer.from(bytes);
      changed[offset] = replacement;
      const expected = accepted(changed);
      expectOutcome(expected, decode, encode, changed, context, baselineDecoded, `${label}[${offset}]=${replacement}`);
      if (expected) accepts += 1;
      else rejects += 1;
    }
  }
  assert.equal(accepts + rejects, bytes.length * 255, `${label}: every alternate byte value covered`);
  return Object.freeze({ accepts, rejects, mutations: bytes.length * 255 });
}

export function runStrictCodecQualification(surface) {
  const { context, postState, packet } = fixture;
  const preState = Buffer.from(surface.encodeState(packet.preState, context));
  const state = Buffer.from(surface.encodeState(postState, context));
  const packetBytes = Buffer.from(surface.encodePacket(packet, context));
  assert.equal(q01Vectors.schema, 'shieldkit/v2-direct-q01-codec-vectors/v1', `${surface.name}: Q01 vector schema`);
  assert.equal(context.denominationSats, q01Vectors.denominationSats, `${surface.name}: Q01 denomination`);
  assert.equal(state.length, 128, `${surface.name}: state fixture length`);
  assert.equal(packetBytes.length, 552, `${surface.name}: packet fixture length`);
  assert.equal(preState.toString('hex'), q01Vectors.preStateHex, `${surface.name}: Q01 pre-state vector`);
  assert.equal(state.toString('hex'), q01Vectors.postStateHex, `${surface.name}: Q01 post-state vector`);
  assert.equal(packetBytes.toString('hex'), q01Vectors.packetHex, `${surface.name}: Q01 packet vector`);
  for (const length of [127, 129]) assert.throws(() => surface.decodeState(new Uint8Array(length), context), /exactly 128 bytes/, `${surface.name}: ${length}-byte state rejection`);
  for (const length of [551, 553]) assert.throws(() => surface.decodePacket(new Uint8Array(length), context), /exactly 552 bytes/, `${surface.name}: ${length}-byte packet rejection`);

  // CashToken prefix bytes are consensus bytes. Explorer txid display is the
  // reverse-only UI representation and must not be substituted into SDA2.
  const categoryWire = Buffer.from(q01Vectors.categoryWireHex, 'hex');
  const explorerDisplay = Buffer.from(categoryWire).reverse();
  assert.equal(explorerDisplay.toString('hex'), q01Vectors.categoryExplorerDisplayHex, `${surface.name}: Q01 category display vector`);
  const categoryPacket = { ...packet, instanceId: categoryWire.toString('hex') };
  const categoryBytes = Buffer.from(surface.encodePacket(categoryPacket, context));
  assert.deepEqual(categoryBytes.subarray(8, 40), categoryWire, `${surface.name}: token category uses wire order`);
  assert.notDeepEqual(categoryBytes.subarray(8, 40), explorerDisplay, `${surface.name}: explorer display order is not packet order`);
  assert.equal(surface.decodePacket(categoryBytes, context).instanceId, categoryWire.toString('hex'), `${surface.name}: category round-trip preserves wire order`);

  const baseline = expectedDigestAndLimbs(packetBytes);
  assert.equal(baseline.digest.toString('hex'), q01Vectors.packetSha256Hex, `${surface.name}: Q01 packet digest vector`);
  assert.deepEqual(baseline.limbs, [q01Vectors.publicInput0BeU128, q01Vectors.publicInput1BeU128], `${surface.name}: Q01 public-input vector`);
  assert.deepEqual(Buffer.from(surface.digestPacket(packetBytes, context)), baseline.digest, `${surface.name}: SHA-256 packet KAT`);
  assert.deepEqual(surface.packetLimbs(packetBytes, context), baseline.limbs, `${surface.name}: SHA-256 BE u128 limbs`);
  const stateEvidence = sweep(state, stateAccepted, surface.decodeState, surface.encodeState, context, `${surface.name}:SKS2`);
  const packetEvidence = sweep(packetBytes, packetAccepted, surface.decodePacket, surface.encodePacket, context, `${surface.name}:SDA2`);

  // Each accepted packet mutation must bind its complete raw packet to the ABI.
  // The sweep already establishes acceptance; this compact second pass checks
  // the two public inputs against an independently computed digest.
  let publicInputVectors = 0;
  for (let offset = 0; offset < packetBytes.length; offset += 1) {
    const original = packetBytes[offset];
    for (let replacement = 0; replacement < 256; replacement += 1) {
      if (replacement === original) continue;
      const changed = Buffer.from(packetBytes); changed[offset] = replacement;
      if (!packetAccepted(changed)) continue;
      const expected = expectedDigestAndLimbs(changed);
      assert.deepEqual(Buffer.from(surface.digestPacket(changed, context)), expected.digest, `${surface.name}: packet SHA-256 vector ${offset}/${replacement}`);
      assert.deepEqual(surface.packetLimbs(changed, context), expected.limbs, `${surface.name}: packet u128 ABI vector ${offset}/${replacement}`);
      assert.notDeepEqual(expected.digest, baseline.digest, `${surface.name}: accepted packet mutation must not share the baseline SHA-256 digest`);
      assert.notDeepEqual(expected.limbs, baseline.limbs, `${surface.name}: accepted packet mutation must not share the baseline u128 limbs`);
      publicInputVectors += 1;
    }
  }
  return Object.freeze({
    schema: 'shieldkit/v2-strict-codec-qualification/v1',
    surface: surface.name,
    lengthsRejected: Object.freeze({ state: Object.freeze([127, 129]), packet: Object.freeze([551, 553]) }),
    categoryByteOrder: Object.freeze({
      wireHex: categoryWire.toString('hex'),
      explorerDisplayHex: explorerDisplay.toString('hex'),
    }),
    sha256BeU128: Object.freeze({ digestHex: baseline.digest.toString('hex'), limbs: baseline.limbs }),
    state: Object.freeze({
      mutations: stateEvidence.mutations,
      acceptedCanonicalDistinct: stateEvidence.accepts,
      rejected: stateEvidence.rejects,
    }),
    packet: Object.freeze({
      mutations: packetEvidence.mutations,
      acceptedCanonicalDistinct: packetEvidence.accepts,
      rejected: packetEvidence.rejects,
    }),
    publicInputVectors,
  });
}
