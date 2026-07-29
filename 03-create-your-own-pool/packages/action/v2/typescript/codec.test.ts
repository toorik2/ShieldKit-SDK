import { ACTION_KIND_CODES, actionPacketPublicLimbs, BN254_FR_MODULUS, decodeActionPacket, decodeStateNft, digestActionPacket, ENCRYPTED_RECORD_BYTES, encodeActionPacket, encodeStateNft, internal, PACKET_BYTES, PACKET_OFFSETS, PacketCodecError, sha256, STATE_BYTES, STATE_OFFSETS, StateCodecError } from './codec.js';

const context = Object.freeze({ denominationSats: '10000000' });
const hex = (byte: string): string => byte.repeat(32);
const fr = (value: bigint): string => value.toString(16).padStart(64, '0');
const expect = (condition: boolean, message: string): void => { if (!condition) throw new Error(message); };
const throws = (fn: () => unknown, pattern: RegExp): void => { try { fn(); } catch (error) { expect(error instanceof Error && pattern.test(error.message), `wrong error: ${String(error)}`); return; } throw new Error(`expected ${pattern}`); };
const equal = (left: Uint8Array, right: Uint8Array, message: string): void => expect(internal.bytesToHex(left) === internal.bytesToHex(right), message);

const state = (noteCount: string, nullifierCount: string, actionSequence: string, root: bigint, reserveSats: string) => ({ profileId: hex('11'), noteRoot: fr(root), nullifierRoot: fr(2n), noteCount, nullifierCount, maximumLiveNotes: '7', reserveSats, actionSequence });
const packet = Object.freeze({ kind: 'deposit' as const, networkId: 2 as const, instanceId: hex('22'), preState: state('0','0','0',1n,'0'), postState: state('1','0','1',3n,'10000000'), publicNullifier: hex('00'), outputNoteLeaf: fr(5n), encryptedRecord: new Uint8Array(ENCRYPTED_RECORD_BYTES).fill(0x44), withdrawalLockingBytecodeHash: hex('00'), transactionContextHash: hex('55') });

function testState(): void {
  const encoded = encodeStateNft(packet.postState, context);
  expect(encoded.length === STATE_BYTES && STATE_BYTES === 128, 'SKS2 length');
  expect(internal.bytesToHex(encoded.slice(0, 4)) === '534b5332', 'SKS2 magic');
  expect(internal.bytesToHex(encoded.slice(STATE_OFFSETS.noteCount, STATE_OFFSETS.noteCount + 4)) === '01000000', 'u32le count');
  equal(encodeStateNft(decodeStateNft(encoded, context), context), encoded, 'SKS2 round trip');
  for (const length of [127, 129]) throws(() => decodeStateNft(new Uint8Array(length), context), /exactly 128 bytes/);
  for (const mutation of [
    ['magic', 0, 0x01, /magic/], ['profile', 4, 0x01, null], ['note root', 36, 0xff, /canonical BN254/], ['nullifier root', 68, 0xff, /canonical BN254/], ['note count', 100, 0xff, /liveNoteCount|reserveSats/], ['nullifier count', 104, 0xff, /exceeds noteCount/], ['capacity', 108, 0x01, null], ['reserve', 112, 0x01, /reserveSats/], ['sequence', 120, 0xff, /counter ceiling|exceeds its range/],
  ] as const) { const changed = encoded.slice(); changed[mutation[1]] = (changed[mutation[1]] ?? 0) ^ mutation[2]; if (mutation[3] === null) expect(internal.bytesToHex(encodeStateNft(decodeStateNft(changed, context), context)) === internal.bytesToHex(changed), `${mutation[0]} changed state`); else throws(() => decodeStateNft(changed, context), mutation[3]); }
  throws(() => encodeStateNft({ ...packet.postState, noteRoot: fr(BN254_FR_MODULUS) }, context), /canonical BN254/);
  throws(() => encodeStateNft({ ...packet.postState, actionSequence: '01' }, context), /canonical unsigned decimal/);
}
function testPacket(): void {
  const encoded = encodeActionPacket(packet, context);
  expect(encoded.length === PACKET_BYTES && PACKET_BYTES === 552, 'SDA2 length'); expect(internal.bytesToHex(encoded.slice(0, 8)) === '5344413202010000', 'SDA2 header');
  equal(encodeActionPacket(decodeActionPacket(encoded, context), context), encoded, 'SDA2 round trip');
  const digest = digestActionPacket(encoded, context); expect(internal.bytesToHex(digest) === 'ded42d09831ea2f39e521ce62b5faf474cf70946a76e934b6d6abe2280559a18', 'packet digest KAT');
  expect(JSON.stringify(actionPacketPublicLimbs(encoded, context)) === JSON.stringify(['296190295460325907773963638825346379591','102304013143187191688059162453337283096']), 'u128 limbs');
  expect(internal.bytesToHex(sha256(new Uint8Array())) === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'independent sha256 KAT');
  for (const length of [551, 553]) throws(() => decodeActionPacket(new Uint8Array(length), context), /exactly 552 bytes/);
  for (const mutation of [
    ['magic', 0, /magic/], ['network', 4, /network/], ['kind', 5, /kind/], ['flags lo', 6, /flags/], ['flags hi', 7, /flags/], ['pre-state', PACKET_OFFSETS.preState + 100, /reserveSats|liveNoteCount/], ['post-state', PACKET_OFFSETS.postState + 104, /reserveSats/], ['inactive nullifier', PACKET_OFFSETS.publicNullifier + 31, /inactive/], ['active output leaf', PACKET_OFFSETS.outputNoteLeaf + 31, null], ['active record', PACKET_OFFSETS.encryptedRecord, null], ['inactive withdrawal hash', PACKET_OFFSETS.withdrawalLockingBytecodeHash + 31, /inactive/], ['context hash', PACKET_OFFSETS.transactionContextHash, null],
  ] as const) { const changed = encoded.slice(); changed[mutation[1]] = (changed[mutation[1]] ?? 0) ^ 1; if (mutation[2] === null) { expect(internal.bytesToHex(digestActionPacket(changed, context)) !== internal.bytesToHex(digest), `${mutation[0]} must affect digest`); } else throws(() => decodeActionPacket(changed, context), mutation[2]); }
  const transfer = { ...packet, kind: 'transfer' as const, preState: state('1','0','1',3n,'10000000'), postState: state('2','1','2',4n,'10000000'), publicNullifier: fr(9n) };
  const withdrawal = { ...packet, kind: 'withdrawal' as const, preState: state('1','0','1',3n,'10000000'), postState: state('1','1','2',3n,'0'), publicNullifier: fr(9n), outputNoteLeaf: hex('00'), encryptedRecord: new Uint8Array(128), withdrawalLockingBytecodeHash: hex('66') };
  expect(decodeActionPacket(encodeActionPacket(transfer, context), context).kind === 'transfer', 'transfer'); expect(decodeActionPacket(encodeActionPacket(withdrawal, context), context).kind === 'withdrawal', 'withdrawal');
  throws(() => encodeActionPacket({ ...packet, publicNullifier: fr(1n) }, context), /inactive/);
  throws(() => encodeActionPacket({ ...transfer, withdrawalLockingBytecodeHash: hex('01') }, context), /inactive/);
  throws(() => encodeActionPacket({ ...withdrawal, encryptedRecord: new Uint8Array(128).fill(1) }, context), /inactive/);
  expect(ACTION_KIND_CODES.deposit === 1 && ACTION_KIND_CODES.transfer === 2 && ACTION_KIND_CODES.withdrawal === 3, 'kind mapping');
}

type RegionEvidence = { accepted: number; rejected: number; };
type OffsetMutationEvidence = { state: Record<string, RegionEvidence>; packet: Record<string, RegionEvidence>; };
const regions = (offset: number, ranges: readonly (readonly [string, number, number])[]): string => {
  const region = ranges.find((candidate) => offset >= candidate[1] && offset < candidate[2]);
  if (region === undefined) throw new Error(`missing region for offset ${offset}`);
  return region[0];
};
const stateRegions = [
  ['magic', 0, 4], ['profileId', 4, 36], ['noteRoot', 36, 68], ['nullifierRoot', 68, 100],
  ['noteCount', 100, 104], ['nullifierCount', 104, 108], ['maximumLiveNotes', 108, 112],
  ['reserveSats', 112, 120], ['actionSequence', 120, 128],
] as const;
const packetRegions = [
  ['magic', 0, 4], ['networkId', 4, 5], ['kind', 5, 6], ['flags', 6, 8], ['instanceId', 8, 40],
  ['preState', 40, 168], ['postState', 168, 296], ['publicNullifier', 296, 328],
  ['outputNoteLeaf', 328, 360], ['encryptedRecord', 360, 488],
  ['withdrawalLockingBytecodeHash', 488, 520], ['transactionContextHash', 520, 552],
] as const;
const increment = (target: Record<string, RegionEvidence>, name: string, result: keyof RegionEvidence): void => {
  const current = target[name];
  if (current === undefined) target[name] = { accepted: result === 'accepted' ? 1 : 0, rejected: result === 'rejected' ? 1 : 0 };
  else current[result] += 1;
};

/**
 * Per-offset smoke evidence. The full all-255-alternate-byte qualification is
 * run for this compiled TypeScript surface by parity.test.mjs through the
 * independent frozen-semantics oracle in strict-codec-qualification.mjs.
 */
function testExhaustiveOffsetMutations(): OffsetMutationEvidence {
  const stateBytes = encodeStateNft(packet.postState, context);
  const depositBytes = encodeActionPacket(packet, context);
  const stateEvidence: Record<string, RegionEvidence> = {};
  const packetEvidence: Record<string, RegionEvidence> = {};
  for (let offset = 0; offset < STATE_BYTES; offset += 1) {
    const changed = stateBytes.slice(); changed[offset] = (changed[offset] ?? 0) ^ 0x01;
    const region = regions(offset, stateRegions);
    try {
      const rebuilt = encodeStateNft(decodeStateNft(changed, context), context);
      equal(rebuilt, changed, `state offset ${offset} was normalized or aliased`);
      increment(stateEvidence, region, 'accepted');
    } catch (error) {
      if (error instanceof StateCodecError) increment(stateEvidence, region, 'rejected');
      else throw error;
    }
  }
  const baselineDigest = internal.bytesToHex(digestActionPacket(depositBytes, context));
  const baselineLimbs = JSON.stringify(actionPacketPublicLimbs(depositBytes, context));
  for (let offset = 0; offset < PACKET_BYTES; offset += 1) {
    const changed = depositBytes.slice(); changed[offset] = (changed[offset] ?? 0) ^ 0x01;
    const region = regions(offset, packetRegions);
    try {
      const rebuilt = encodeActionPacket(decodeActionPacket(changed, context), context);
      equal(rebuilt, changed, `packet offset ${offset} was normalized or aliased`);
      expect(internal.bytesToHex(digestActionPacket(changed, context)) !== baselineDigest, `packet offset ${offset} preserved SHA-256 digest`);
      expect(JSON.stringify(actionPacketPublicLimbs(changed, context)) !== baselineLimbs, `packet offset ${offset} preserved public limbs`);
      increment(packetEvidence, region, 'accepted');
    } catch (error) {
      if (error instanceof StateCodecError || error instanceof PacketCodecError) increment(packetEvidence, region, 'rejected');
      else throw error;
    }
  }
  const evidence = Object.freeze({ state: stateEvidence, packet: packetEvidence });
  const stateTotal = Object.values(evidence.state).reduce((total, value) => total + value.accepted + value.rejected, 0);
  const packetTotal = Object.values(evidence.packet).reduce((total, value) => total + value.accepted + value.rejected, 0);
  expect(stateTotal === STATE_BYTES, 'state offset mutation coverage');
  expect(packetTotal === PACKET_BYTES, 'packet offset mutation coverage');
  return evidence;
}

testState(); testPacket();
export const offsetMutationEvidence: OffsetMutationEvidence = testExhaustiveOffsetMutations();
console.log('V2 strict TypeScript codec tests: passed');
console.log(`V2_OFFSET_MUTATION_EVIDENCE=${JSON.stringify(offsetMutationEvidence)}`);
