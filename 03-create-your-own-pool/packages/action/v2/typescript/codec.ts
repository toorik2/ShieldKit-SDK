/**
 * Independent strict TypeScript codec for V2 Direct consensus bytes.
 *
 * It deliberately does not import the JavaScript codec: a disagreement here is
 * useful parity evidence, rather than two entry points to the same parser.
 */

export const STATE_BYTES = 128;
export const PACKET_BYTES = 552;
export const ENCRYPTED_RECORD_BYTES = 128;
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;
export const BN254_FR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const STATE_OFFSETS = Object.freeze({
  magic: 0, profileId: 4, noteRoot: 36, nullifierRoot: 68,
  noteCount: 100, nullifierCount: 104, maximumLiveNotes: 108,
  reserveSats: 112, actionSequence: 120, end: STATE_BYTES,
});

export const PACKET_OFFSETS = Object.freeze({
  magic: 0, networkId: 4, kind: 5, flags: 6, instanceId: 8,
  preState: 40, postState: 168, publicNullifier: 296,
  outputNoteLeaf: 328, encryptedRecord: 360,
  withdrawalLockingBytecodeHash: 488, transactionContextHash: 520,
  end: PACKET_BYTES,
});

export const ACTION_KIND_CODES = Object.freeze({ deposit: 1, transfer: 2, withdrawal: 3 } as const);
export type ActionKind = keyof typeof ACTION_KIND_CODES;
export type NetworkId = 1 | 2;

export interface StateContext { readonly denominationSats: string; }
export interface StateNft {
  readonly profileId: string;
  readonly noteRoot: string;
  readonly nullifierRoot: string;
  readonly noteCount: string;
  readonly nullifierCount: string;
  readonly maximumLiveNotes: string;
  readonly reserveSats: string;
  readonly actionSequence: string;
}
export interface ActionPacket {
  readonly kind: ActionKind;
  readonly networkId: NetworkId;
  readonly instanceId: string;
  readonly preState: StateNft;
  readonly postState: StateNft;
  readonly publicNullifier: string;
  readonly outputNoteLeaf: string;
  readonly encryptedRecord: Uint8Array;
  readonly withdrawalLockingBytecodeHash: string;
  readonly transactionContextHash: string;
}

export class StateCodecError extends Error { constructor(message: string) { super(message); this.name = 'StateCodecError'; } }
export class PacketCodecError extends Error { constructor(message: string) { super(message); this.name = 'PacketCodecError'; } }

const ZERO_32 = '0'.repeat(64);
const HEX_32 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const MAX_U32 = 0xffff_ffffn;
const MAX_NULLIFIER_COUNT = 0xffff_fffen;
const MAX_ACTION_SEQUENCE = 1n << 33n;
const STATE_KEYS = ['profileId', 'noteRoot', 'nullifierRoot', 'noteCount', 'nullifierCount', 'maximumLiveNotes', 'reserveSats', 'actionSequence'];
const PACKET_KEYS = ['kind', 'networkId', 'instanceId', 'preState', 'postState', 'publicNullifier', 'outputNoteLeaf', 'encryptedRecord', 'withdrawalLockingBytecodeHash', 'transactionContextHash'];

type UnknownRecord = Record<string, unknown>;
function failState(message: string): never { throw new StateCodecError(message); }
function failPacket(message: string): never { throw new PacketCodecError(message); }
function objectWithExactKeys(value: unknown, expected: readonly string[], label: string, fail: (message: string) => never): UnknownRecord {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} has missing or unknown properties`);
  return value as UnknownRecord;
}
function decimal(value: unknown, maximum: bigint, label: string, fail: (message: string) => never): bigint {
  if (typeof value !== 'string' || !DECIMAL.test(value)) fail(`${label} must be a canonical unsigned decimal string`);
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} exceeds its range`);
  return parsed;
}
function hex32(value: unknown, label: string, fail: (message: string) => never): string {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail(`${label} must be 32 lowercase hexadecimal bytes`);
  return value;
}
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}
function fixedBytes(value: unknown, length: number, label: string, fail: (message: string) => never): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) fail(`${label} must contain exactly ${length} bytes`);
  return new Uint8Array(value);
}
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return false;
  return true;
}
function allZero(bytes: Uint8Array): boolean { return bytes.every((byte) => byte === 0); }
function writeU32LE(out: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 4; i += 1) out[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn);
}
function writeU64LE(out: Uint8Array, offset: number, value: bigint): void {
  for (let i = 0; i < 8; i += 1) out[offset + i] = Number((value >> BigInt(8 * i)) & 0xffn);
}
function readULE(bytes: Uint8Array, offset: number, width: number): bigint {
  let value = 0n;
  for (let i = 0; i < width; i += 1) value |= BigInt(bytes[offset + i] ?? 0) << BigInt(8 * i);
  return value;
}
function copy(out: Uint8Array, offset: number, input: Uint8Array): void { out.set(input, offset); }
function ascii(value: string): Uint8Array { return new Uint8Array([...value].map((character) => character.charCodeAt(0))); }
function canonicalFr(value: unknown, label: string, fail: (message: string) => never): string {
  const hex = hex32(value, label, fail);
  if (BigInt(`0x${hex}`) >= BN254_FR_MODULUS) fail(`${label} must be a canonical BN254 Fr element`);
  return hex;
}
function stateContext(value: unknown): bigint {
  const context = objectWithExactKeys(value, ['denominationSats'], 'state context', failState);
  const denomination = decimal(context.denominationSats, MAX_MONEY_SATS, 'denominationSats', failState);
  if (denomination === 0n) failState('denominationSats must be nonzero');
  return denomination;
}

function normaliseState(value: unknown, context: unknown, label: string): StateNft {
  const input = objectWithExactKeys(value, STATE_KEYS, label, failState);
  const denomination = stateContext(context);
  const noteCount = decimal(input.noteCount, MAX_U32, `${label}.noteCount`, failState);
  const nullifierCount = decimal(input.nullifierCount, MAX_NULLIFIER_COUNT, `${label}.nullifierCount`, failState);
  const maximumLiveNotes = decimal(input.maximumLiveNotes, MAX_U32, `${label}.maximumLiveNotes`, failState);
  const reserveSats = decimal(input.reserveSats, MAX_MONEY_SATS, `${label}.reserveSats`, failState);
  const actionSequence = decimal(input.actionSequence, MAX_ACTION_SEQUENCE - 1n, `${label}.actionSequence`, failState);
  if (nullifierCount > noteCount) failState(`${label}.nullifierCount exceeds noteCount`);
  const live = noteCount - nullifierCount;
  if (maximumLiveNotes === 0n) failState(`${label}.maximumLiveNotes must be at least one`);
  if (maximumLiveNotes > MAX_MONEY_SATS / denomination) failState(`${label}.maximumLiveNotes exceeds MAX_MONEY_SATS for denominationSats`);
  if (live > maximumLiveNotes) failState(`${label}.liveNoteCount exceeds maximumLiveNotes`);
  if (reserveSats !== live * denomination) failState(`${label}.reserveSats must equal liveNoteCount times denominationSats`);
  if (actionSequence < (noteCount > nullifierCount ? noteCount : nullifierCount)) failState(`${label}.actionSequence is below the counter floor`);
  if (actionSequence > noteCount + nullifierCount) failState(`${label}.actionSequence exceeds the counter ceiling`);
  return Object.freeze({
    profileId: hex32(input.profileId, `${label}.profileId`, failState),
    noteRoot: canonicalFr(input.noteRoot, `${label}.noteRoot`, failState),
    nullifierRoot: canonicalFr(input.nullifierRoot, `${label}.nullifierRoot`, failState),
    noteCount: noteCount.toString(), nullifierCount: nullifierCount.toString(),
    maximumLiveNotes: maximumLiveNotes.toString(), reserveSats: reserveSats.toString(), actionSequence: actionSequence.toString(),
  });
}

export function validateStateNft(value: unknown, context: unknown): StateNft { return normaliseState(value, context, 'state NFT commitment'); }
export function encodeStateNft(value: unknown, context: unknown): Uint8Array {
  const state = normaliseState(value, context, 'state NFT commitment');
  const out = new Uint8Array(STATE_BYTES);
  copy(out, STATE_OFFSETS.magic, ascii('SKS2'));
  copy(out, STATE_OFFSETS.profileId, hexToBytes(state.profileId));
  copy(out, STATE_OFFSETS.noteRoot, hexToBytes(state.noteRoot));
  copy(out, STATE_OFFSETS.nullifierRoot, hexToBytes(state.nullifierRoot));
  writeU32LE(out, STATE_OFFSETS.noteCount, BigInt(state.noteCount));
  writeU32LE(out, STATE_OFFSETS.nullifierCount, BigInt(state.nullifierCount));
  writeU32LE(out, STATE_OFFSETS.maximumLiveNotes, BigInt(state.maximumLiveNotes));
  writeU64LE(out, STATE_OFFSETS.reserveSats, BigInt(state.reserveSats));
  writeU64LE(out, STATE_OFFSETS.actionSequence, BigInt(state.actionSequence));
  return out;
}
export function decodeStateNft(value: unknown, context: unknown): StateNft {
  const bytes = fixedBytes(value, STATE_BYTES, 'state NFT commitment', failState);
  if (!equalBytes(bytes.slice(0, 4), ascii('SKS2'))) failState('state NFT commitment magic is invalid');
  return normaliseState({
    profileId: bytesToHex(bytes.slice(4, 36)), noteRoot: bytesToHex(bytes.slice(36, 68)), nullifierRoot: bytesToHex(bytes.slice(68, 100)),
    noteCount: readULE(bytes, 100, 4).toString(), nullifierCount: readULE(bytes, 104, 4).toString(),
    maximumLiveNotes: readULE(bytes, 108, 4).toString(), reserveSats: readULE(bytes, 112, 8).toString(), actionSequence: readULE(bytes, 120, 8).toString(),
  }, context, 'state NFT commitment');
}

function knownKind(value: unknown): ActionKind | undefined {
  return value === 'deposit' || value === 'transfer' || value === 'withdrawal' ? value : undefined;
}
function kindFromCode(code: number): ActionKind | undefined {
  if (code === 1) return 'deposit'; if (code === 2) return 'transfer'; if (code === 3) return 'withdrawal'; return undefined;
}
function network(value: unknown): NetworkId {
  if (value === 1 || value === 2) return value;
  return failPacket('action packet network is unsupported');
}
function packetState(value: unknown, context: unknown, label: string): StateNft {
  try { return validateStateNft(value, context); }
  catch (error) { if (error instanceof Error) return failPacket(`${label} is invalid: ${error.message}`); throw error; }
}
function normalisePacket(value: unknown, context: unknown): ActionPacket {
  const input = objectWithExactKeys(value, PACKET_KEYS, 'action packet', failPacket);
  const kind = knownKind(input.kind);
  if (kind === undefined) failPacket('action packet kind is unsupported');
  const packet: ActionPacket = {
    kind, networkId: network(input.networkId), instanceId: hex32(input.instanceId, 'instanceId', failPacket),
    preState: packetState(input.preState, context, 'preState'), postState: packetState(input.postState, context, 'postState'),
    publicNullifier: canonicalFr(input.publicNullifier, 'publicNullifier', failPacket), outputNoteLeaf: canonicalFr(input.outputNoteLeaf, 'outputNoteLeaf', failPacket),
    encryptedRecord: fixedBytes(input.encryptedRecord, ENCRYPTED_RECORD_BYTES, 'encryptedRecord', failPacket),
    withdrawalLockingBytecodeHash: hex32(input.withdrawalLockingBytecodeHash, 'withdrawalLockingBytecodeHash', failPacket),
    transactionContextHash: hex32(input.transactionContextHash, 'transactionContextHash', failPacket),
  };
  if (kind === 'deposit' && (packet.publicNullifier !== ZERO_32 || packet.withdrawalLockingBytecodeHash !== ZERO_32)) failPacket('deposit packet contains nonzero inactive fields');
  if (kind === 'transfer' && packet.withdrawalLockingBytecodeHash !== ZERO_32) failPacket('transfer packet contains nonzero inactive fields');
  if (kind === 'withdrawal' && (packet.outputNoteLeaf !== ZERO_32 || !allZero(packet.encryptedRecord))) failPacket('withdrawal packet contains nonzero inactive fields');
  if (packet.preState.profileId !== packet.postState.profileId) failPacket('packet changes the profileId');
  if (packet.preState.maximumLiveNotes !== packet.postState.maximumLiveNotes) failPacket('packet changes maximumLiveNotes');
  return Object.freeze(packet);
}
export function validateActionPacket(value: unknown, context: unknown): ActionPacket { return normalisePacket(value, context); }
export function encodeActionPacket(value: unknown, context: unknown): Uint8Array {
  const packet = normalisePacket(value, context); const out = new Uint8Array(PACKET_BYTES);
  copy(out, 0, ascii('SDA2')); out[4] = packet.networkId; out[5] = ACTION_KIND_CODES[packet.kind];
  copy(out, 8, hexToBytes(packet.instanceId)); copy(out, 40, encodeStateNft(packet.preState, context)); copy(out, 168, encodeStateNft(packet.postState, context));
  copy(out, 296, hexToBytes(packet.publicNullifier)); copy(out, 328, hexToBytes(packet.outputNoteLeaf)); copy(out, 360, packet.encryptedRecord);
  copy(out, 488, hexToBytes(packet.withdrawalLockingBytecodeHash)); copy(out, 520, hexToBytes(packet.transactionContextHash)); return out;
}
export function decodeActionPacket(value: unknown, context: unknown): ActionPacket {
  const bytes = fixedBytes(value, PACKET_BYTES, 'action packet', failPacket);
  if (!equalBytes(bytes.slice(0, 4), ascii('SDA2'))) failPacket('action packet magic is invalid');
  const kind = kindFromCode(bytes[5] ?? -1); if (kind === undefined) failPacket('action packet kind is unsupported');
  if ((bytes[4] ?? 0) !== 1 && (bytes[4] ?? 0) !== 2) failPacket('action packet network is unsupported');
  if ((bytes[6] ?? 0) !== 0 || (bytes[7] ?? 0) !== 0) failPacket('action packet flags must be zero');
  return normalisePacket({
    kind, networkId: bytes[4], instanceId: bytesToHex(bytes.slice(8, 40)), preState: decodeStateNft(bytes.slice(40, 168), context), postState: decodeStateNft(bytes.slice(168, 296), context),
    publicNullifier: bytesToHex(bytes.slice(296, 328)), outputNoteLeaf: bytesToHex(bytes.slice(328, 360)), encryptedRecord: bytes.slice(360, 488),
    withdrawalLockingBytecodeHash: bytesToHex(bytes.slice(488, 520)), transactionContextHash: bytesToHex(bytes.slice(520, 552)),
  }, context);
}

function rotr(value: number, shift: number): number { return (value >>> shift) | (value << (32 - shift)); }
/** Dependency-free SHA-256, used so this codec has no runtime dependency. */
export function sha256(input: Uint8Array): Uint8Array {
  const k = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const bitLength = BigInt(input.length) * 8n; const paddedLength = Math.ceil((input.length + 9) / 64) * 64; const padded = new Uint8Array(paddedLength); padded.set(input); padded[input.length] = 0x80;
  for (let i = 0; i < 8; i += 1) padded[paddedLength - 1 - i] = Number((bitLength >> BigInt(8 * i)) & 0xffn);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  for (let base = 0; base < padded.length; base += 64) {
    const w = new Uint32Array(64); for (let i = 0; i < 16; i += 1) w[i] = ((padded[base + 4*i] ?? 0) << 24) | ((padded[base + 4*i+1] ?? 0) << 16) | ((padded[base + 4*i+2] ?? 0) << 8) | (padded[base + 4*i+3] ?? 0);
    for (let i = 16; i < 64; i += 1) { const x = w[i-15] ?? 0, y = w[i-2] ?? 0; w[i] = (((rotr(x,7)^rotr(x,18)^(x>>>3)) + (w[i-16] ?? 0) + (rotr(y,17)^rotr(y,19)^(y>>>10)) + (w[i-7] ?? 0)) >>> 0); }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i += 1) { const s1=rotr(e,6)^rotr(e,11)^rotr(e,25), ch=(e&f)^((~e)&g), t1=(h+s1+ch+(k[i] ?? 0)+(w[i] ?? 0))>>>0, s0=rotr(a,2)^rotr(a,13)^rotr(a,22), maj=(a&b)^(a&c)^(b&c), t2=(s0+maj)>>>0; h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0; }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
  }
  const out = new Uint8Array(32); [h0,h1,h2,h3,h4,h5,h6,h7].forEach((word, i) => { out[i*4]=word>>>24; out[i*4+1]=(word>>>16)&255; out[i*4+2]=(word>>>8)&255; out[i*4+3]=word&255; }); return out;
}
export function digestActionPacket(value: unknown, context: unknown): Uint8Array { const bytes = fixedBytes(value, PACKET_BYTES, 'action packet', failPacket); decodeActionPacket(bytes, context); return sha256(bytes); }
export function actionPacketPublicLimbs(value: unknown, context: unknown): readonly [string, string] { const digest = digestActionPacket(value, context); return Object.freeze([BigInt(`0x${bytesToHex(digest.slice(0,16))}`).toString(), BigInt(`0x${bytesToHex(digest.slice(16,32))}`).toString()]); }
export const internal = Object.freeze({ bytesToHex, hexToBytes });
