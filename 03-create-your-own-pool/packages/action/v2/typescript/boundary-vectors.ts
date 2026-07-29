import { decodeStateNft, encodeStateNft, internal, type StateNft } from './codec.js';

const STATE_KEYS = ['actionSequence', 'maximumLiveNotes', 'noteCount', 'noteRoot', 'nullifierCount', 'nullifierRoot', 'profileId', 'reserveSats'];
const IDS = [
  'zero-roots-empty-live-set', 'minimum-nonzero-roots-one-live', 'maximum-canonical-roots-empty-live-set',
  'noncanonical-note-root-modulus', 'noncanonical-nullifier-root-modulus', 'count-and-nullifier-maximums',
  'nullifier-count-u32-maximum-rejected', 'nullifier-count-exceeds-note-count', 'maximum-live-notes-one-live-one',
  'live-count-exceeds-maximum-live-notes', 'maximum-live-notes-210000000-and-maximum-reserve',
  'maximum-live-notes-above-denomination-cap', 'maximum-live-notes-zero', 'reserve-zero-empty-live-set',
  'reserve-mismatch-one-satoshi', 'action-sequence-counter-floor', 'action-sequence-counter-ceiling',
  'action-sequence-below-counter-floor', 'action-sequence-above-counter-ceiling',
  'action-sequence-absolute-maximum-rejected-by-counter-ceiling', 'action-sequence-absolute-range-limit',
  'u32-little-endian-pattern', 'u64-reserve-little-endian-pattern', 'u64-action-sequence-little-endian-pattern',
  'state-length-127', 'state-length-129',
] as const;

type RecordValue = Record<string, unknown>;
const fail = (message: string): never => { throw new Error(`state boundary vectors: ${message}`); };
const record = (value: unknown, label: string): RecordValue => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail(`${label} is not an object`);
  return value as RecordValue;
};
const exactKeys = (value: RecordValue, expected: readonly string[], label: string): void => {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail(`${label} keys`);
};
const string = (value: unknown, label: string): string => typeof value === 'string' ? value : fail(`${label} is not a string`);
const hex = (value: string, label: string): Uint8Array => {
  if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) fail(`${label} is not lowercase even-length hex`);
  return internal.hexToBytes(value);
};
const throws = (fn: () => unknown, label: string): void => {
  try { fn(); } catch { return; }
  fail(`${label} unexpectedly accepted`);
};

/** Validates the JSONL artifact through this implementation only. */
export function validateStateBoundaryVectors(raw: unknown): void {
  if (!Array.isArray(raw) || raw.length < 2) fail('records');
  const records = raw as unknown[];
  const header = record(records[0], 'header');
  exactKeys(header, ['defaultState', 'denominationSats', 'schema', 'stateBytes', 'vectorCount'], 'header');
  if (header.schema !== 'shieldkit/v2-direct-q01-state-boundary-vectors/v1' || header.denominationSats !== '10000000' || header.stateBytes !== 128) fail('header values');
  const defaultState = record(header.defaultState, 'defaultState');
  exactKeys(defaultState, STATE_KEYS, 'defaultState');
  const vectors = records.slice(1);
  if (header.vectorCount !== vectors.length || vectors.length !== IDS.length) fail('vector count');
  for (let index = 0; index < vectors.length; index += 1) {
    const vector = record(vectors[index], `vector ${index}`);
    const hasState = Object.hasOwn(vector, 'state');
    exactKeys(vector, hasState ? ['expect', 'id', 'state', 'stateHex'] : ['expect', 'id', 'stateHex'], `vector ${index}`);
    if (vector.id !== IDS[index] || (vector.expect !== 'accept' && vector.expect !== 'reject')) fail(`vector ${index} identity`);
    const bytes = hex(string(vector.stateHex, `vector ${index}.stateHex`), `vector ${index}.stateHex`);
    if (!hasState) {
      if (vector.expect !== 'reject' || bytes.length === 128) fail(`vector ${index} length`);
      throws(() => decodeStateNft(bytes, { denominationSats: '10000000' }), `vector ${index}`);
      continue;
    }
    const override = record(vector.state, `vector ${index}.state`);
    if (Object.keys(override).some((key) => !STATE_KEYS.includes(key))) fail(`vector ${index} override key`);
    const state = { ...defaultState, ...override } as unknown as StateNft;
    if (bytes.length !== 128) fail(`vector ${index} state length`);
    if (vector.expect === 'accept') {
      if (internal.bytesToHex(encodeStateNft(state, { denominationSats: '10000000' })) !== vector.stateHex) fail(`vector ${index} encode`);
      if (JSON.stringify(decodeStateNft(bytes, { denominationSats: '10000000' })) !== JSON.stringify(state)) fail(`vector ${index} decode`);
    } else {
      throws(() => encodeStateNft(state, { denominationSats: '10000000' }), `vector ${index} encode`);
      throws(() => decodeStateNft(bytes, { denominationSats: '10000000' }), `vector ${index} decode`);
    }
  }
}
