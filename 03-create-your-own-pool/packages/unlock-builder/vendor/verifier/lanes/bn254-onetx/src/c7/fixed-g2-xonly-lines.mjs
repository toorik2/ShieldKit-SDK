// Authenticated table bytes for the uniform x/slope fixed-G2 representation.
// Every record is two Fp2 slopes (gamma then delta); each K=13 window begins
// with two Fp2 x-coordinate seeds. The offline constructor validates every
// reconstructed line against the live all-affine trajectory before emitting.
import { createHash } from 'node:crypto';
import { mod } from '../../../../build/chunked/pairing/_szmath.mjs';
import { fixedLineEvents } from './fixed-g2-lines.mjs';
import { XONLY_RECORD_BYTES, XONLY_SEED_BYTES, XONLY_WINDOWS, xOnlyWindowFor } from './xonly-fixed-g2-plan.mjs';
import { xOnlyFixedLineEvents, xOnlyStateBeforeStep } from './xonly-fixed-g2.mjs';

const FP_BYTES = 32;
const cat = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const leFp = (value) => {
  let current = mod(BigInt(value));
  const out = new Uint8Array(FP_BYTES);
  for (let index = 0; index < FP_BYTES; index += 1) { out[index] = Number(current & 0xffn); current >>= 8n; }
  return out;
};
const fp2Bytes = (value) => cat(leFp(value.c0), leFp(value.c1));
const sha256d = (bytes) => {
  const once = createHash('sha256').update(bytes).digest();
  return Uint8Array.from(createHash('sha256').update(once).digest());
};

const xOnlyEvents = () => {
  const xonly = xOnlyFixedLineEvents().events;
  const fixed = fixedLineEvents();
  if (xonly.length !== fixed.length) throw new Error('x/slope event count differs from fixed table');
  return xonly;
};
const recordBytes = (event) => cat(fp2Bytes(event.gamma.slope), fp2Bytes(event.delta.slope));
const seedBytes = (state) => cat(fp2Bytes(state.gamma.x), fp2Bytes(state.delta.x));

export const xOnlyFixedLineWindow = (lo, hi) => {
  xOnlyWindowFor(lo, hi);
  const state = xOnlyStateBeforeStep(lo);
  const events = xOnlyEvents().filter((event) => event.step >= lo && event.step < hi);
  const bytes = cat(seedBytes(state), ...events.map(recordBytes));
  const doubles = events.filter((event) => event.op === 'dl').length;
  const adds = events.filter((event) => event.op === 'al').length;
  if (events.length !== doubles + adds || events.some((event) => recordBytes(event).length !== XONLY_RECORD_BYTES)) {
    throw new Error(`invalid x/slope fixed-G2 table window [${lo}, ${hi})`);
  }
  return {
    lo,
    hi,
    events,
    bytes,
    seedBytes: XONLY_SEED_BYTES,
    digest: sha256d(bytes),
    digestHex: Buffer.from(sha256d(bytes)).toString('hex'),
  };
};

export const assertXOnlyFixedLineTable = () => {
  let doubles = 0;
  let adds = 0;
  let bytes = 0;
  for (const [lo, hi] of XONLY_WINDOWS) {
    xOnlyWindowFor(lo, hi);
    const table = xOnlyFixedLineWindow(lo, hi);
    const tableDoubles = table.events.filter((event) => event.op === 'dl').length;
    const tableAdds = table.events.filter((event) => event.op === 'al').length;
    doubles += tableDoubles;
    adds += tableAdds;
    bytes += table.bytes.length;
    if (table.bytes.length !== XONLY_SEED_BYTES + XONLY_RECORD_BYTES * table.events.length) {
      throw new Error(`x/slope table [${lo}, ${hi}) has inconsistent length`);
    }
  }
  // Every Miller step in [1,64) contributes one fixed double; ~21 fixed adds.
  if (doubles !== 63 || adds !== 21) {
    throw new Error(`unexpected x/slope table census ${JSON.stringify({ doubles, adds, bytes, windows: XONLY_WINDOWS })}`);
  }
  return { doubles, adds, bytes };
};
