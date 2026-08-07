// Opt-in research generator for the seven-input projected-state route.
// Five K=13 executors carry only the dynamic Miller state; immutable
// statement/VK context is read from the byte-exact, genesis-authenticated
// projection context.  The terminal retains the complete BQ relation: moving
// its Horner loop into the executors was rejected by real density measurement.
// This module is never selected by a candidate build profile.
import { projectedExecutorSource, projectedStateLayout } from './measure-projected-state.mjs';

const base = await import(process.env.C7_ZBITS_GB3 ?? '../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const cat = (...parts) => {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.length; }
  return out;
};
const fieldBytes = (value, width, raw = false) => {
  let current = raw ? BigInt(value) : ((BigInt(value) % P) + P) % P;
  const out = new Uint8Array(width);
  for (let i = 0; i < width; i++) { out[i] = Number(current & 0xffn); current >>= 8n; }
  return out;
};
const valuesAt = (step) => Object.fromEntries(base.SGB.map((name, index) => [name, BigInt(base.stateVal(step)[index])]));
const dynamicBytesAt = (step) => {
  const values = valuesAt(step);
  return cat(...projectedStateLayout.dynamic.map((name) => fieldBytes(values[name], name === 'hInt' ? 40 : 32, name === 'hInt')));
};

export const DYNAMIC_STATE_BYTES = projectedStateLayout.dynamicBytes;
export const TERMINAL_SEAM_BYTES = DYNAMIC_STATE_BYTES;
export const STATE_BYTES = DYNAMIC_STATE_BYTES;
export const stateW = base.stateW;
export const MODE_SCHEDULE = base.MODE_SCHEDULE;
export const cdatStep = base.cdatStep;
export const wdatStep = base.wdatStep;
export const stateVal = base.stateVal;
export const SHARED = base.SHARED;

export const projectionContext = (step = 1) => {
  const values = valuesAt(step);
  return cat(...projectedStateLayout.context.map((name) => fieldBytes(values[name], 32)));
};
export const inBlobGB = (lo, hi) => cat(
  dynamicBytesAt(lo),
  base.inBlobGB(lo, hi).slice(base.STATE_BYTES),
);
export const outBlobGB = (hi) => dynamicBytesAt(hi);
export const genChunkGB = (lo, hi, cfg = {}) => {
  if (!cfg.forward) throw new Error('projected-state generator requires authenticated forward edges');
  return projectedExecutorSource({ lo, hi, genesisInputIndex: 5 });
};
