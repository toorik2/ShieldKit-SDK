// Rehost the shared K=13 generator with the lane-local normalized S-Z math.
// The generator source is imported byte-for-byte except for its math import;
// this keeps the tested shared emitter authoritative while isolating the C7
// quotient trajectory to this lane.
import { readFileSync } from 'node:fs';

const shared = (name) => new URL(`../../../../build/chunked/pairing/${name}`, import.meta.url).href;
const sourcePath = new URL('../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs', import.meta.url);
const normalizedMath = new URL('./normalized-szmath.mjs', import.meta.url).href;
let source = readFileSync(sourcePath, 'utf8');
for (const [from, to] of [
  ['./_szmath.mjs', normalizedMath],
  ['./_millermath.mjs', shared('_millermath.mjs')],
  ['./t3_shared3_9k7.mjs', shared('t3_shared3_9k7.mjs')],
  ['./_t4kp_specialize_local.mjs', shared('_t4kp_specialize_local.mjs')],
]) source = source.replaceAll(`'${from}'`, JSON.stringify(to));
const generated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

export const CDNW = generated.CDNW;
export const CDW = generated.CDW;
export const CDWIDTH = generated.CDWIDTH;
export const CD_ADD_B = generated.CD_ADD_B;
export const CD_B = generated.CD_B;
export const CD_MAND_B = generated.CD_MAND_B;
export const DERIVE_MODE = generated.DERIVE_MODE;
export const DYN_PACK = generated.DYN_PACK;
export const MODE_PACK = generated.MODE_PACK;
export const MODE_SCHEDULE = generated.MODE_SCHEDULE;
export const NW = generated.NW;
export const SGB = generated.SGB;
export const SHARED = generated.SHARED;
export const STATE_BYTES = generated.STATE_BYTES;
export const STATE_LIMBS = generated.STATE_LIMBS;
export const W = generated.W;
export const WD_B = generated.WD_B;
export const cdatBytesForStep = generated.cdatBytesForStep;
export const cdatStep = generated.cdatStep;
export const chunkIdxOf = generated.chunkIdxOf;
export const dataBlob = generated.dataBlob;
export const genChunkGB = generated.genChunkGB;
export const hasAddStep = generated.hasAddStep;
export const inBlobGB = generated.inBlobGB;
export const outBlobGB = generated.outBlobGB;
export const perStep = generated.perStep;
export const stateBlob = generated.stateBlob;
export const stateVal = generated.stateVal;
export const stateW = generated.stateW;
export const stepCount = generated.stepCount;
export const wdatBytesForChunk = generated.wdatBytesForChunk;
export const wdatBytesForMode = generated.wdatBytesForMode;
export const wdatStep = generated.wdatStep;
