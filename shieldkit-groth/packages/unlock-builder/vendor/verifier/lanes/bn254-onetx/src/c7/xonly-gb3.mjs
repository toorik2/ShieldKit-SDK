// Rehost the shared K=13 generator with the x/slope S-Z quotient.
import { readFileSync } from 'node:fs';

const shared = (name) => new URL(`../../../../build/chunked/pairing/${name}`, import.meta.url).href;
const sourcePath = new URL('../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs', import.meta.url);
const xonlyMath = new URL('./xonly-szmath.mjs', import.meta.url).href;
let source = readFileSync(sourcePath, 'utf8');
for (const [from, to] of [
  ['./_szmath.mjs', xonlyMath],
  ['./_millermath.mjs', shared('_millermath.mjs')],
  ['./t3_shared3_9k7.mjs', shared('t3_shared3_9k7.mjs')],
  ['./_t4kp_specialize_local.mjs', shared('_t4kp_specialize_local.mjs')],
]) source = source.replaceAll(`'${from}'`, JSON.stringify(to));
const generated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

export const { CDNW, CDW, CDWIDTH, CD_ADD_B, CD_B, CD_MAND_B, DERIVE_MODE, DYN_PACK, MODE_PACK,
  MODE_SCHEDULE, NW, SGB, SHARED, STATE_BYTES, STATE_LIMBS, W, WD_B, cdatBytesForStep, cdatStep,
  chunkIdxOf, dataBlob, genChunkGB, hasAddStep, inBlobGB, outBlobGB, perStep, stateBlob, stateVal,
  stateW, stepCount, wdatBytesForChunk, wdatBytesForMode, wdatStep } = generated;
