// Rehost the shared S-Z generator against PairFold's complete mixed
// transcript. This keeps the common BCH emitter authoritative while ensuring
// its genesis hash, witnesses, quotient, and terminal use one construction.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const shared = (name) => new URL(`../../../../build/chunked/pairing/${name}`, import.meta.url).href;
const sourcePath = new URL('../../../../build/chunked/pairing/gen_miller_sz.mjs', import.meta.url);
const mixedMath = new URL('./mixed-szmath.mjs', import.meta.url).href;
const libauth = pathToFileURL(require.resolve('@bitauth/libauth')).href;
let source = readFileSync(sourcePath, 'utf8');
for (const [from, to] of [
  ['./_szmath.mjs', mixedMath],
  ['./_millermath.mjs', shared('_millermath.mjs')],
  ['@bitauth/libauth', libauth],
]) source = source.replaceAll(`'${from}'`, JSON.stringify(to));
const generated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

export const CLOSE_IN = generated.CLOSE_IN;
export const CLOSE_IN_C = generated.CLOSE_IN_C;
export const STATE = generated.STATE;
export const ccffDigest = generated.ccffDigest;
export const closeOutLimbs = generated.closeOutLimbs;
export const closeOutLimbsC = generated.closeOutLimbsC;
export const closePushedArgs = generated.closePushedArgs;
export const closePushedArgsC = generated.closePushedArgsC;
export const closeState = generated.closeState;
export const closeStateC = generated.closeStateC;
export const committedIn = generated.committedIn;
export const debakeParams = generated.debakeParams;
export const debakeVals = generated.debakeVals;
export const genChunk = generated.genChunk;
export const genCloseChunk = generated.genCloseChunk;
export const outLimbs = generated.outLimbs;
export const pushedArgs = generated.pushedArgs;
export const stepCount = generated.stepCount;
