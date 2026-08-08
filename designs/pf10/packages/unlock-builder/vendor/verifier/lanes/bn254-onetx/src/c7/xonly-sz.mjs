// Rehost the S-Z stage generator with the x/slope quotient math.
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const shared = (name) => new URL(`../../../../build/chunked/pairing/${name}`, import.meta.url).href;
const sourcePath = new URL('../../../../build/chunked/pairing/gen_miller_sz.mjs', import.meta.url);
const xonlyMath = new URL('./xonly-szmath.mjs', import.meta.url).href;
const libauth = pathToFileURL(require.resolve('@bitauth/libauth')).href;
let source = readFileSync(sourcePath, 'utf8');
for (const [from, to] of [
  ['./_szmath.mjs', xonlyMath],
  ['./_millermath.mjs', shared('_millermath.mjs')],
  ['@bitauth/libauth', libauth],
]) source = source.replaceAll(`'${from}'`, JSON.stringify(to));
const generated = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

export const { CLOSE_IN, CLOSE_IN_C, STATE, ccffDigest, closeOutLimbs, closeOutLimbsC, closePushedArgs,
  closePushedArgsC, closeState, closeStateC, committedIn, debakeParams, debakeVals, genChunk,
  genCloseChunk, outLimbs, pushedArgs, stepCount } = generated;
