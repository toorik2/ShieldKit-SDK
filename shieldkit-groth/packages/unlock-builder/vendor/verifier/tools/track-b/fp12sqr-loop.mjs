import { repoPath as vcRepoPath } from '#repo-paths';
// Track B milestone: a HAND-WRITTEN looped real-field-op verifier.
// Reuses fp12.cash's verbatim OP_DEFINE'd tower (correct field math) and hand-writes
// only the loop: f = fp12Sqr(f), N times, with the counter on the altstack. Because the
// frame IS fp12Sqr's input/output (12 in → 12 out), the function consumes old-f and
// leaves new-f in place — no frame swap needed. Gated vs noble f^(2^N). This proves the
// reuse-tower + hand-loop path on a REAL expensive field op (the core of shared Miller).
import { execFileSync } from 'node:child_process';
import { hexToBin } from '../../node_modules/@bitauth/libauth/build/index.js';
import { bytecodeToScript, scriptToBytecode } from '../../vendor/cashc-resched/packages/utils/dist/index.js';
import { push, measure, O } from './asm-measure.mjs';
import { splitmix64, randFp } from '../../build/singleton/bn254/_harness.mjs';
import { pathToFileURL } from 'node:url';

const { bn254 } = await import(pathToFileURL(vcRepoPath('node_modules/@noble/curves/esm/bn254.js')).href);
const Fp12 = bn254.fields.Fp12;
const f12 = (x) => [x.c0.c0.c0, x.c0.c0.c1, x.c0.c1.c0, x.c0.c1.c1, x.c0.c2.c0, x.c0.c2.c1,
                    x.c1.c0.c0, x.c1.c0.c1, x.c1.c1.c0, x.c1.c1.c1, x.c1.c2.c0, x.c1.c2.c1];

const CLI = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');
const FP12 = vcRepoPath('build/singleton/bn254/fp12.cash');

// 1. compile fp12.cash, parse, extract the OP_DEFINE table + fp12Sqr's id
const bc = hexToBin(execFileSync('node', [CLI, FP12, '-h'], { encoding: 'utf8' }).trim());
const script = bytecodeToScript(bc);
let lastDef = -1;
for (let i = 0; i < script.length; i++) if (script[i] === 0x89) lastDef = i;       // OP_DEFINE
const table = script.slice(0, lastDef + 1);
const spend = script.slice(lastDef + 1);
const invokes = []; for (let i = 0; i < spend.length; i++) if (spend[i] === 0x8a) invokes.push(i); // OP_INVOKE
// spend calls fp12Mul (1st), fp12Sqr (2nd), fp12Conj (3rd) at top level
const idElem = spend[invokes[1] - 1];
if (typeof idElem !== 'number' || idElem < 0x51 || idElem > 0x60) throw new Error('fp12Sqr id not OP_1..16: ' + idElem);
const fp12SqrId = idElem - 0x50;
const tableBc = scriptToBytecode(table);
console.log(`extracted: ${invokes.length} top-level invokes in spend; fp12Sqr id = ${fp12SqrId}; table ${tableBc.length}B`);

// 2. reference: f and f^(2^N)
const rng = splitmix64(0x66734c6fn);
const a = Fp12.fromBigTwelve(Array.from({ length: 12 }, () => randFp(rng)));
const N = 10;
let cur = a; for (let k = 0; k < N; k++) cur = Fp12.sqr(cur);
const fIn = f12(a), expected = f12(cur);

// 3. emit the hand loop (counter on altstack; f stays on main, squared in place)
function gen(exp) {
  const loop = [];
  const e = (...b) => b.flat(Infinity).forEach((x) => loop.push(x));
  for (let i = 11; i >= 0; i--) e(push(fIn[i]));          // push f: f11..f0 → f0 on top (fp12Sqr wants A0 on top)
  e(push(0), O.OP_TOALTSTACK);                            // counter = 0 → altstack
  e(O.OP_BEGIN);
  e(push(fp12SqrId), O.OP_INVOKE);                        // f = fp12Sqr(f): consumes [A11..A0](A0 top), leaves [C0..C11](C11 top)
  for (let i = 1; i <= 11; i++) e(push(i), O.OP_ROLL);    // reverse 12: [C0..C11](C11 top) → [C11..C0](C0 top) — restores A0-on-top for next call
  e(O.OP_FROMALTSTACK, push(1), O.OP_ADD, O.OP_DUP, O.OP_TOALTSTACK, push(N), O.OP_GREATERTHANOREQUAL); // c+1; exit when c+1>=N
  e(O.OP_UNTIL);
  e(O.OP_FROMALTSTACK, O.OP_DROP);                        // drop the final counter
  for (let i = 0; i < 12; i++) e(push(exp[i]), O.OP_NUMEQUAL, O.OP_VERIFY); // verify f == f^(2^N)
  e(O.OP_1);
  return Uint8Array.from([...tableBc, ...loop]);
}

const good = measure(gen(expected));
const bad = measure(gen(expected.map((v, i) => (i === 0 ? (v + 1n) % bn254.fields.Fp.ORDER : v))));
console.log(`HAND fp12Sqr-loop (N=${N}):`, JSON.stringify(good));
console.log('  per-iter op-cost ~', Math.round(good.opCost / N).toLocaleString(), '| bytes', good.bytes);
console.log('  BAD (wrong f^(2^N)) accepted =', bad.accepted, '(must be false)');
console.log('  GATE =', good.accepted === true && bad.accepted === false ? 'GREEN' : 'RED');
