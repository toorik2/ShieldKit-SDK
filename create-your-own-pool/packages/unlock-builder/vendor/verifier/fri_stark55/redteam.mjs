import {
  LOGN,
  LOG_BLOWUP,
  NUM_QUERIES,
  CATEGORY,
  init,
  buildBundle,
  evaluateBundle,
  metrics,
  assertStandard,
  allAccepted,
  accepted,
  jsResult,
  cloneBytes,
  p2sh32,
  hash256,
} from './common.mjs';
import { qStarkProve } from '../fri_stark/qstark.mjs';
import { buildQStarkWitnessCapture } from '../fri_stark/build_qstark_split.mjs';
import { Asm } from '../fri_stark/asm.mjs';
import { encodeDataPush } from '../node_modules/@bitauth/libauth/build/index.js';

await init();

let crownSizeBlocked = false;

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function run(bundle, label, expectAll) {
  const states = evaluateBundle(bundle, true);
  const m = metrics(bundle, states);
  if (expectAll) {
    assert(allAccepted(states), `${label}: ${m.rows.map((r) => r.error ?? 'OK').join(' | ')}`);
    try {
      assertStandard(m);
    } catch (error) {
      // This suite is the independent soundness regression battery.  Keep it
      // runnable while the checked-in research fixture is over the hard crown
      // size cap, but make the resource failure explicit; verifier-bench still
      // fails the release on the same metrics.
      const message = error instanceof Error ? error.message : String(error);
      if (!/script bytes|serialized tx/.test(message)) throw error;
      crownSizeBlocked = true;
      console.log(`honest: VM soundness PASS; crown size gate BLOCKED (${message})`);
    }
  } else {
    assert(!allAccepted(states), `${label}: false transaction accepted on every input`);
  }
  return { states, metrics: m };
}

const honestProof = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES);
const honest = buildBundle(honestProof);
const js = jsResult(honestProof);
assert(js.ok === true, `honest JS verifier rejected: ${js.why}`);
run(honest, 'honest', true);
console.log('honest: JS ACCEPT + standard BCH VM all-input ACCEPT');

// A false Fibonacci trace: the seed transition is wrong, while all later rows
// follow Fibonacci. The prover remains protocol-shaped, so this exercises the
// AIR/DEEP/FRI soundness path rather than a malformed witness.
function falseTrace(n) {
  const a = new Array(n); const b = new Array(n);
  a[0] = 1n; b[0] = 1n; a[1] = 1n; b[1] = 3n;
  for (let i = 2; i < n; i++) { a[i] = b[i - 1]; b[i] = (a[i - 1] + b[i - 1]) % 2147483647n; }
  return { a, b };
}
const falseProof = qStarkProve(LOGN, LOG_BLOWUP, NUM_QUERIES, { trace: falseTrace(1 << LOGN) });
const falseJs = jsResult(falseProof);
assert(falseJs.ok === false, 'false AIR unexpectedly passed the JS verifier');
run(buildBundle(falseProof), 'false AIR trace', false);
console.log('false AIR trace: JS REJECT + standard BCH VM transaction REJECT');

// Shared-instance and challenge mutations. These are all witness-only changes;
// the token commitment and fixed redeem programs stay honest.
const mutations = [
  ['target', (name, value) => name === 'target' ? value + 1n : value],
  ['alpha limb', (name, value) => name === 'alpha__a0' ? value + 1n : value],
  ['zeta limb', (name, value) => name === 'zetaX__a0' ? value + 1n : value],
  ['gamma limb', (name, value) => name === 'gamma0__a0' ? value + 1n : value],
  ['final constant limb', (name, value) => name === 'finalConst__a0' ? value + 1n : value],
  ['inverse limb', (name, value) => name === 'invVz__a0' ? value + 1n : value],
  ['query half', (name, value) => name === 'q0_half0' ? value + 1n : value],
  ['query FRI value', (name, value) => name === 'q0_fa0__a0' ? value + 1n : value],
  ['query Merkle direction', (name, value) => name === 'q0_fp0_dir0' ? value + 1n : value],
];
for (const [label, patch] of mutations) {
  run(buildBundle(honestProof, patch), `mutation: ${label}`, false);
  console.log(`mutation ${label}: REJECT`);
}

// Mutate an absorbed root byte. This is deliberately a binary patch and tests
// the H token-commitment provenance rather than arithmetic.
run(buildBundle(honestProof, (name, value) => {
  if (name !== 'traceRoot') return value;
  const out = cloneBytes(value); out[0] ^= 1; return out;
}), 'trace-root mutation', false);
console.log('trace-root mutation: REJECT');

// P2SH hash binding: changing one redeem byte without changing its funding
// script must fail before the verifier body runs.
const redeemTamper = buildBundle(honestProof);
redeemTamper.unlockings[1] = cloneBytes(redeemTamper.unlockings[1]);
redeemTamper.unlockings[1][redeemTamper.unlockings[1].length - 1] ^= 1;
run(redeemTamper, 'P2SH redeem mutation', false);
console.log('P2SH redeem mutation: REJECT');

// Coverage binding: swapping two follower witnesses preserves the P2SH redeem
// hash but assigns a query slice to the wrong input position.
const swapped = buildBundle(honestProof);
[swapped.unlockings[1], swapped.unlockings[2]] = [swapped.unlockings[2], swapped.unlockings[1]];
run(swapped, 'follower position swap', false);
console.log('follower position swap: REJECT');

// Leader provenance: replace input 0 with a different P2SH32 redeem. Followers
// pin the genuine deployed leader hash and must reject the transaction.
const bypass = buildBundle(honestProof);
const bypassRedeem = Uint8Array.from([0x51]);
bypass.sourceOutputs[0] = { ...bypass.sourceOutputs[0], lockingBytecode: p2sh32(bypassRedeem) };
bypass.unlockings[0] = encodeDataPush(bypassRedeem);
run(bypass, 'leader bypass', false);
console.log('leader bypass: REJECT');

// Token/category and H output substitution are both state-provenance failures.
const foreignCategory = buildBundle(honestProof);
foreignCategory.sourceOutputs[3] = {
  ...foreignCategory.sourceOutputs[3],
  token: { ...foreignCategory.sourceOutputs[3].token, category: hash256(CATEGORY) },
};
run(foreignCategory, 'foreign category', false);
console.log('foreign category: REJECT');

const foreignH = buildBundle(honestProof);
foreignH.transaction.outputs[0] = {
  ...foreignH.transaction.outputs[0],
  token: { ...foreignH.transaction.outputs[0].token, nft: { capability: 'none', commitment: hash256(foreignH.H) } },
};
run(foreignH, 'foreign H commitment', false);
console.log('foreign H commitment: REJECT');

// Deterministic targeted sweep over soundness-critical numeric witness names.
const captured = buildQStarkWitnessCapture(honestProof);
const sweepNames = captured.names.filter((name) =>
  name === 'target' || name === 'alpha__a0' || name === 'zetaY__b0' ||
  name === 'gamma1__a1' || name === 'beta0__b1' ||
  name === 'q1_faIdx0' || name === 'q2_half1' || name === 'q3_fp2_dir1' ||
  name === 'q4_finv2' || name === 'invXmXL__a0',
);
let sweepRejects = 0;
for (const name of sweepNames) {
  const result = run(buildBundle(honestProof, (candidate, value) => {
    if (candidate !== name) return value;
    // Direction bits are consumed as booleans by OP_IF; flip 0↔1 rather than
    // using 2, which is truthy and is intentionally equivalent to 1 there.
    return name.includes('_dir') ? (value === 0n ? 1n : 0n) : value + 1n;
  }), `sweep ${name}`, false);
  if (result.states.some((state) => !accepted(state))) sweepRejects++;
}
assert(sweepRejects === sweepNames.length, `witness sweep ${sweepRejects}/${sweepNames.length}`);
console.log(`witness sweep: ${sweepRejects}/${sweepNames.length} REJECT`);

if (crownSizeBlocked) {
  console.error('FRI-STARK55 REDTEAM BLOCKED: soundness suite clean, but the strict crown size gate failed');
  process.exitCode = 1;
} else {
  console.log('FRI-STARK55 REDTEAM PASS: no false transaction accepted');
}
