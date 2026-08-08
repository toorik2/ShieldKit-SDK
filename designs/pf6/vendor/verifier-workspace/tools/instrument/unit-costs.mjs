import { repoPath as vcRepoPath } from '#repo-paths';
// tools/instrument/unit-costs.mjs
// ---------------------------------------------------------------------------
// DIFFERENTIAL micro-measurement of per-FUNCTION op-cost for the BN254 tower.
// For each target we compile/evaluate the self-feeding micro-contract at two
// loop counts (K and K2) in BOTH 'call' and 'empty' modes on the loosened BCH
// 2026 VM, then:
//     callMarg  = (cost_call(K2)  - cost_call(K))  / (K2 - K)  // call + return-bind
//     emptyMarg = (cost_empty(K2) - cost_empty(K)) / (K2 - K)  // pure loop control
//     UNIT      = callMarg - emptyMarg                          // target call inc.
//                                                               // arg-push + invoke
//                                                               // + return-binding
// Same decomposition for arith / push / base(=instr*100). The loop scaffolding,
// state declarations and constructor marshalling are identical between K and K2
// (the bound is a compile-time constant) so they cancel exactly in the delta.
// 'empty' subtracts ONLY the loop-control overhead (i<N, i++, branch) so the unit
// RETAINS the full per-call-site marshalling that also runs in miller4. (An earlier
// 'glue' baseline that reproduced the return-binding cancelled real per-call-site
// base/push and under-counted instr by ~2x; validated against the measured split.)
//
// Output: per-function unit op-cost with arith/base/push split, written to
// out/unit-costs.json and printed as a table. Run: node tools/instrument/unit-costs.mjs
// ---------------------------------------------------------------------------
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { genContract } from './gen.mjs';
import { TARGETS, TARGET_ORDER, P } from './funcs.mjs';

const LIBAUTH = pathToFileURL(vcRepoPath('node_modules/@bitauth/libauth/build/index.js')).href;
const {
  hexToBin, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026,
  createTestAuthenticationProgramBch, ConsensusBch2025,
  ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

const CASHC = vcRepoPath('vendor/cashc-resched/packages/cashc/dist/cashc-cli.js');

const HUGE = Number.MAX_SAFE_INTEGER;
const loosened = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
  maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE,
  maximumOperationCount: HUGE,
};
const looseVm = createVirtualMachine(createInstructionSetBch2026(false, {
  consensus: loosened, ripemd160, secp256k1, sha1, sha256,
}));

const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};

const splitmix64 = (seed) => {
  let s = BigInt.asUintN(64, seed);
  return () => {
    s = BigInt.asUintN(64, s + 0x9e3779b97f4a7c15n);
    let z = s;
    z = BigInt.asUintN(64, (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n);
    z = BigInt.asUintN(64, (z ^ (z >> 27n)) * 0x94d049bb133111ebn);
    return z ^ (z >> 31n);
  };
};
const randFp = (rng) => { let x = 0n; for (let i = 0; i < 4; i++) x = (x << 64n) | rng(); return x % P; };

const tmp = mkdtempSync(join(tmpdir(), 'instr-'));

function compile(name, loops, mode, pad) {
  const src = genContract(name, loops, mode, pad);
  const f = join(tmp, `${name}_${mode}_${loops}_p${pad}.cash`);
  writeFileSync(f, src);
  const hex = execFileSync('node', [CASHC, f, '-h'], { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 }).trim();
  return hexToBin(hex);
}

// SURROUNDING live-local depth at each Miller-level call site in miller4, ON TOP
// of the function's own args, so the differential reproduces the real per-call
// arg-marshalling base (deeper stack -> deeper OP_PICKs -> more base; validated:
// +~457 instr per +8 surrounding locals for `line`). millerSingle keeps f (12) +
// R (6) = 18 live across its loop body, so fp12Sqr/line/pointDouble/pointAdd/psi/
// fp2Neg are all called with ~18 surrounding locals. The 3 combine fp12Mul run in
// spend() over the 4 results a..d (48 ints live early) -> ~36 surrounding mid.
// Sub-tower functions (mulFp..fp6Mul) get pad 0: their cost is consumed INSIDE a
// parent's unit (already measured nested), not attributed directly, so their
// natural micro depth is correct.
const SURROUND = {
  fp12Sqr: 18, line: 18, pointDouble: 18, pointAdd: 18, psi: 18,
  fp12Mul: 36,
};
const padFor = (name) => SURROUND[name] ?? 0;

function evalSeeds(template, seeds) {
  const unlocking = Uint8Array.from(seeds.slice().reverse().flatMap((a) => [...pushInt(a)]));
  const program = createTestAuthenticationProgramBch({
    lockingBytecode: template, unlockingBytecode: unlocking, valueSatoshis: 1000n,
  });
  const state = looseVm.evaluate(program);
  const top = state.stack[state.stack.length - 1];
  const accepted = state.error === undefined && state.stack.length === 1
    && top !== undefined && top.length === 1 && top[0] === 1;
  const m = state.metrics;
  return {
    accepted, error: state.error,
    opCost: m.operationCost,
    arith: m.arithmeticCost ?? 0,
    push: m.stackPushedBytes ?? 0,
    instr: m.evaluatedInstructionCount ?? 0,
  };
}

// loop-count plan per cost tier: keep K2 small (compile-time constant bound; cost
// scales with loops only at eval). Heavy fns -> small counts to bound runtime.
function plan(name) {
  const inN = TARGETS[name].inN;
  // crude tiering by fan-in / known heaviness
  if (['fp12Mul', 'fp12Sqr'].includes(name)) return { K: 2, K2: 6 };
  if (['mul034', 'line', 'pointDouble', 'pointAdd', 'fp6Mul'].includes(name)) return { K: 4, K2: 12 };
  if (['fp6Add', 'fp6Sub', 'fp6MulByV', 'psi', 'fp2Mul', 'fp2Sqr', 'fp2MulXi'].includes(name)) return { K: 8, K2: 40 };
  return { K: 20, K2: 120 }; // mulFp/addFp/subFp
}

function measure(name) {
  const t = TARGETS[name];
  const W = Math.max(t.inN, t.outN, 4);
  const rng = splitmix64(0xB0254n + BigInt([...name].reduce((a, c) => a + c.charCodeAt(0), 0)));
  const seeds = Array.from({ length: W }, () => randFp(rng));
  const { K, K2 } = plan(name);
  const dK = K2 - K;

  const pad = padFor(name);
  const tplCallK = compile(name, K, 'call', pad);
  const tplCallK2 = compile(name, K2, 'call', pad);
  const tplEmptyK = compile(name, K, 'empty', pad);
  const tplEmptyK2 = compile(name, K2, 'empty', pad);

  const cK = evalSeeds(tplCallK, seeds);
  const cK2 = evalSeeds(tplCallK2, seeds);
  const eK = evalSeeds(tplEmptyK, seeds);
  const eK2 = evalSeeds(tplEmptyK2, seeds);

  for (const [lbl, r] of [['callK', cK], ['callK2', cK2], ['emptyK', eK], ['emptyK2', eK2]]) {
    if (!r.accepted) throw new Error(`${name} ${lbl} not accepted: ${JSON.stringify(r.error)}`);
  }

  const marg = (a, b, key) => (b[key] - a[key]) / dK;
  const unit = (key) => marg(cK, cK2, key) - marg(eK, eK2, key);

  const u = {
    opCost: unit('opCost'),
    arith: unit('arith'),
    push: unit('push'),
    base: unit('instr') * 100,
    instr: unit('instr'),
  };
  return { name, K, K2, pad, ...u,
    callMargOp: marg(cK, cK2, 'opCost'), emptyMargOp: marg(eK, eK2, 'opCost') };
}

const rows = [];
for (const name of TARGET_ORDER) {
  process.stderr.write(`measuring ${name} ...`);
  const r = measure(name);
  rows.push(r);
  process.stderr.write(` op=${Math.round(r.opCost)}\n`);
}

writeFileSync(vcRepoPath('out/unit-costs.json'),
  JSON.stringify(rows, null, 2));

const fmt = (n) => Math.round(n).toLocaleString();
console.log('\n=== PER-FUNCTION UNIT OP-COST (differential, loosened BCH-2026 VM) ===');
console.log('function       unit op-cost     arith        base         push      instr   (base=instr*100)');
console.log('-------------------------------------------------------------------------------------------');
for (const r of rows) {
  const pct = (x) => r.opCost > 0 ? `${(100 * x / r.opCost).toFixed(0)}%` : '-';
  console.log(
    `${r.name.padEnd(13)} ${fmt(r.opCost).padStart(11)} ` +
    `${(fmt(r.arith) + ' ' + pct(r.arith)).padStart(13)} ` +
    `${(fmt(r.base) + ' ' + pct(r.base)).padStart(13)} ` +
    `${(fmt(r.push) + ' ' + pct(r.push)).padStart(11)} ` +
    `${fmt(r.instr).padStart(7)}`
  );
}
console.log('\nwrote out/unit-costs.json');
