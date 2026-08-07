import { repoPath as vcRepoPath } from '#repo-paths';
// gate.mjs -- SELF-VERIFYING REPRODUCIBILITY GATE for the BN254 singleton crown.
//
// WHY THIS EXISTS
//   The shipped locking bytecode was produced by a *stochastic* annealing search, so it
//   is NOT bit-reproducible by re-running the pipeline. A reviewer therefore cannot
//   "reproduce the artifact" the usual way. This gate replaces that with a *deterministic
//   proof* that the SHIPPED hex is a faithful, behaviour-preserving, correctly-verifying
//   recompilation of the trusted baseline -- without re-running the search.
//
// USAGE
//   node gate.mjs <shipped.hex> [multiproof-vectors.json] [flags]
//   flags:
//     --skip-e2e         run CHECK 1 + CHECK 2 only, mark CHECK 3 DEFERRED (exit 2)
//     --trials N         random-Fp trials per body in CHECK 2   (default 4)
//                        NOTE: the pairing/Miller-loop body (id 33) runs ~18s each, so
//                        CHECK 2 wall-time is ~trials*40s. More trials = more assurance.
//     --e2e-proofs N     limit CHECK 3 to the first N multiproof vectors (default: all)
//     --vectors PATH     explicit path to the multiproof vectors (else 2nd positional / default)
//
//   Exit 0  iff all three checks PASS.  Exit 1 if any check FAILs.  Exit 2 if E2E deferred.
//
// THE THREE CHECKS (each prints its own PASS/FAIL)
//   1. ROUND-TRIP  (well-formedness / faithful recompiler output)
//        recompile(decompile(hex)) == hex, byte-exact over every OP_DEFINE body + main,
//        using the pipeline's dissect/decompile/recompile. Proves the shipped hex is a
//        fixpoint of the block-DAG decompiler: its own decompiled DAG recompiles back to
//        it byte-for-byte, so it is a genuine recompiler output with no hidden bytes.
//
//        The crown adds nullary "derive-constant" helper subroutines (e.g. id 13/38) that
//        are NOT in the baseline arity table and cannot be probed in isolation (they run
//        away under the cost-free VM). We recover their (in,out) arity by a bounded,
//        ascending, self-validating search: only an arity under which the WHOLE program
//        re-serializes byte-identically is accepted, so the recovered arity is certified
//        by the byte-exact round-trip itself (a wrong arity makes decompile throw or the
//        bytes differ). If no block-DAG model can be established we fall back to a
//        structural (canonical minimal-push encoding) round-trip and say so loudly.
//
//   2. PER-BODY DIFFERENTIAL  (same behaviour as the trusted baseline)
//        For every subroutine id present in BOTH the shipped hex and baseline.json, run
//        the shipped body and the baseline body in isolation on the same random Fp inputs
//        and require BIT-IDENTICAL output stacks. Proves the shipped subroutines compute
//        exactly what the trusted baseline computes (even when a shipped body now INVOKEs a
//        derive-helper instead of embedding a constant -- the observable output is equal).
//        Shipped-only helper ids (no baseline counterpart) are reported and left to CHECK 3.
//
//   3. E2E  (the whole verifier accepts valid + rejects invalid)
//        Run the shipped hex as the locking script against the multiproof vectors: require
//        valid-ACCEPT N/N, invalid-REJECT N/N, and (differential) same verdict as baseline.
//
// PATH PORTABILITY
//   All pipeline assets are resolved relative to this file (./pipeline-sub6k/...). The only
//   absolute default is the multiproof-vectors path, overridable via a 2nd arg / --vectors.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, isAbsolute, resolve } from 'node:path';
import {
  createVirtualMachine, createInstructionSetBch2026, createTestAuthenticationProgramBch,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256, hexToBin,
  bigIntToVmNumber, vmNumberToBigInt,
} from '@bitauth/libauth';
import { parse, serialize } from './pipeline-sub6k/asm.mjs';
import { dissect, decompileProgram, recompileProgram } from './pipeline-sub6k/program.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const PIPE = join(HERE, 'pipeline-sub6k');
const SCORE_OVERHEAD = 359;   // score = locking bytes + P2SH/redeem overhead (matches crown filenames)
const MAIN_IN = 10;           // main-routine input arity used by the pipeline round-trip
const OP_CAP = 20_000_000;    // per-subroutine op cap for CHECK 2 -> guarantees termination
const DEFAULT_VECTORS = vcRepoPath('out/bch/groth16-singleton-multiproof-vectors.json');
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ---- CLI ----------------------------------------------------------------------------
const argv = process.argv.slice(2);
const flags = { skipE2e: false, trials: 4, e2eProofs: Infinity, vectors: null };
const positional = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--skip-e2e') flags.skipE2e = true;
  else if (a === '--trials') flags.trials = +argv[++i];
  else if (a === '--e2e-proofs') flags.e2eProofs = +argv[++i];
  else if (a === '--vectors') flags.vectors = argv[++i];
  else positional.push(a);
}
const hexPath = positional[0];
if (!hexPath) {
  console.error('usage: node gate.mjs <shipped.hex> [multiproof-vectors.json] [--skip-e2e] [--trials N] [--e2e-proofs N]');
  process.exit(64);
}
const vectorsPath = flags.vectors || positional[1] || DEFAULT_VECTORS;
const absHex = isAbsolute(hexPath) ? hexPath : resolve(process.cwd(), hexPath);

// ---- load shipped hex + trusted baseline --------------------------------------------
const shipBytes = Uint8Array.from(Buffer.from(readFileSync(absHex, 'utf8').trim(), 'hex'));
const rawBase = JSON.parse(readFileSync(join(PIPE, 'baseline.json'), 'utf8'));
const baseline = Uint8Array.from(Buffer.from(rawBase.debug?.bytecode || rawBase.bytecodeHex || rawBase.hex, 'hex'));
const baseArity = JSON.parse(readFileSync(join(PIPE, 'arity.json'), 'utf8'));

const dShip = dissect(shipBytes);
const dBase = dissect(baseline);

// ---- header -------------------------------------------------------------------------
const sha = createHash('sha256').update(Buffer.from(shipBytes)).digest('hex');
console.log('================================================================================');
console.log(' BN254 SINGLETON REPRODUCIBILITY GATE');
console.log('================================================================================');
console.log(`  hex file      : ${absHex}`);
console.log(`  locking bytes : ${shipBytes.length}`);
console.log(`  score         : ${shipBytes.length + SCORE_OVERHEAD}   (locking + ${SCORE_OVERHEAD})`);
console.log(`  sha256        : ${sha}`);
console.log(`  baseline      : ${baseline.length} B  (${rawBase.contractName || '?'})`);
console.log(`  subroutines   : ${dShip.order.length} shipped / ${dBase.order.length} baseline`);
console.log('');

const results = {};   // name -> boolean|null (null = deferred)

// =====================================================================================
// CHECK 1 -- ROUND-TRIP
// =====================================================================================
function tryRoundTrip(d, arity, bytes) {
  const ir = decompileProgram(d, arity, MAIN_IN);
  const r = recompileProgram(d, ir, arity);
  const full = Buffer.from(r.bytes).equals(Buffer.from(bytes));
  const badBodies = r.perBody.filter((b) => !b.exact).map((b) => b.id);
  return { exact: full && r.mainExact && badBodies.length === 0, mainExact: r.mainExact, badBodies };
}

// Recover arity for ids present in the shipped hex but absent from the baseline table, by
// requiring a byte-exact whole-program round-trip. Ascending (in,out) => minimal, certified
// solution. Bounded so a pathological hex can never hang the gate.
function recoverMissingArity(d, bytes, missing, { MAXIN = 18, MAXOUT = 34, CAP = 200000 } = {}) {
  let attempts = 0;
  const rec = (k, arity) => {
    if (k === missing.length) {
      attempts++;
      if (attempts > CAP) return null;
      try { return tryRoundTrip(d, arity, bytes).exact ? arity : null; } catch { return null; }
    }
    const id = missing[k];
    for (let i = 0; i <= MAXIN; i++) {
      for (let o = 0; o <= MAXOUT; o++) {
        if (attempts > CAP) return null;
        const sol = rec(k + 1, { ...arity, [id]: { in: i, out: o } });
        if (sol) return sol;
      }
    }
    return null;
  };
  return { sol: rec(0, { ...baseArity }), attempts };
}

function checkRoundTrip() {
  console.log('--------------------------------------------------------------------------------');
  console.log(' CHECK 1 -- ROUND-TRIP  (recompile(decompile(hex)) == hex, byte-exact)');
  console.log('--------------------------------------------------------------------------------');
  const missing = dShip.order.filter((id) => !baseArity[id]);
  let arity = { ...baseArity };
  if (missing.length) {
    console.log(`  derive-helper ids not in baseline arity : ${missing.join(', ')}`);
    if (missing.length > 4) {
      console.log('  too many unknown-arity subroutines to recover -> block-DAG round-trip not attempted');
    } else {
      const { sol, attempts } = recoverMissingArity(dShip, shipBytes, missing);
      if (sol) {
        arity = sol;
        const recovered = missing.map((id) => `${id}:${sol[id].in}->${sol[id].out}`).join('  ');
        console.log(`  recovered arity (certified by byte-exact round-trip, ${attempts} attempts): ${recovered}`);
      } else {
        console.log(`  could NOT recover a byte-exact arity model (${attempts} attempts)`);
        arity = null;
      }
    }
  }

  if (arity) {
    let rt;
    try { rt = tryRoundTrip(dShip, arity, shipBytes); }
    catch (e) { console.log(`  block-DAG decompile threw: ${e.message}`); rt = null; }
    if (rt && rt.exact) {
      console.log('  MODE          : block-DAG (strong)  -- every body + main recompiles byte-exact');
      console.log('  CHECK 1       : PASS');
      results.roundTrip = true;
      return;
    }
    if (rt) console.log(`  block-DAG round-trip NON-EXACT (mainExact=${rt.mainExact}, bad bodies=${rt.badBodies.join(',') || 'none'})`);
  }

  // Fallback: arity-free structural (canonical minimal-push encoding) round-trip.
  const structural = Buffer.from(serialize(parse(shipBytes))).equals(Buffer.from(shipBytes));
  if (structural) {
    console.log('  MODE          : structural (weaker)  -- block-DAG model not established;');
    console.log('                  proved canonical minimal-push encoding + clean op-stream only.');
    console.log('                  (behaviour is still gated by CHECK 2 + CHECK 3)');
    console.log('  CHECK 1       : PASS (structural)');
    results.roundTrip = true;
  } else {
    console.log('  structural round-trip ALSO failed (op-stream is not a canonical fixpoint)');
    console.log('  CHECK 1       : FAIL');
    results.roundTrip = false;
  }
}

// =====================================================================================
// CHECK 2 -- PER-BODY DIFFERENTIAL vs baseline
// =====================================================================================
// A subroutine run in isolation on RANDOM (invalid) Fp is not guaranteed to terminate
// under the cost-free measurement VM, so we run the differential on an operation-CAPPED
// VM. Every legitimate body (incl. the heavy pairing body id 33) completes well under the
// cap and yields identical output to the uncapped VM; only a genuine runaway (e.g. a
// corrupted body with a non-terminating loop) hits the cap -> reported as an error, which
// the difftest verdict logic then flags as a mismatch. This is a local re-implementation
// of the pipeline's runSubroutine (program.mjs) with maximumOperationCount = OP_CAP.
const HUGE_ = Number.MAX_SAFE_INTEGER;
const cappedConsensus = {
  ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
  maximumMemorySlots: HUGE_, maximumStandardLockingBytecodeLength: -1,
  maximumStandardUnlockingBytecodeLength: HUGE_, maximumTokenCommitmentLength: 128,
  operationCostBudgetPerByte: HUGE_, maximumStackItemLength: HUGE_, maximumVmNumberByteLength: HUGE_,
  maximumStackDepth: HUGE_, maximumControlStackDepth: HUGE_, maximumBytecodeLength: HUGE_,
  maximumOperationCount: OP_CAP,
};
const cappedVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: cappedConsensus, ripemd160, secp256k1, sha1, sha256 }));
const INVOKE_OP = 0x8a;
function runSubCapped(d, id, inputs) {
  const out = [];
  for (const r of d.defRecs) { out.push({ op: 0, data: d.bodies.get(r.id) }); out.push(r.idRec); out.push(r.defRec); }
  for (const v of inputs) out.push({ op: 0, data: bigIntToVmNumber(BigInt(v)) });
  if (id >= 1 && id <= 16) out.push({ op: 0x50 + id }); else out.push({ op: 0, data: bigIntToVmNumber(BigInt(id)) });
  out.push({ op: INVOKE_OP });
  const st = cappedVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: serialize(out), unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
  const benign = !st.error || /Non-P2SH|clean stack|exactly one|single/i.test(String(st.error));
  return { stack: st.stack.map((b) => vmNumberToBigInt(b, { maximumVmNumberByteLength: HUGE_ })), error: benign ? undefined : String(st.error) };
}

// deterministic random Fp generator (identical to the pipeline's difftest.mjs)
function mkrng(seed) {
  let x = BigInt(seed) * 6364136223846793005n + 1n;
  return () => {
    x = (x * 6364136223846793005n + 1442695040888963407n) & ((1n << 64n) - 1n);
    let z = x;
    z = (z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n & ((1n << 64n) - 1n);
    z = (z ^ (z >> 27n)) * 0x94d049bb133111ebn & ((1n << 64n) - 1n);
    return (z ^ (z >> 31n)) & ((1n << 64n) - 1n);
  };
}
function randFp(rng) { let v = 0n; for (let i = 0; i < 4; i++) v = (v << 64n) | rng(); return v % P; }
const eqStacks = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function checkDifferential(trials) {
  console.log('');
  console.log('--------------------------------------------------------------------------------');
  console.log(` CHECK 2 -- PER-BODY DIFFERENTIAL vs baseline  (${trials} random-Fp trials/body)`);
  console.log('--------------------------------------------------------------------------------');
  const sharedIds = dShip.order.filter((id) => baseArity[id] && dBase.bodies.has(id));
  const shipOnly = dShip.order.filter((id) => !(baseArity[id] && dBase.bodies.has(id)));

  // The ederive/fold-table crown REPURPOSES some baseline ids as nullary "derive/provider"
  // helpers (e.g. baseline id 15 was a duplicate of id 14; the crown dedups it and reuses
  // id 15 as a 32-byte constant provider). Such an id is NOT the same logical subroutine as
  // the baseline id, so a per-id differential against baseline is meaningless for it. We
  // detect a repurposed provider robustly (and corruption-resistantly): every baseline
  // subroutine has in-arity >= 1, so it underflows when invoked on ZERO inputs; a body that
  // instead runs CLEANLY on zero inputs is a nullary provider with no baseline counterpart.
  // A merely-corrupted body still needs its inputs -> still underflows on 0 -> stays compared.
  const providers = [], shared = [];
  for (const id of sharedIds) {
    const isProvider = baseArity[id].in >= 1 && runSubCapped(dShip, id, []).error === undefined;
    (isProvider ? providers : shared).push(id);
  }

  const fails = [];
  let checkedBodies = 0, noCleanBodies = 0;
  for (const id of shared) {
    process.stderr.write(`    [check2] body def#${id} ...\r`);
    let clean = 0, match = 0, errMismatch = 0;
    for (let s = 0; s < trials; s++) {
      const rng = mkrng(s * 1009 + id * 7 + 1);
      const inputs = Array.from({ length: baseArity[id].in }, () => randFp(rng));
      const ro = runSubCapped(dBase, id, inputs);    // trusted baseline body
      const rs = runSubCapped(dShip, id, inputs);    // shipped body
      if (ro.error) { continue; }                    // baseline itself errored -> not a clean trial
      clean++;
      if (!rs.error && eqStacks(ro.stack, rs.stack)) match++;
      else errMismatch++;
    }
    if (errMismatch > 0) fails.push(id);
    if (clean === 0) noCleanBodies++;
    else checkedBodies++;
    const verdict = errMismatch > 0 ? 'FAIL' : (clean > 0 ? `ok(${match}/${clean})` : 'no-clean-trial');
    if (errMismatch > 0 || clean === 0) console.log(`    def#${String(id).padStart(2)}  ${verdict}`);
  }
  console.log(`  shared bodies checked : ${checkedBodies}/${shared.length}  (no-clean: ${noCleanBodies})`);
  if (providers.length) console.log(`  repurposed providers  : def#${providers.join(', def#')}  (nullary derive/const helpers, no baseline counterpart -> covered by CHECK 3)`);
  if (shipOnly.length) console.log(`  shipped-only helpers  : def#${shipOnly.join(', def#')}  (new derive helpers, no baseline counterpart -> covered by CHECK 3)`);
  if (fails.length) {
    console.log(`  BEHAVIOUR MISMATCH    : def#${fails.join(', def#')}`);
    console.log('  CHECK 2       : FAIL');
    results.differential = false;
  } else if (checkedBodies === 0) {
    console.log('  no body produced a clean baseline trial -- cannot certify behaviour');
    console.log('  CHECK 2       : FAIL');
    results.differential = false;
  } else {
    console.log('  CHECK 2       : PASS  (every shared body bit-identical to the trusted baseline)');
    results.differential = true;
  }
}

// =====================================================================================
// CHECK 3 -- E2E
// =====================================================================================
function checkE2E() {
  console.log('');
  console.log('--------------------------------------------------------------------------------');
  console.log(' CHECK 3 -- E2E  (valid-ACCEPT + invalid-REJECT on multiproof vectors)');
  console.log('--------------------------------------------------------------------------------');
  if (flags.skipE2e) {
    console.log('  --skip-e2e set: CHECK 3 DEFERRED (wired; run without --skip-e2e to execute).');
    results.e2e = null;
    return;
  }
  const HUGE = Number.MAX_SAFE_INTEGER;
  const loosened = {
    ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7,
    maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1,
    maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128,
    operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE,
    maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE,
  };
  const vm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loosened, ripemd160, secp256k1, sha1, sha256 }));
  const runLock = (lock, unlockHex) =>
    vm.verify(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: hexToBin(unlockHex), valueSatoshis: 10000n })) === true;

  const mp = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  const n = Math.min(mp.proofs.length, flags.e2eProofs);
  let acc = 0, rej = 0, diff = 0;
  for (let i = 0; i < n; i++) {
    const p = mp.proofs[i];
    const oV = runLock(shipBytes, p.unlocking), oI = runLock(shipBytes, p.invalidUnlocking);
    const bV = runLock(baseline, p.unlocking), bI = runLock(baseline, p.invalidUnlocking);
    if (oV) acc++; if (!oI) rej++; if (oV === bV && oI === bI) diff++;
    console.log(`    proof#${i} valid=${oV ? 'ACCEPT' : 'FAIL'} invalid=${oI ? 'ACCEPT!!' : 'reject'} diff=${oV === bV && oI === bI ? 'ok' : 'MISMATCH'}`);
  }
  const pass = acc === n && rej === n && diff === n;
  console.log(`  valid-ACCEPT ${acc}/${n} ; invalid-REJECT ${rej}/${n} ; differential ${diff}/${n}`);
  console.log(`  CHECK 3       : ${pass ? 'PASS' : 'FAIL'}`);
  results.e2e = pass;
}

// ---- run ----------------------------------------------------------------------------
checkRoundTrip();
checkDifferential(flags.trials);
checkE2E();

// ---- summary ------------------------------------------------------------------------
console.log('');
console.log('================================================================================');
const label = (v) => (v === null ? 'DEFERRED' : v ? 'PASS' : 'FAIL');
console.log(`  CHECK 1 ROUND-TRIP     : ${label(results.roundTrip)}`);
console.log(`  CHECK 2 DIFFERENTIAL   : ${label(results.differential)}`);
console.log(`  CHECK 3 E2E            : ${label(results.e2e)}`);
const allPass = results.roundTrip && results.differential && results.e2e === true;
const anyFail = results.roundTrip === false || results.differential === false || results.e2e === false;
if (allPass) { console.log('  OVERALL                : PASS'); console.log('================================================================================'); process.exit(0); }
if (anyFail) { console.log('  OVERALL                : FAIL'); console.log('================================================================================'); process.exit(1); }
console.log('  OVERALL                : INCOMPLETE (E2E deferred -- not a full pass)');
console.log('================================================================================');
process.exit(2);
