#!/usr/bin/env node
// =============================================================================
// fold_pass.mjs -- the complete FoldTable(L<=4) + Peephole(L=5) deterministic
// stack-op FOLD optimizer pass.
//
// WHAT IT DOES
//   Given a recompiler-output singleton (OP_DEFINE subroutine table + main routine,
//   as locking bytecode hex), it rewrites every maximal run of PURE stack ops -- across
//   main and all bodies -- by GREEDY window superoptimization: at each position it takes
//   the longest window (5..2 ops) that has a strictly-shorter EQUIVALENT stack effect,
//   and replaces it, iterating each run to a FIXPOINT, then the whole program to a
//   fixpoint. It is DETERMINISTIC (no random search): fixed alphabet, fixed window
//   order, first-shorter-equivalent wins.
//
//   The productive rewrites are exactly the stackcert FoldTable / Peephole identities,
//   e.g.  DROP DROP -> 2DROP ,  OVER OVER -> 2DUP ,  SWAP OVER -> TUCK ,
//         <3>ROLL <3>ROLL -> 2SWAP ,  <5>ROLL <5>ROLL -> 2ROT ,  <3>PICK <3>PICK -> 2OVER ,
//         ROT ROT ROT -> (delete) ,  2ROT 2ROT 2ROT -> (delete) , plus L<=4 composites.
//
// WHY IT IS SOUND -- one machine-checked theorem PER FOLD (contrast CSE's single theorem)
//   Every replacement this pass applies is a bytecode-level stack IDENTITY. Each such
//   identity is a rewrite in the stackcert rewrite library:
//     * FoldTable -- window-complete for windows of L<=4 pure ops (every net-negative
//       L<=4 identity over the decompiler-safe alphabet has a proven `rfl`-theorem), and
//     * Peephole  -- a curated L=5 extension (identity-cycles like ROT^3, 2ROT^3, and
//       <n>ROLL/<n>PICK staircase collapses).
//   So, UNLIKE cse-pass (whose whole soundness is the single `invoke_cse` theorem), the
//   fold pass carries a PER-FOLD proof obligation -- but the table is window-complete for
//   L<=4, so no L<=4 identity is missed and none is unproven. As a redundant, target-VM
//   belt-and-braces check the pass ALSO confirms each window replacement live on the VM
//   across DEEP sentinel depths (the `equiv` oracle) before applying it -- and the --gate
//   suite re-verifies the whole implementation (round-trip + differentials).
//
// TARGET-AGNOSTIC
//   The pass never inspects field arithmetic; it needs only, for the target VM, a
//   `dissect` / `rebuild` / `runSubroutine` / decompile round-trip (supplied here by
//   ../pipeline-sub6k for the BCH-2026 loosened VM) and the VM itself for the equivalence
//   oracle. Point it at a BLS singleton or any future recompiler output; it folds that too.
//
// USAGE
//   node fold_pass.mjs <in.hex> <out.hex>            run the pass, write reduced hex
//   node fold_pass.mjs <in.hex> <out.hex> --gate     ... then run all 3 gates (exit 0 iff pass)
//   node fold_pass.mjs --gate <in.hex> <out.hex>     (flag order-insensitive)
//   node fold_pass.mjs --selfcheck                   reproduce the 5628 -> 5476 fold crown
//
// Portable: the pipeline is a RELATIVE import (../pipeline-sub6k) and the self-check
// crowns are resolved relative to this file. No absolute/scratch paths.
// =============================================================================

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { parse, serialize } from '../core/asm.mjs';
import {
  dissect, rebuild, runSubroutine, decompileProgram, recompileProgram, looseVm,
} from '../core/program.mjs';
import {
  createTestAuthenticationProgramBch, bigIntToVmNumber, vmNumberToBigInt,
} from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');
const HUGE = Number.MAX_SAFE_INTEGER;
// BN254 field modulus -- used ONLY as the modulus of the deterministic PRNG that feeds
// gate inputs (so gate stacks span the field). NOT a correctness input; nothing else in
// the pass is field- or curve-specific.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

const PICK = 0x79, ROLL = 0x7a;

// -----------------------------------------------------------------------------
// idxPush -- CORRECT push encoding for a PICK/ROLL depth operand `k`.
//
// THE BUG THIS FIXES (caught by the argv-parametrized fold pass): the naive encoding
// `idxPush(k) = 0x50 + k` is only valid for 1 <= k <= 16, where 0x51..0x60 are the
// single-byte opcodes OP_1..OP_16. At k = 17 it yields 0x61 -- which is OP_NOP2
// (CHECKSEQUENCEVERIFY), NOT a push -- and every larger k emits an unrelated OPCODE
// instead of a numeric operand. The deep ROLL/PICK staircase bodies in these singletons
// reach index ~38, so a naive re-encode SILENTLY CORRUPTS them. Correct encoding:
//     k == 0            -> OP_0            (0x00)
//     1 <= k <= 16      -> OP_1..OP_16     (0x51..0x60), one byte
//     k >= 17           -> direct push of the minimal signed little-endian VM number,
//                          via bigIntToVmNumber (handles the high-bit/sign case, e.g.
//                          128 -> [0x80,0x00], so the operand never reads as negative).
// The pass moreover PRESERVES the exact source bytes of any op it does not fold (see
// tokenize's `exact`), so anything untouched round-trips byte-for-byte regardless of how
// it was originally encoded; idxPush is used only to emit fold *replacements*.
function idxPush(k) {
  if (k < 0) throw new Error('idxPush: negative index ' + k);
  if (k === 0) return [0x00];
  if (k <= 16) return [0x50 + k];
  const vn = bigIntToVmNumber(BigInt(k));
  if (vn.length > 75) throw new Error('idxPush: index operand too large ' + k);
  return [vn.length, ...vn]; // minimal-header direct push (len prefix + payload)
}

// -----------------------------------------------------------------------------
// The DECOMPILER-SAFE replacement alphabet (NO 3DUP/IFDUP/DEPTH/altstack): the ops the
// block decompiler models, so a fold never produces something the round-trip gate can't
// re-derive. Single-op forms + <k>PICK/<k>ROLL (k<=KMAX_REPL). Candidate replacements are
// drawn only from here (plus deletion + pairs of single-byte ops).
// -----------------------------------------------------------------------------
const KMAX_REPL = 10; // <k>PICK/<k>ROLL candidate depth bound (all <=16 => single-byte idx)
const ONE = {
  DUP: 0x76, DROP: 0x75, OVER: 0x78, SWAP: 0x7c, ROT: 0x7b, NIP: 0x77, TUCK: 0x7d,
  '2DUP': 0x6e, '2DROP': 0x6d, '2OVER': 0x70, '2ROT': 0x71, '2SWAP': 0x72,
};
const REPL = [];
for (const [name, op] of Object.entries(ONE)) REPL.push({ name, bytes: Uint8Array.from([op]), len: 1 });
for (let k = 0; k <= KMAX_REPL; k++) {
  REPL.push({ name: `<${k}>PICK`, bytes: Uint8Array.from([...idxPush(k), PICK]), len: 1 + idxPush(k).length });
  REPL.push({ name: `<${k}>ROLL`, bytes: Uint8Array.from([...idxPush(k), ROLL]), len: 1 + idxPush(k).length });
}
const ONES = REPL.filter((r) => r.len === 1);

// candidate replacements STRICTLY SHORTER than `maxBytes`, in fixed order (deletion first,
// then single ops / short <k>PICK-ROLL, then ordered pairs of single-byte ops). The FIRST
// candidate that is stack-equivalent to the window wins -- fixed order => deterministic.
function* shorter(maxBytes) {
  if (0 < maxBytes) yield { name: '(delete)', bytes: new Uint8Array() };
  for (const r of REPL) if (r.len < maxBytes) yield r;
  for (const a of ONES) for (const b of ONES) if (2 < maxBytes) yield { name: a.name + ' ' + b.name, bytes: Uint8Array.from([...a.bytes, ...b.bytes]) };
}

// -----------------------------------------------------------------------------
// VM stack-effect ORACLE (context-free identity across depths). Pushes D distinct
// sentinel values, runs the byte sequence, returns the resulting stack (as hex), or null
// on a non-benign VM error. `equiv` requires identical stacks at EVERY depth in TSET, so
// an identity that only coincides at one depth is rejected. Memoized per (D, bytes): the
// same window recurs across bodies and fixpoint passes, so caching preserves exact
// semantics while cutting VM evals dramatically.
// -----------------------------------------------------------------------------
function makeOracle(TSET) {
  const cache = new Map();
  function effect(seqBytes, D) {
    const key = D + ':' + Buffer.from(seqBytes).toString('hex');
    const hit = cache.get(key);
    if (hit !== undefined) return hit;
    const push = [];
    for (let i = 0; i < D; i++) push.push(0x03, i & 0xff, 0x22, 0x33);
    const lock = Uint8Array.from([...push, ...seqBytes]);
    const s = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: lock, unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
    const r = (s.error && !/Non-P2SH|clean stack|exactly one|single/i.test(String(s.error)))
      ? null : s.stack.map((x) => Buffer.from(x).toString('hex'));
    cache.set(key, r);
    return r;
  }
  function equiv(a, b) {
    for (const D of TSET) {
      const ea = effect(a, D), eb = effect(b, D);
      if (ea === null || eb === null) return false;
      if (ea.length !== eb.length || !ea.every((x, i) => x === eb[i])) return false;
    }
    return true;
  }
  return { effect, equiv, cache };
}

// Choose sentinel depths deep enough to distinguish every staircase index actually used:
// base = max(11, maxK+4) where maxK is the deepest <k>PICK/<k>ROLL in the program, then
// test five consecutive depths base..base+4 (a run of depths beats accidental one-off
// coincidences and reaches past the deepest ROLL/PICK slot).
const smallInt = (o) => {
  if (!o) return null;
  if (o.op === 0x00) return 0;
  if (o.op >= 0x51 && o.op <= 0x60) return o.op - 0x50;
  if (o.data && o.data.length === 1) return o.data[0];
  if (o.data && o.data.length === 0) return 0;
  return null;
};
function computeTSET(bytes) {
  const d = dissect(bytes);
  let maxK = 0;
  const scan = (ops) => {
    for (let i = 0; i < ops.length; i++) {
      const o = ops[i], n = ops[i + 1], k = smallInt(o);
      if (k !== null && n && n.data === undefined && (n.op === PICK || n.op === ROLL)) maxK = Math.max(maxK, k);
    }
  };
  for (const id of d.order) scan(parse(d.bodies.get(id)));
  scan(d.mainOps);
  const base = Math.max(11, maxK + 4);
  return { maxK, TSET: [base, base + 1, base + 2, base + 3, base + 4] };
}

// -----------------------------------------------------------------------------
// Tokenize an op list into PURE stack-op units (merging <k>PICK / <k>ROLL into one token)
// vs IMPURE ops (everything else). PURE tokens carry their EXACT source bytes (via `exact`)
// so any token the fold leaves alone re-emits byte-for-byte -- deep indices included. `src`
// is the buffer `ops` was parsed from (offsets index into it).
// -----------------------------------------------------------------------------
const NAME1 = { 0x76: 'DUP', 0x75: 'DROP', 0x78: 'OVER', 0x7c: 'SWAP', 0x7b: 'ROT', 0x77: 'NIP', 0x7d: 'TUCK', 0x6e: '2DUP', 0x6d: '2DROP', 0x70: '2OVER', 0x71: '2ROT', 0x72: '2SWAP' };
const exact = (o, src) => src.slice(o.off, o.off + o.hdr + (o.data ? o.data.length : 0));
function tokenize(ops, src) {
  const t = [];
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i], n = ops[i + 1], k = smallInt(o);
    if (k !== null && k >= 0 && k <= 63 && n && n.data === undefined && (n.op === PICK || n.op === ROLL)) {
      t.push({ pure: true, name: `<${k}>${n.op === PICK ? 'PICK' : 'ROLL'}`, bytes: Uint8Array.from([...exact(o, src), ...exact(n, src)]) });
      i++; continue;
    }
    if (o.data === undefined && NAME1[o.op]) { t.push({ pure: true, name: NAME1[o.op], bytes: Uint8Array.from([o.op]) }); continue; }
    t.push({ pure: false, raw: o });
  }
  return t;
}
function tokensToOps(toks) {
  const bytes = [];
  for (const t of toks) { if (t.pure) bytes.push(...t.bytes); else bytes.push(...serialize([t.raw])); }
  return parse(Uint8Array.from(bytes));
}

// -----------------------------------------------------------------------------
// GREEDY longest-window fold to fixpoint over one PURE run. At position i, try window
// sizes 5..2 (longest first); for the first window that has a strictly-shorter equivalent
// replacement, splice it in and restart. Iterate until a full sweep changes nothing.
// -----------------------------------------------------------------------------
function foldRun(run, oracle, foldLog) {
  let changed = true;
  let cur = run.slice();
  while (changed) {
    changed = false;
    const out = [];
    let i = 0;
    while (i < cur.length) {
      let done = false;
      for (let w = Math.min(5, cur.length - i); w >= 2 && !done; w--) {
        const win = cur.slice(i, i + w);
        const wb = Uint8Array.from(win.reduce((a, t) => [...a, ...t.bytes], []));
        const L = wb.length; if (L < 2) continue;
        for (const cand of shorter(L)) {
          if (oracle.equiv(wb, cand.bytes)) {
            const key = `${win.map((t) => t.name).join(' ')}  =>  ${cand.name || '(delete)'} [${L}->${cand.bytes.length}B, -${L - cand.bytes.length}]`;
            foldLog.set(key, (foldLog.get(key) || 0) + 1);
            for (const rt of tokenize(parse(cand.bytes), cand.bytes)) out.push(rt);
            i += w; done = true; changed = true; break;
          }
        }
      }
      if (!done) { out.push(cur[i]); i++; }
    }
    cur = out;
  }
  return cur;
}
function foldOps(ops, src, oracle, foldLog) {
  const toks = tokenize(ops, src);
  const out = [];
  let i = 0;
  while (i < toks.length) {
    if (!toks[i].pure) { out.push(toks[i]); i++; continue; }
    let j = i; while (j < toks.length && toks[j].pure) j++;
    for (const t of foldRun(toks.slice(i, j), oracle, foldLog)) out.push(t);
    i = j;
  }
  return tokensToOps(out);
}

// -----------------------------------------------------------------------------
// runFoldPass: fold every body + main once (each run internally to fixpoint), rebuild.
// -----------------------------------------------------------------------------
function runFoldPass(bytes, oracle) {
  const d = dissect(bytes);
  const foldLog = new Map();
  const override = new Map();
  const rows = [];
  const changedIds = new Set();
  for (const id of d.order) {
    const orig = d.bodies.get(id);
    const folded = serialize(foldOps(parse(orig), orig, oracle, foldLog));
    override.set(id, folded);
    if (folded.length !== orig.length || Buffer.compare(Buffer.from(folded), Buffer.from(orig)) !== 0) {
      changedIds.add(id);
      if (folded.length !== orig.length) rows.push({ what: 'def#' + id, from: orig.length, to: folded.length });
    }
  }
  const mainOrig = serialize(d.mainOps);
  const mainNew = serialize(foldOps(parse(mainOrig), mainOrig, oracle, foldLog));
  if (mainNew.length !== mainOrig.length) rows.push({ what: 'main', from: mainOrig.length, to: mainNew.length });
  const folded = rebuild(d, override, mainNew);
  const totalFolds = [...foldLog.values()].reduce((a, b) => a + b, 0);
  return { folded, foldLog, rows, changedIds, totalFolds, from: bytes.length, to: folded.length };
}

// runFoldFixpoint: repeat runFoldPass until a pass applies 0 folds. Each pass is a
// composition of sound stack-identity rewrites, so the whole chain is sound.
function runFoldFixpoint(bytes, oracle, { maxPasses = 20 } = {}) {
  let cur = bytes;
  const passes = [];
  for (let iter = 1; iter <= maxPasses; iter++) {
    const r = runFoldPass(cur, oracle);
    if (r.totalFolds === 0) break; // fixpoint: nothing folded
    passes.push(r);
    cur = r.folded;
  }
  const totalFolds = passes.reduce((a, p) => a + p.totalFolds, 0);
  return { folded: cur, passes, totalFolds, origLen: bytes.length, foldedLen: cur.length, net: cur.length - bytes.length };
}

// =============================================================================
// GATES: three empirical checks that the applied folding matches the identities.
//   1. round-trip byte-exact   (folded decompiles+recompiles to itself)
//   2. per-subroutine diff      (orig body == folded body, semantically; unchanged==byte-eq)
//   3. whole-main differential  (whole program identical / same benign error over deep stacks)
// =============================================================================
const ENVI = (n, d) => { const v = process.env[n]; return v === undefined ? d : parseInt(v, 10); };
const ARITY_MAXK = ENVI('FOLD_ARITY_MAXK', 45);
const ARITY_STABLE = ENVI('FOLD_ARITY_STABLE', 6);
const SUB_TRIALS = ENVI('FOLD_SUB_TRIALS', 8);    // GATE2 random inputs per changed body
const MAIN_TRIALS = ENVI('FOLD_MAIN_TRIALS', 200); // GATE3 random deep stacks

const rnd = (s) => { let x = BigInt(s + 7); for (let i = 0; i < 6; i++) x = (x * 6364136223846793005n + 1442695040888963407n) % P; return x; };

// Wide-arity probe (staircase bodies consume ~35 inputs; the shared probeArity caps at 30
// and would under-count). Monotone arity => early-stop once ARITY_STABLE consecutive
// successes are seen past the last error. Self-validating: an under-probed arity makes
// GATE1's byte-exact round-trip underflow => rt-exact goes FALSE, never passes silently.
function wideArity(dd, maxK = ARITY_MAXK) {
  const table = {};
  for (const id of dd.order) {
    let maxErr = -1, netBig = 0, succ = 0;
    for (let k = 0; k <= maxK; k++) {
      const r = runSubroutine(dd, id, Array.from({ length: k }, (_, i) => rnd(i * 31 + id)));
      if (r.error) { maxErr = k; succ = 0; } else { netBig = r.stack.length - k; if (++succ >= ARITY_STABLE) break; }
    }
    table[id] = { in: maxErr + 1, out: maxErr + 1 + netBig };
  }
  return table;
}

function runGates(origBytes, foldedBytes, { quiet = false } = {}) {
  const log = quiet ? () => {} : (...a) => console.log(...a);
  const d = dissect(origBytes), df = dissect(foldedBytes);
  const arity = wideArity(df); // folding preserves arity, so one table serves orig+folded

  // GATE 1: round-trip byte-exact
  let rtExact = false, badBodies = [], mainExact = false;
  try {
    const ir = decompileProgram(df, arity, 10);
    const rc = recompileProgram(df, ir, arity);
    rtExact = Buffer.from(rc.bytes).equals(Buffer.from(foldedBytes));
    mainExact = rc.mainExact;
    badBodies = rc.perBody.filter((b) => !b.exact).map((b) => b.id);
  } catch (e) { log('  GATE1 decompile THREW:', e.message); }
  log('GATE1 round-trip byte-exact:', rtExact, '| mainExact:', mainExact, '| bad bodies:', badBodies.join(',') || 'none');

  // GATE 2: per-subroutine differential (+ unchanged bodies byte-identical)
  let subMism = 0, unchangedByteEq = 0, unchangedTotal = 0, changedRun = 0;
  const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  for (const id of d.order) {
    const same = Buffer.from(d.bodies.get(id)).equals(Buffer.from(df.bodies.get(id)));
    if (same) { unchangedTotal++; unchangedByteEq++; continue; } // unchanged => trivially equal, no exec
    changedRun++;
    for (let s = 0; s < SUB_TRIALS; s++) {
      const inputs = Array.from({ length: arity[id].in }, (_, i) => rnd(i * 13 + id * 101 + s));
      const ro = runSubroutine(d, id, inputs), rs = runSubroutine(df, id, inputs);
      const ok = !ro.error && !rs.error && eq(ro.stack, rs.stack);
      if (!ok) { subMism++; if (subMism <= 5) log('  sub mismatch id', id, 's', s, ro.error || '', rs.error || ''); }
    }
  }
  log('GATE2 per-subroutine differential: mismatches', subMism, '| changed bodies run', changedRun, '| unchanged byte-eq', unchangedByteEq + '/' + unchangedTotal);

  // GATE 3: whole-main differential over random deep stacks
  const recsOf = (dd) => dd.defRecs.map((r) => ({ body: dd.bodies.get(r.id), idRec: r.idRec, defRec: r.defRec }));
  const oRecs = recsOf(d), fRecs = recsOf(df);
  function runWith(recs, mainOps, stackVals) {
    const ops = [];
    for (const r of recs) { ops.push({ op: 0, data: r.body }); ops.push(r.idRec); ops.push(r.defRec); }
    for (const v of stackVals) ops.push({ op: 0, data: bigIntToVmNumber(BigInt(v)) });
    for (const o of mainOps) ops.push(o);
    const st = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: serialize(ops), unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
    const benign = !st.error || /Non-P2SH|clean stack|exactly one|single/i.test(String(st.error));
    return { stack: benign ? st.stack.map((b) => vmNumberToBigInt(b, { maximumVmNumberByteLength: HUGE })) : null, err: benign ? null : String(st.error) };
  }
  let mainFail = 0;
  for (let t = 0; t < MAIN_TRIALS; t++) {
    const D = 30 + (t % 20);
    const sv = Array.from({ length: D }, (_, i) => rnd(i * 41 + t * 5003 + 900));
    const a = runWith(oRecs, d.mainOps, sv), b = runWith(fRecs, df.mainOps, sv);
    const ok = ((a.stack === null) === (b.stack === null))
      && (a.stack === null ? a.err === b.err : (a.stack.length === b.stack.length && a.stack.every((x, i) => x === b.stack[i])));
    if (!ok) { mainFail++; if (mainFail <= 5) log('  main-diff fail t', t, 'aerr', a.err, 'berr', b.err); }
  }
  log('GATE3 whole-main differential:', (MAIN_TRIALS - mainFail) + '/' + MAIN_TRIALS, 'pass, fail', mainFail);

  const allPass = rtExact && mainExact && badBodies.length === 0 && subMism === 0
    && mainFail === 0 && unchangedByteEq === unchangedTotal;
  return { allPass, rtExact, mainExact, badBodies, subMism, mainFail, unchangedByteEq, unchangedTotal };
}

// -----------------------------------------------------------------------------
function loadHex(path) { return Uint8Array.from(Buffer.from(readFileSync(path, 'utf8').trim(), 'hex')); }

function reportPass(r, i) {
  console.log(`-- pass ${i + 1} --  ${r.from}B -> ${r.to}B  (-${r.from - r.to}B, ${r.totalFolds} folds)`);
  [...r.foldLog.entries()].sort((a, b) => b[1] - a[1]).forEach(([k, v]) => console.log(`   x${String(v).padStart(3)}  ${k}`));
  r.rows.forEach((row) => console.log(`   ${row.what}: ${row.from}->${row.to} (-${row.from - row.to})`));
}

// =============================================================================
// SELF-CHECK
//   (a) oracle FIRES on the 3 headline identities, REJECTS the 2 non-identities;
//   (b) 5628 search crown -> 5476 fold crown, byte-exact (sha), gates green;
//   (c) 4346 CSE crown -> 0 folds (fold _|_ CSE true negative).
// =============================================================================
const SELFCHECK_5628 = join(HERE, '..', 'singleton-5987-locking5628-search.hex');
const SELFCHECK_4346 = join(HERE, '..', 'singleton-4705-locking4346-foldcse.hex');
const EXPECT_INPUT_LEN = 5628;
const EXPECT_FOLD_LEN = 5476;
const EXPECT_FOLD_SHA = '63601c1e6ce1dca0c7d90f4773669b5798ead38d559baf372aa01c09d8226687';

function oracleUnitTests() {
  // deep sentinel depths (>= 11 distinguishes 2ROT/2OVER etc.); dedicated oracle
  const { equiv } = makeOracle([11, 12, 13, 14, 15]);
  const seq = (...parts) => Uint8Array.from(parts.flat());
  const cases = [
    { name: 'DROP DROP -> 2DROP', a: seq(0x75, 0x75), b: seq(0x6d), want: true },
    { name: '<3>ROLL <3>ROLL -> 2SWAP', a: seq(idxPush(3), ROLL, idxPush(3), ROLL), b: seq(0x72), want: true },
    { name: '<5>ROLL <5>ROLL -> 2ROT', a: seq(idxPush(5), ROLL, idxPush(5), ROLL), b: seq(0x71), want: true },
    { name: 'DUP DUP != 2DUP', a: seq(0x76, 0x76), b: seq(0x6e), want: false },
    { name: '<1>PICK <1>PICK != 2OVER', a: seq(idxPush(1), PICK, idxPush(1), PICK), b: seq(0x70), want: false },
  ];
  let ok = true;
  for (const c of cases) {
    const got = equiv(c.a, c.b);
    const pass = got === c.want;
    if (!pass) ok = false;
    console.log(`   ${pass ? 'OK ' : '*** BAD ***'}  oracle ${c.name}: equiv=${got} (want ${c.want})`);
  }
  return ok;
}

function selfcheck() {
  console.log('=== fold_pass --selfcheck ===\n');

  console.log('[1/3] oracle unit tests (fires on identities, rejects non-identities):');
  const oracleOk = oracleUnitTests();

  console.log('\n[2/3] fold crown reproduction: 5628 search -> 5476 foldcomplete');
  console.log('input:', SELFCHECK_5628);
  const bytes = loadHex(SELFCHECK_5628);
  if (bytes.length !== EXPECT_INPUT_LEN) { console.error(`FAIL: input is ${bytes.length}B, expected ${EXPECT_INPUT_LEN}B`); return 1; }
  const { TSET, maxK } = computeTSET(bytes);
  console.log(`sentinel depths: maxK=${maxK}  TSET=[${TSET.join(',')}]`);
  const oracle = makeOracle(TSET);
  const r = runFoldFixpoint(bytes, oracle);
  r.passes.forEach((p, i) => reportPass(p, i));
  const gotSha = sha(r.folded);
  const lenOk = r.foldedLen === EXPECT_FOLD_LEN;
  const shaOk = gotSha === EXPECT_FOLD_SHA;
  console.log(`\nresult: ${r.origLen}B -> ${r.foldedLen}B (net ${r.net}B) in ${r.passes.length} reducing pass(es)`);
  console.log(`byte-count: ${r.foldedLen} === ${EXPECT_FOLD_LEN} ? ${lenOk}`);
  console.log(`sha256    : ${gotSha}`);
  console.log(`sha match : ${shaOk}  (target ${EXPECT_FOLD_SHA})`);
  console.log('running gates on the reproduced crown ...');
  const g = runGates(bytes, r.folded);
  console.log('gates all-pass:', g.allPass);

  console.log('\n[3/3] fold _|_ CSE true-negative: 4346 CSE crown -> 0 folds');
  const cbytes = loadHex(SELFCHECK_4346);
  const { TSET: ctset } = computeTSET(cbytes);
  const cr = runFoldFixpoint(cbytes, makeOracle(ctset));
  const zeroFolds = cr.totalFolds === 0 && cr.foldedLen === cbytes.length && Buffer.from(cr.folded).equals(Buffer.from(cbytes));
  console.log(`4346 crown: ${cbytes.length}B -> ${cr.foldedLen}B, folds applied ${cr.totalFolds}  => 0-fold true-negative: ${zeroFolds}`);

  console.log('\n==== SELFCHECK VERDICT ====');
  console.log(`oracle unit tests : ${oracleOk}`);
  console.log(`5628->5476 bytes  : ${lenOk}`);
  console.log(`5476 sha match    : ${shaOk}`);
  console.log(`gates green       : ${g.allPass}`);
  console.log(`4346 zero-fold    : ${zeroFolds}`);
  const ok = oracleOk && lenOk && shaOk && g.allPass && zeroFolds;
  console.log(ok ? 'SELFCHECK: PASS (deterministic reproduction verified)' : 'SELFCHECK: FAIL');
  return ok ? 0 : 1;
}

// =============================================================================
// CLI
// =============================================================================
function main() {
  const args = process.argv.slice(2);
  const gate = args.includes('--gate');
  const doSelfcheck = args.includes('--selfcheck');
  const positional = args.filter((a) => !a.startsWith('--'));

  if (doSelfcheck) { process.exit(selfcheck()); }

  if (positional.length < 2) {
    console.error('usage: node fold_pass.mjs <in.hex> <out.hex> [--gate]');
    console.error('       node fold_pass.mjs --selfcheck');
    process.exit(2);
  }
  const [inPath, outPath] = positional;
  const bytes = loadHex(inPath);
  const { TSET, maxK } = computeTSET(bytes);
  console.log(`input ${bytes.length}B  sha ${sha(bytes)}  | sentinel maxK=${maxK} TSET=[${TSET.join(',')}]`);
  const oracle = makeOracle(TSET);
  const r = runFoldFixpoint(bytes, oracle);
  writeFileSync(outPath, Buffer.from(r.folded).toString('hex'));
  r.passes.forEach((p, i) => reportPass(p, i));
  console.log(`fixpoint: ${r.passes.length} reducing pass(es), ${r.origLen}B -> ${r.foldedLen}B (net ${r.net}B, ${r.totalFolds} folds); wrote ${outPath}`);
  console.log(`output sha ${sha(r.folded)}`);

  if (gate) {
    console.log('\n==== GATE VERDICT ====');
    const g = runGates(bytes, r.folded);
    console.log('all gates pass:', g.allPass);
    process.exit(g.allPass ? 0 : 1);
  }
  process.exit(0);
}

main();
