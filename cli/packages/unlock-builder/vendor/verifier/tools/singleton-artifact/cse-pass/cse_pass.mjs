#!/usr/bin/env node
// =============================================================================
// cse_pass.mjs -- the complete invoke_cse deterministic optimizer pass.
//
// WHAT IT DOES
//   Given a recompiler-output singleton (OP_DEFINE subroutine table + main
//   routine, as locking bytecode hex), it factors EVERY net-positive repeated
//   contiguous op-subsequence -- across main and all bodies -- into a shared
//   OP_INVOKE body. This is common-subexpression elimination at the bytecode
//   level. It is DETERMINISTIC (no search): a census of repeats, a greedy
//   disjoint set-pack, and a byte-exact splice.
//
// WHY IT IS SOUND
//   Every factoring is justified by ONE general, machine-checked theorem --
//   Stackcert.InvokeCSE.invoke_cse -- which states OP_INVOKE stack-transparency:
//   replacing any contiguous op-subsequence by [push id; OP_INVOKE], where a new
//   OP_DEFINE binds `id` to exactly that subsequence, preserves execution on
//   every input stack. There is NO per-factoring proof obligation (contrast the
//   fold-table, which needs a separate theorem per rewrite). So the pass is
//   "sound by construction": any factoring the census emits is covered by the
//   single theorem, and the gates below are a belt-and-braces empirical check
//   that the *implementation* (splice + id allocation) matches the theorem.
//
// TARGET-AGNOSTIC
//   The pass never inspects field arithmetic; it only needs, for the target VM,
//   a `dissect` / `runSubroutine` / decompile round-trip (supplied here by
//   ../pipeline-sub6k for the BCH-2026 loosened VM). Point it at a BLS singleton,
//   or any future recompiler output, and it factors that too -- provided the
//   pipeline can dissect/run that program.
//
// USAGE
//   node cse_pass.mjs <in.hex> <out.hex>     run the pass, write reduced hex
//   node cse_pass.mjs <in.hex> <out.hex> --gate   ... then run all 4 gates
//   node cse_pass.mjs --gate <in.hex> <out.hex>   (flag order-insensitive)
//   node cse_pass.mjs --selfcheck            reproduce the 4818->4359 crown result
//
// Portable: the pipeline is resolved by a RELATIVE import (../pipeline-sub6k),
// the self-check crown by a path relative to this file. No absolute/scratch paths.
// =============================================================================

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parse, serialize } from '../pipeline-sub6k/asm.mjs';
import {
  dissect, decompileProgram, recompileProgram, runSubroutine, looseVm,
} from '../pipeline-sub6k/program.mjs';
import {
  createTestAuthenticationProgramBch, bigIntToVmNumber, vmNumberToBigInt,
} from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));

// ---- opcode / VM constants ---------------------------------------------------
const DEFINE = 0x89, INVOKE = 0x8a;
const PICK = 0x79, ROLL = 0x7a;
const HUGE = Number.MAX_SAFE_INTEGER;
// BN254 field modulus -- used ONLY as the modulus of the deterministic PRNG that
// generates gate inputs (so gate stacks span the field). Not a correctness input.
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;

// ---- census tunables ---------------------------------------------------------
const MAXL = 130;      // max op-length of a factored subsequence. Marshalling
                       // macros in these singletons are < ~120 ops; 130 is slack.
const MINBYTES = 8;    // ignore trivially short repeats (never net-positive).
const MIN_NET = 10;    // only factor if it saves > 10 bytes (net(B,K) <= -10).
const FIRST_FREE_ID = 40; // first unused OP_DEFINE id. Recompiler output uses
                       // 1..~39; 40..127 encode as a single push byte (=> invoke
                       // site is exactly 3 bytes: push1 + idbyte + INVOKE).

// minimal push header length for a payload of n bytes (1 / 2 / 3).
function pushHeader(n) { return n <= 75 ? 1 : n <= 255 ? 2 : 3; }

// Net byte change of factoring a length-B body with K non-overlapping call sites:
//   - remove B*K inline bytes, add B once (the shared body) => B*(1-K)
//   - add 3 bytes per call site (push1 + idbyte + INVOKE)   => 3*K
//   - add the definition overhead once: bodyPushHeader(B) + idpush(2) + DEFINE(1)
// Want net <= -MIN_NET. (Estimate; the true delta is measured after serialize.)
function netBytes(B, K) { return B * (1 - K) + 3 * K + (pushHeader(B) + 3); }

// -----------------------------------------------------------------------------
// STREAMS + GLOBAL TOKEN ARRAY
// Build one op-stream per code region (main, then every body), intern each op to
// an integer token, and concatenate into one global array T with a UNIQUE NEGATIVE
// BARRIER between regions. Barriers guarantee no "repeat" is ever detected across
// a region boundary (which would be meaningless to factor).
//   T[g]  = interned token at global position g (negative == barrier)
//   G[g]  = { si: stream index, i: local op index, blen: byte length } (null at barrier)
// -----------------------------------------------------------------------------
function buildStreams(d) {
  const streams = [];
  const mkStream = (name, raw) => {
    const ops = parse(raw);
    const tok = ops.map((o) => (o.data !== undefined
      ? 'P' + Buffer.from(o.data).toString('hex')
      : 'O' + o.op.toString(16)));
    const blen = ops.map((o) => o.hdr + (o.data ? o.data.length : 0));
    return { name, ops, tok, blen };
  };
  streams.push(mkStream('main', serialize(d.mainOps)));
  for (const id of d.order) streams.push(mkStream('body#' + id, d.bodies.get(id)));
  // stream index -> owning body id (null for main). si k>0 owns body d.order[k-1].
  const streamBodyId = (si) => (si === 0 ? null : d.order[si - 1]);

  const intern = new Map();
  let nextId = 1;
  const T = [], G = [];
  let barrier = -1;
  // Never factor windows across control-flow boundaries: the CSE theorem applies to straight-line code.
  const CF = new Set([0x63, 0x64, 0x65, 0x66, 0x67, 0x68]); // IF NOTIF BEGIN UNTIL ELSE ENDIF
  for (let si = 0; si < streams.length; si++) {
    const st = streams[si];
    for (let i = 0; i < st.ops.length; i++) {
      if (CF.has(st.ops[i].op)) { T.push(barrier--); G.push(null); continue; }
      let t = intern.get(st.tok[i]);
      if (t === undefined) { t = nextId++; intern.set(st.tok[i], t); }
      T.push(t); G.push({ si, i, blen: st.blen[i] });
    }
    T.push(barrier--); G.push(null); // inter-stream barrier
  }
  return { streams, streamBodyId, T, G, N: T.length };
}

// -----------------------------------------------------------------------------
// CENSUS: every repeated contiguous op-subsequence.
// For each length L in [2, MAXL], hash every window of L ops (skipping windows
// that straddle a barrier), group windows by content. Any content with >= 2
// occurrences is a candidate; the greedy pass below decides which to actually
// take (disjointness + net threshold). Returns Map<contentKey, {L,B,starts:[]}>.
// -----------------------------------------------------------------------------
function censusContents({ T, G, N }) {
  const contents = new Map();
  for (let L = 2; L <= MAXL; L++) {
    const m = new Map();
    for (let s = 0; s + L <= N; s++) {
      let ok = true, B = 0;
      for (let k = 0; k < L; k++) {
        if (T[s + k] < 0) { ok = false; break; } // barrier inside window
        B += G[s + k].blen;
      }
      if (!ok || B < MINBYTES) continue;
      let key = '';
      for (let k = 0; k < L; k++) key += T[s + k] + ',';
      let e = m.get(key);
      if (!e) { e = { L, B, starts: [] }; m.set(key, e); }
      e.starts.push(s);
    }
    for (const [key, e] of m) if (e.starts.length >= 2) contents.set(key, e);
  }
  return contents;
}

// -----------------------------------------------------------------------------
// DANGLING-CONST-PUSH FILTER  (a correctness constraint, NOT an optimization)
//
// WHY: the byte-exact round-trip decompiler (GATE1) models an OP_INVOKE's outputs
// as OPAQUE stack values. If a factored subsequence ENDS with a constant push whose
// value is then consumed as the depth operand of an EXTERNAL OP_PICK/OP_ROLL (the op
// immediately AFTER the factored region), then after factoring that depth is no
// longer a statically-known constant -- it is an opaque INVOKE output -- and the
// decompiler can no longer resolve the PICK/ROLL depth => round-trip fails.
//
// This does NOT affect SOUNDNESS -- invoke_cse still holds -- but the byte-exact
// gate requires depth operands stay statically resolvable, so we reject such
// contents from candidacy. Sub-patterns that END in the PICK/ROLL itself (or in a
// DROP, an arithmetic op, etc.) are unaffected and remain factorable.
//
// Returns the set of contentKeys to skip.
// -----------------------------------------------------------------------------
function danglingFilter(contents, { streams, T, G }) {
  const isConstPush = (o) => o.data !== undefined || o.op === 0x00 || o.op === 0x4f
    || (o.op >= 0x51 && o.op <= 0x60); // OP_0, OP_1NEGATE, OP_1..OP_16, or any push
  const rejected = new Set();
  for (const [key, e] of contents) {
    const L = e.L, s0 = e.starts[0];
    const lastOp = streams[G[s0 + L - 1].si].ops[G[s0 + L - 1].i];
    if (!isConstPush(lastOp)) continue;
    let danger = false;
    for (const s of e.starts) {
      const after = s + L;
      if (T[after] < 0) continue; // region ends here: nothing follows
      const g = G[after];
      const nx = streams[g.si].ops[g.i];
      if (nx.op === PICK || nx.op === ROLL) { danger = true; break; }
    }
    if (danger) rejected.add(key);
  }
  return rejected;
}

// -----------------------------------------------------------------------------
// GREEDY DISJOINT SET-PACK
// Repeatedly take the single most net-negative factoring whose occurrences are
// still non-overlapping AND lie in as-yet-unconsumed global positions; mark those
// positions consumed; allocate the next free id. Deterministic: Map iteration is
// insertion order (by L, then first-occurrence position), ties broken by first-seen.
// Returns chosen[] = { id, L, B, K, net, picks:[globalStart] } in application order.
// -----------------------------------------------------------------------------
function greedyPack(contents, rejected, { N, G, streams }, firstId = FIRST_FREE_ID) {
  const consumed = new Uint8Array(N);
  const nonOverlapAvail = (starts, L) => {
    const s = starts.slice().sort((a, b) => a - b);
    const picks = [];
    let last = -1;
    for (const p of s) {
      if (p < last) continue; // overlaps a previously picked occurrence of THIS content
      let free = true;
      for (let k = 0; k < L; k++) if (consumed[p + k]) { free = false; break; }
      if (!free) continue;    // overlaps an already-committed factoring
      picks.push(p); last = p + L;
    }
    return picks;
  };

  const chosen = [];
  let idCounter = firstId;
  while (true) {
    let best = null;
    for (const [key, e] of contents) {
      if (rejected.has(key)) continue;
      const picks = nonOverlapAvail(e.starts, e.L);
      if (picks.length < 2) continue;
      const n = netBytes(e.B, picks.length);
      if (n <= -MIN_NET && (!best || n < best.n)) best = { key, e, picks, n };
    }
    if (!best) break;
    for (const p of best.picks) for (let k = 0; k < best.e.L; k++) consumed[p + k] = 1;
    // per-site location breakdown (for the report)
    const loc = {};
    for (const p of best.picks) { const nm = streams[G[p].si].name; loc[nm] = (loc[nm] || 0) + 1; }
    chosen.push({ id: idCounter++, L: best.e.L, B: best.e.B, K: best.picks.length, net: best.n, picks: best.picks, loc });
  }
  return chosen;
}

// -----------------------------------------------------------------------------
// APPLY: splice each factoring into the op streams and rebuild the program.
// Each chosen occurrence [i, i+L) is replaced by [push id; OP_INVOKE]; a new
// OP_DEFINE record (bodyPush; idPush; DEFINE) is appended for each new id.
// Returns { factored:Uint8Array, chosen (with contentBytes), streamBodyId }.
// -----------------------------------------------------------------------------
function applyFactorings(d, ctx, chosen) {
  const { streams, streamBodyId, G } = ctx;

  // content bytes for each factoring (from its first occurrence); assert byte-identical
  for (const c of chosen) {
    const bytesAt = (p) => serialize(streams[G[p].si].ops.slice(G[p].i, G[p].i + c.L));
    const b0 = Buffer.from(bytesAt(c.picks[0])).toString('hex');
    for (const p of c.picks) {
      if (Buffer.from(bytesAt(p)).toString('hex') !== b0) throw new Error('content bytes mismatch id' + c.id);
    }
    c.contentBytes = Uint8Array.from(Buffer.from(b0, 'hex'));
  }

  // mutable copies of every op stream
  const modMain = streams[0].ops.slice();
  const modBody = new Map();
  for (let k = 1; k < streams.length; k++) modBody.set(streamBodyId(k), streams[k].ops.slice());
  const targetOps = (si) => (si === 0 ? modMain : modBody.get(streamBodyId(si)));

  // group replacements by stream, splice descending so earlier indices stay valid
  const bySi = new Map();
  for (const c of chosen) {
    for (const p of c.picks) {
      const g = G[p];
      if (!bySi.has(g.si)) bySi.set(g.si, []);
      bySi.get(g.si).push({ i: g.i, L: c.L, id: c.id });
    }
  }
  for (const [si, reps] of bySi) {
    reps.sort((a, b) => b.i - a.i);
    const arr = targetOps(si);
    for (const r of reps) arr.splice(r.i, r.L, { op: 0, data: Uint8Array.from([r.id]) }, { op: INVOKE });
  }

  // rebuild: original defs (bodies now containing invoke sites), then new defs, then main
  const out = [];
  for (const r of d.defRecs) {
    out.push({ op: 0, data: serialize(modBody.get(r.id)) });
    out.push(r.idRec);
    out.push(r.defRec);
  }
  for (const c of chosen) {
    out.push({ op: 0, data: c.contentBytes });
    out.push({ op: 0, data: Uint8Array.from([c.id]) });
    out.push({ op: DEFINE });
  }
  for (const o of modMain) out.push(o);

  return { factored: serialize(out), chosen, bySi };
}

// -----------------------------------------------------------------------------
// WIDE-ARITY PROBE  (a correctness constraint, NOT an optimization)
// The shared pipeline `probeArity` caps input probing at 30. But the deepest
// ROLL/PICK staircase bodies here consume ~35 inputs; capped at 30, their arity is
// UNDER-estimated and the round-trip decompiler underflows. We probe wider (cap 45,
// env CSE_ARITY_MAXK). Runtime semantics are unchanged -- this only feeds the gate's
// input counts.
//
// EARLY-STOP (self-validating perf): some bodies run an intrinsically expensive VM
// computation on every valid input (a deep marshalling staircase can take ~1s/probe),
// so probing the full 0..maxK range costs ~46 expensive runs each -> minutes. A body's
// arity is monotone (errors below `in`, succeeds at/above), so once we have STABLE
// consecutive successes past the last error we know `in` and `netBig` (which is
// constant for a stack-transparent body) -- further probing is redundant. We stop
// there (env CSE_ARITY_STABLE, default 6), capped at maxK. This is SELF-VALIDATING:
// if it ever under-probes and reports a wrong arity, GATE1's byte-exact round-trip
// decompile underflows and rt-exact goes FALSE -- so a bad arity can never pass silently.
// -----------------------------------------------------------------------------
const ENVI = (name, dflt) => { const v = process.env[name]; return v === undefined ? dflt : parseInt(v, 10); };
const ARITY_MAXK = ENVI('CSE_ARITY_MAXK', 45);
const ARITY_STABLE = ENVI('CSE_ARITY_STABLE', 6);
// Gate trial counts. Defaults are the full DW values (thorough). They are
// env-overridable so the gates can run a quick subset on a machine under load or
// on a program with intrinsically expensive bodies (each gate still exercises every
// factoring / the whole main; fewer random draws). invoke_cse equivalence is
// value-independent, so any nonzero trial count that passes corroborates all.
const SUB_TRIALS = ENVI('CSE_SUB_TRIALS', 10);    // GATE2 random inputs per subroutine
const CSE_TRIALS = ENVI('CSE_CSE_TRIALS', 120);   // GATE3 random stacks per factoring
const MAIN_TRIALS = ENVI('CSE_MAIN_TRIALS', 200); // GATE4 random deep stacks
const rnd = (s) => { let x = BigInt(s + 7); for (let i = 0; i < 6; i++) x = (x * 6364136223846793005n + 1442695040888963407n) % P; return x; };
function wideArity(dd, maxK = ARITY_MAXK) {
  const table = {};
  for (const id of dd.order) {
    let maxErr = -1, netBig = 0, succ = 0;
    for (let k = 0; k <= maxK; k++) {
      const r = runSubroutine(dd, id, Array.from({ length: k }, (_, i) => rnd(i * 31 + id)));
      if (r.error) { maxErr = k; succ = 0; }
      else { netBig = r.stack.length - k; if (++succ >= ARITY_STABLE) break; } // early-stop; GATE1 re-validates
    }
    table[id] = { in: maxErr + 1, out: maxErr + 1 + netBig };
  }
  return table;
}

// -----------------------------------------------------------------------------
// GATES: four empirical checks that the applied factoring matches the theorem.
//   1. round-trip byte-exact   (factored decompiles+recompiles to itself)
//   2. per-subroutine diff     (orig bodies == factored bodies, semantically)
//   3. invoke_cse local diff   (inline content == [push id; INVOKE] on shared table)
//   4. whole-main diff         (whole program identical over random deep stacks)
// Returns { allPass, ...counters } and (unless quiet) logs a line per gate.
// -----------------------------------------------------------------------------
function runGates(orig, factored, d, applied, ctx, { quiet = false } = {}) {
  const { chosen, bySi } = applied;
  const { streamBodyId } = ctx;
  const log = quiet ? () => {} : (...a) => console.log(...a);

  const df = dissect(factored);
  const newIdsPresent = chosen.every((c) => df.order.includes(c.id));
  let bodyContentOk = true;
  for (const c of chosen) {
    if (!df.bodies.has(c.id) || Buffer.from(df.bodies.get(c.id)).toString('hex') !== Buffer.from(c.contentBytes).toString('hex')) {
      bodyContentOk = false; log('  BAD new body content id', c.id);
    }
  }
  log('re-dissect bodies:', df.order.length, '| new ids present:', newIdsPresent, '| body-content==subseq:', bodyContentOk);

  // GATE 1: round-trip byte-exact
  const arity = wideArity(df);
  const ir = decompileProgram(df, arity, 10);
  const rc = recompileProgram(df, ir, arity);
  const rtExact = Buffer.from(rc.bytes).equals(Buffer.from(factored));
  const badBodies = rc.perBody.filter((b) => !b.exact).map((b) => b.id);
  log('GATE1 round-trip byte-exact:', rtExact, '| mainExact:', rc.mainExact, '| bad bodies:', badBodies.join(',') || 'none');

  // GATE 2: per-subroutine differential (orig ids) + unchanged-body byte identity
  const arO = wideArity(d);
  const changedIds = new Set([...bySi.keys()].filter((si) => si !== 0).map((si) => streamBodyId(si)));
  let sub = 0, subUnchangedByteEq = 0, subUnchangedTotal = 0;
  for (const id of d.order) {
    const changed = changedIds.has(id);
    if (!changed) {
      subUnchangedTotal++;
      const be = Buffer.from(d.bodies.get(id)).equals(Buffer.from(df.bodies.get(id)));
      if (be) subUnchangedByteEq++; else log('  unchanged body id', id, 'NOT byte-identical!');
    }
    for (let k = 0; k < SUB_TRIALS; k++) {
      const ins = Array.from({ length: arO[id].in }, (_, i) => rnd(i * 13 + id * 101 + k));
      const rOrig = runSubroutine(d, id, ins), rFac = runSubroutine(df, id, ins);
      const eq = !rOrig.error && !rFac.error && rOrig.stack.length === rFac.stack.length && rOrig.stack.every((x, i) => x === rFac.stack[i]);
      if (!eq) { sub++; if (sub <= 5) log('  sub mismatch id', id, 'k', k, rOrig.error || '', rFac.error || ''); }
    }
  }
  log('GATE2 per-subroutine differential: mismatches', sub, '| unchanged byte-eq', subUnchangedByteEq + '/' + subUnchangedTotal, '| changed ids', changedIds.size);

  // shared runner: def table + random stack + tail bytes -> stack (or null on non-benign error)
  const dfRecs = df.defRecs.map((r) => ({ body: df.bodies.get(r.id), idRec: r.idRec, defRec: r.defRec }));
  const origRecs = d.defRecs.map((r) => ({ body: d.bodies.get(r.id), idRec: r.idRec, defRec: r.defRec }));
  function runWith(recs, tailOpsOrBytes, stackVals, isBytes) {
    const ops = [];
    for (const r of recs) { ops.push({ op: 0, data: r.body }); ops.push(r.idRec); ops.push(r.defRec); }
    for (const v of stackVals) ops.push({ op: 0, data: bigIntToVmNumber(BigInt(v)) });
    const tail = isBytes ? parse(tailOpsOrBytes) : tailOpsOrBytes;
    for (const o of tail) ops.push(o);
    const st = looseVm.evaluate(createTestAuthenticationProgramBch({ lockingBytecode: serialize(ops), unlockingBytecode: new Uint8Array(), valueSatoshis: 1000n }));
    const benign = !st.error || /Non-P2SH|clean stack|exactly one|single/i.test(String(st.error));
    return { stack: benign ? st.stack.map((b) => vmNumberToBigInt(b, { maximumVmNumberByteLength: HUGE })) : null, err: benign ? null : String(st.error) };
  }

  // GATE 3: invoke_cse local differential -- inline content vs [push id; INVOKE]
  let cseFail = 0, cseTotal = 0;
  for (const c of chosen) {
    const D = Math.max(arity[c.id].in, 30);
    const invokeSite = Uint8Array.from([0x01, c.id, INVOKE]);
    for (let t = 0; t < CSE_TRIALS; t++) {
      const sv = Array.from({ length: D }, (_, i) => rnd(i * 97 + t * 7919 + c.id * 131));
      const a = runWith(dfRecs, c.contentBytes, sv, true);
      const b = runWith(dfRecs, invokeSite, sv, true);
      cseTotal++;
      const eq = a.stack && b.stack && a.stack.length === b.stack.length && a.stack.every((x, i) => x === b.stack[i]);
      if (!eq) { cseFail++; if (cseFail <= 5) log('  cse-diff fail id', c.id, 't', t); }
    }
  }
  log('GATE3 invoke_cse local differential:', (cseTotal - cseFail) + '/' + cseTotal, 'pass, fail', cseFail);

  // GATE 4: whole-main differential over random deep stacks
  let mainFail = 0, mainTotal = 0;
  for (let t = 0; t < MAIN_TRIALS; t++) {
    const D = 30 + (t % 20);
    const sv = Array.from({ length: D }, (_, i) => rnd(i * 41 + t * 5003 + 900));
    const a = runWith(origRecs, d.mainOps, sv, false);
    const b = runWith(dfRecs, df.mainOps, sv, false);
    mainTotal++;
    const eq = ((a.stack === null) === (b.stack === null))
      && (a.stack === null ? a.err === b.err : (a.stack.length === b.stack.length && a.stack.every((x, i) => x === b.stack[i])));
    if (!eq) { mainFail++; if (mainFail <= 5) log('  main-diff fail t', t, 'aerr', a.err, 'berr', b.err); }
  }
  log('GATE4 whole-main differential:', (mainTotal - mainFail) + '/' + mainTotal, 'pass, fail', mainFail);

  const allPass = rtExact && badBodies.length === 0 && sub === 0 && cseFail === 0 && mainFail === 0
    && bodyContentOk && newIdsPresent && (subUnchangedByteEq === subUnchangedTotal);
  return { allPass, rtExact, badBodies, sub, cseFail, mainFail, bodyContentOk, newIdsPresent, subUnchangedByteEq, subUnchangedTotal };
}

// -----------------------------------------------------------------------------
// runPass: the whole deterministic pass, as a pure function of input bytes.
// Returns { origLen, factored, factoredLen, net, chosen, ctx, d, applied }.
// -----------------------------------------------------------------------------
function runPass(origBytes) {
  const d = dissect(origBytes);
  const ctx = buildStreams(d);
  const contents = censusContents(ctx);
  const rejected = danglingFilter(contents, ctx);
  // DYNAMIC first-free id: existing bodies occupy ids up to max(d.order); new
  // factorings must start ABOVE them, so a second+ pass over an already-factored
  // program does not collide with the ids the previous pass created.
  const firstId = (d.order.length ? Math.max(...d.order) : FIRST_FREE_ID - 1) + 1;
  const chosen = greedyPack(contents, rejected, ctx, firstId);
  const applied = applyFactorings(d, ctx, chosen);
  return {
    origLen: origBytes.length,
    factored: applied.factored,
    factoredLen: applied.factored.length,
    net: applied.factored.length - origBytes.length,
    predictedNet: chosen.reduce((a, c) => a + c.net, 0),
    rejectedCount: rejected.size,
    chosen, ctx, d, applied,
  };
}

// invoke_cse is deterministic but NOT idempotent: splitting a marshalling stream in
// pass N can EXPOSE a nested common sub-subsequence that only becomes a cross-body
// repeat once its enclosing runs are separate streams (empirically −13 B on the crown,
// pass 2). So iterate the pass to a FIXPOINT — until a pass factors nothing. Each pass
// is a sound invoke_cse rewrite (Stackcert.InvokeCSE), so the composition is sound.
// `gate:true` verifies EVERY pass (round-trip + differentials) so the whole chain is checked.
function runPassFixpoint(origBytes, { gate = false, maxPasses = 20 } = {}) {
  let cur = origBytes;
  const passes = [];
  let allPass = true;
  for (let iter = 1; iter <= maxPasses; iter++) {
    const r = runPass(cur);
    if (r.chosen.length === 0) break;          // fixpoint reached
    if (gate) {
      const g = runGates(cur, r.factored, r.d, r.applied, r.ctx, { quiet: true });
      r.gates = g;
      if (!g.allPass) allPass = false;
    }
    passes.push(r);
    cur = r.factored;
  }
  return {
    factored: cur, passes, allPass,
    origLen: origBytes.length, factoredLen: cur.length, net: cur.length - origBytes.length,
    totalPredicted: passes.reduce((a, p) => a + p.predictedNet, 0),
  };
}

function loadHex(path) { return Uint8Array.from(Buffer.from(readFileSync(path, 'utf8').trim(), 'hex')); }

function reportFactorings(r) {
  console.log(`crown ${r.origLen}B -> factored ${r.factoredLen}B   (net ${r.net}B, predicted ${r.predictedNet}B)`);
  console.log(`dangling-const-push contents rejected: ${r.rejectedCount}`);
  console.log(`factorings applied: ${r.chosen.length}  ids ${r.chosen.map((c) => c.id).join(',')}`);
  for (const c of r.chosen) {
    console.log(`  id${c.id}  net=${c.net}B  ops=${c.L}  B=${c.B}  K=${c.K}  sites=${JSON.stringify(c.loc)}`);
  }
}

// =============================================================================
// SELF-CHECK: reproduce the BN254 crown result 4818 -> 4359, gates green.
// The 4818-locking crown ships alongside the tool (../singleton-5177-...hex).
// =============================================================================
const SELFCHECK_INPUT = join(HERE, '..', 'singleton-5177-locking4818-marshcse.hex');
const SELFCHECK_EXPECT_LEN = 4346;   // fixpoint (pass1 -> 4359, pass2 -> 4346)
const SELFCHECK_EXPECT_INPUT_LEN = 4818;

function selfcheck() {
  console.log('=== cse_pass --selfcheck : BN254 crown 4818 -> 4346 (fixpoint) ===');
  console.log('input:', SELFCHECK_INPUT);
  const bytes = loadHex(SELFCHECK_INPUT);
  if (bytes.length !== SELFCHECK_EXPECT_INPUT_LEN) {
    console.error(`FAIL: input crown is ${bytes.length}B, expected ${SELFCHECK_EXPECT_INPUT_LEN}B`);
    return 1;
  }
  const r = runPassFixpoint(bytes, { gate: true });
  r.passes.forEach((p, i) => { console.log(`\n-- pass ${i + 1} --`); reportFactorings(p); });
  console.log(`\nfixpoint: ${r.passes.length} reducing pass(es), ${r.origLen}B -> ${r.factoredLen}B (net ${r.net}B)`);
  const lenOk = r.factoredLen === SELFCHECK_EXPECT_LEN;
  console.log(`byte-count check: ${r.factoredLen} === ${SELFCHECK_EXPECT_LEN} ? ${lenOk}`);
  console.log('\n==== SELFCHECK VERDICT ====');
  console.log(`reproduces ${SELFCHECK_EXPECT_LEN}B: ${lenOk} | every pass gated: ${r.allPass}`);
  const ok = lenOk && r.allPass;
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
    console.error('usage: node cse_pass.mjs <in.hex> <out.hex> [--gate]');
    console.error('       node cse_pass.mjs --selfcheck');
    process.exit(2);
  }
  const [inPath, outPath] = positional;
  const bytes = loadHex(inPath);
  const r = runPassFixpoint(bytes, { gate });   // iterate to fixpoint (CSE is not idempotent)
  writeFileSync(outPath, Buffer.from(r.factored).toString('hex'));
  r.passes.forEach((p, i) => { console.log(`-- pass ${i + 1} --`); reportFactorings(p); });
  console.log(`fixpoint: ${r.passes.length} reducing pass(es), ${r.origLen}B -> ${r.factoredLen}B (net ${r.net}B); wrote ${outPath}`);

  if (gate) {
    console.log('\n==== GATE VERDICT ====');
    console.log('every pass gated (round-trip + differentials) all-pass:', r.allPass);
    process.exit(r.allPass ? 0 : 1);
  }
  process.exit(0);
}

main();
