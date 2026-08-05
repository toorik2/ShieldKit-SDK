#!/usr/bin/env node
// passes/movearrange.mjs — the move-arrange (DAG-reschedule) pass.
//
// Sound by LeanBCH.Opt `schedule_refines` ∪ `schedule_refines_move_cond`: it decompiles each body +
// main into the block-DAG IR, then for each block emits the SMALLER of {rescheduled, original ops} —
// both of which reproduce the exact entry→exit main+alt layout, so any per-block mix is
// semantics-preserving by construction. Unlike fold/cse (byte-golf), this cuts EXECUTED movement ops
// (PICK/ROLL/DROP — the fp12 shuffle storm), which lowers OP-COST — the lever for the op-pad-bound
// mass. Framing (defs, minted invokes) goes through the active dialect via core/program.
//
// STATUS / LIMITS (honest): this pass targets the fp-verifier opcode set. Two boundaries vs the
// fully-general fold/cse passes:
//   1. DECOMPILER COVERAGE — core/decompile models the opcodes the verifier uses; a program using an
//      unmodeled shuffle (e.g. OP_3DUP 0x6f) throws "unhandled opcode". Completing the decompiler's
//      opcode table generalizes it.
//   2. ARITY PROBE COST — probing every subroutine by running it 31x on the uncapped VM is slow on the
//      fp tower (minutes). Pass a CACHED arity (--arity a.json, `{id:{in,out}}`) to skip probing — the
//      intended workflow (probe once, reuse), fast + deterministic.
//
//   node movearrange.mjs <in.hex> <out.hex> [--gate] [--arity a.json]   (--arity strongly recommended)
import { readFileSync, writeFileSync } from 'node:fs';
import { serialize, parse } from '../core/asm.mjs';
import { dissect, probeArity, rebuild, decompileProgram, recompileProgram } from '../core/program.mjs';
import { decompile } from '../core/decompile.mjs';
import { optimizeItems } from '../core/arrange.mjs';

/** Reschedule every body + main, choosing per block the smaller of {sched, orig}. Returns bytes.
 *  `arityCache` (optional `{id:{in,out}}`) skips the slow probe. */
export function moveArrange(bytes, arityCache = null) {
  const d = dissect(bytes);
  const arity = arityCache || probeArity(d);
  const override = new Map();
  for (const id of d.order) {
    const items = decompile(d.bodies.get(id), arity, arity[id].in, { label: 'def#' + id });
    const { bytes: b } = optimizeItems(items, arity, 'sched', { peephole: true });
    override.set(id, b);
  }
  const mainItems = decompile(serialize(d.mainOps), arity, 10, { label: 'main' });
  const { bytes: mainOpt } = optimizeItems(mainItems, arity, 'sched', { peephole: true });
  return { out: rebuild(d, override, mainOpt), d, arity };
}

// ---- CLI ----
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const gate = args.includes('--gate');
  const ai = args.indexOf('--arity');
  const arityCache = ai >= 0 ? JSON.parse(readFileSync(args[ai + 1], 'utf8')) : null;
  const [inPath, outPath] = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--arity');
  if (!inPath || !outPath) { console.error('usage: node movearrange.mjs <in.hex> <out.hex> [--gate] [--arity a.json]'); process.exit(2); }
  const bytes = Uint8Array.from(Buffer.from(readFileSync(inPath, 'utf8').trim().replace(/\s/g, ''), 'hex'));
  const { out, d, arity } = moveArrange(bytes, arityCache);
  // SOUNDNESS GATE: identity round-trip must reproduce the input byte-exact (proves the block
  // partition is faithful); the per-block min(sched,orig) is layout-equivalent by construction.
  if (gate) {
    const ir = decompileProgram(d, arity);
    const { bytes: rt } = recompileProgram(d, ir, arity);
    const exact = Buffer.from(rt).equals(Buffer.from(bytes));
    console.log(`move-arrange GATE: identity round-trip byte-exact = ${exact}`);
    if (!exact) { console.error('✗ round-trip NOT byte-exact — refusing'); process.exit(1); }
  }
  writeFileSync(outPath, Buffer.from(out).toString('hex') + '\n');
  console.log(`move-arrange: ${bytes.length} B -> ${out.length} B (net ${out.length - bytes.length} B); wrote ${outPath}`);
}
