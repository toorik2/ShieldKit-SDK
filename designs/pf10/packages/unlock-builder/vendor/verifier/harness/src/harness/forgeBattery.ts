// Reusable A1 FORGE BATTERY driver.
//
// Every one of the ~57 per-verifier forge scripts re-implements the SAME loop:
//   1. confirm each honest chunk (locking+unlocking, and its covenant/intraTx
//      surface) ACCEPTS on the real BCH-2026 consensus VM, then
//   2. for every tamper, mutate one chunk and assert the forged program REJECTS.
// A single accepting forgery (or a failing honest control) = A1 FAIL.
//
// This module factors that loop ONCE, wrapping the shared toolkit primitives
// (evaluatePair from ./vm.ts, tamperProof from ./tamper.ts) so no forge script
// hand-rolls createVirtualMachineBch2026 / tamper vectors again.
import { createRealVm, evaluatePair, type Bch2026Vm } from './vm.js';
import { tamperProof, tamperRunStepProof } from './tamper.js';
import type { Step } from './types.js';

/** One honest program under test: a Step (locking+unlocking + optional
 * covenant / intraTx context). Reuse the harness Step so a verifier's existing
 * scenario chunks feed straight in. */
export type ForgeChunk = Step;

/** Context handed to a tamper: the chunk to forge, its index, and the full
 * ordered chunk list (so cross-chunk forgeries — thread-escape to a sibling's
 * locking, covenant hand-off tampering — can be expressed). */
export interface TamperContext {
  index: number;
  chunk: ForgeChunk;
  chunks: readonly ForgeChunk[];
}

/**
 * A named forgery. `forge` returns the mutated program that MUST be rejected:
 *   - a single Step, or
 *   - a Step[] (a multi-step run; rejected iff at least one step rejects, mirroring
 *     the harness runRejects semantics), or
 *   - undefined to SKIP this chunk (e.g. a thread-escape has no meaning on a
 *     terminal chunk). Skipped pairs are not counted as forgeries.
 */
export interface Tamper {
  name: string;
  forge: (ctx: TamperContext) => Step | Step[] | undefined;
}

export interface ForgeRow {
  /** tamper name, or 'honest' for the control row */
  tamper: string;
  chunk: string;
  accepted: boolean;
  /** true for honest controls, false for forgeries */
  expectAccept: boolean;
  /** accepted === expectAccept */
  ok: boolean;
  operationCost: number;
  error?: string;
}

export interface ForgeBatteryResult {
  /** every honest control accepted AND every forgery rejected */
  pass: boolean;
  honestControls: number;
  honestFailures: number;
  forgeriesTested: number;
  /** forgeries that ACCEPTED — MUST be 0 */
  acceptingForgeries: number;
  /** per-tamper tally: tested vs as-expected */
  byTamper: Record<string, { tested: number; asExpected: number }>;
  rows: ForgeRow[];
}

export interface ForgeBatteryOptions {
  /** VM to evaluate on; defaults to the real BCH-2026 consensus VM (createRealVm). */
  vm?: Bch2026Vm;
  /** Judge acceptance by BSV OP_RETURN-terminator semantics instead of strict BCH. */
  bsv?: boolean;
}

const acceptsStep = (vm: Bch2026Vm, step: Step, bsv: boolean) => {
  const o = evaluatePair(vm, step.lockingBytecode, step.unlockingBytecode, step.covenant, step.intraTx);
  return { accepted: bsv ? o.bsvAccepted : o.accepted, operationCost: o.operationCost, error: o.error };
};

/** A forged run (one or more steps) rejects iff at least one of its steps rejects. */
const runOutcome = (vm: Bch2026Vm, forged: Step | Step[], bsv: boolean) => {
  const steps = Array.isArray(forged) ? forged : [forged];
  let accepted = true;
  let operationCost = 0;
  let error: string | undefined;
  for (const s of steps) {
    const r = acceptsStep(vm, s, bsv);
    operationCost += r.operationCost;
    if (!r.accepted) {
      accepted = false;
      error = r.error;
      break; // first rejecting step decides the run
    }
  }
  return { accepted, operationCost, error };
};

/**
 * Run the honest-accept + reject-each-tamper battery over `chunks` with `tampers`.
 * Returns a structured verdict; never throws on a forge failure (inspect `.pass`).
 * Use assertForgeBattery for the exit-1-on-fail wrapper CLI scripts want.
 */
export const runForgeBattery = (
  chunks: readonly ForgeChunk[],
  tampers: readonly Tamper[],
  options: ForgeBatteryOptions = {},
): ForgeBatteryResult => {
  const vm = options.vm ?? createRealVm();
  const bsv = options.bsv ?? false;
  const rows: ForgeRow[] = [];
  const byTamper: Record<string, { tested: number; asExpected: number }> = {};
  let honestControls = 0;
  let honestFailures = 0;
  let forgeriesTested = 0;
  let acceptingForgeries = 0;

  chunks.forEach((chunk, index) => {
    // honest control
    const h = acceptsStep(vm, chunk, bsv);
    honestControls += 1;
    if (!h.accepted) honestFailures += 1;
    rows.push({
      tamper: 'honest', chunk: chunk.label, accepted: h.accepted,
      expectAccept: true, ok: h.accepted, operationCost: h.operationCost, error: h.error,
    });

    // each forgery must reject
    for (const t of tampers) {
      const forged = t.forge({ index, chunk, chunks });
      if (forged === undefined) continue; // not applicable to this chunk
      const r = runOutcome(vm, forged, bsv);
      const ok = !r.accepted;
      forgeriesTested += 1;
      if (r.accepted) acceptingForgeries += 1;
      (byTamper[t.name] ??= { tested: 0, asExpected: 0 }).tested += 1;
      if (ok) byTamper[t.name]!.asExpected += 1;
      rows.push({
        tamper: t.name, chunk: chunk.label, accepted: r.accepted,
        expectAccept: false, ok, operationCost: r.operationCost, error: r.error,
      });
    }
  });

  return {
    pass: honestFailures === 0 && acceptingForgeries === 0,
    honestControls, honestFailures, forgeriesTested, acceptingForgeries, byTamper, rows,
  };
};

/**
 * The stock witness tamper: bit-flip inside a data push of the unlocking script
 * (delegates to the shared tamperProof). `nthLargest` selects which push (0 =
 * largest, the proof/witness blob). Returns undefined if the chunk has no data
 * push to tamper, so it is skipped rather than crashing the battery.
 */
export const witnessTamper = (nthLargest = 0, name = `witness-tamper[${nthLargest}]`): Tamper => ({
  name,
  forge: ({ index, chunk, chunks }) => {
    if (chunk.intraTx !== undefined) {
      try {
        return tamperRunStepProof(chunks, index, nthLargest);
      } catch {
        return undefined; // no data push at this rank
      }
    }

    let bad: Uint8Array;
    try {
      bad = tamperProof(chunk.unlockingBytecode, nthLargest);
    } catch {
      return undefined; // no data push at this rank
    }
    return { ...chunk, unlockingBytecode: bad };
  },
});

/** Pretty one-line-per-tamper summary for CLI output. */
export const formatForgeSummary = (r: ForgeBatteryResult): string => {
  const lines: string[] = ['=== FORGE BATTERY (real BCH-2026 consensus VM) ==='];
  for (const [name, v] of Object.entries(r.byTamper)) {
    lines.push(`  ${name.padEnd(28)} ${v.asExpected}/${v.tested} reject-as-expected`);
  }
  lines.push(`\nhonest controls: ${r.honestControls} (failures: ${r.honestFailures})`);
  lines.push(`accepting forgeries: ${r.acceptingForgeries}  (MUST be 0)`);
  lines.push(`\n=== RESULT: ${r.pass ? 'PASS — every forgery REJECTS, every honest control ACCEPTS' : `*** A1 FAIL: ${r.acceptingForgeries} accepting forgeries, ${r.honestFailures} honest failures ***`} ===`);
  return lines.join('\n');
};

/** CLI wrapper: run the battery, print the summary, and process.exit(1) on any
 * accepting forgery or honest failure (the contract every forge_battery.mjs wants). */
export const assertForgeBattery = (
  chunks: readonly ForgeChunk[],
  tampers: readonly Tamper[],
  options: ForgeBatteryOptions = {},
): ForgeBatteryResult => {
  const r = runForgeBattery(chunks, tampers, options);
  console.log(formatForgeSummary(r));
  if (!r.pass) process.exit(1);
  return r;
};
