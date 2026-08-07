// ★ THE REALITY GATE ★
//
// Structural enforcement of the "NO PLACEHOLDERS / NO MOCK DATA EVER" rule.
//
// Every "sub-100k / banked / achieved / score=N" claim about an assembled verifier
// MUST be backed by a passing `assertAllInputsReal` report. If it is not, the number
// is a PROJECTION, not a result — and must be labelled as such.
//
// Why this exists: this project has repeatedly been bitten by measurements that LOOKED
// real but were backed by placeholder inputs — mkTail length-model fillers, zero-fill
// dummy unlockings, phantom-UTXO seam commitments. Each produced a score/wire number
// that no VM actually accepts. The rule "no placeholders" was stated but not enforced;
// this file makes it a runnable gate that agents/scripts import instead of self-reporting.
//
// GROUND TRUTH = VM ACCEPTANCE. The gate drives every input through the real BCH-2026 VM
// against its real siblings (and, for a token covenant, its real incoming token). An input
// is real iff the VM strictly accepts it. The `looksPlaceholder` heuristic below is ADVISORY
// ONLY — it never fails a VM-accepting input (an early over-eager heuristic false-flagged
// real seam-narrowed witnesses that the VM accepts; the VM, not a byte pattern, decides).
import { createRealVm, evaluatePair, type Bch2026Vm } from './vm.js';

export interface RealTxInput {
  lockingBytecode: Uint8Array;
  unlockingBytecode: Uint8Array;
  valueSatoshis?: bigint;
  /** Optional introspection fields for fixed deployment profiles. */
  sequenceNumber?: number;
  outpointTransactionHash?: Uint8Array;
  /** Incoming token covenant state (the UTXO this input spends), if it is a token-covenant
   * redeem that reads tx.inputs[i].nftCommitment. Without it such an input rejects at covIn. */
  token?: { category: Uint8Array; capability: 'none' | 'mutable' | 'minting'; commitment: Uint8Array };
}

export interface InputReality {
  index: number;
  accepts: boolean;
  reason: string;
  unlockingLen: number;
  /** advisory: the unlocking matches a known filler shape (does NOT by itself fail the input). */
  looksFiller: boolean;
}

export interface RealityReport {
  ok: boolean;
  inputCount: number;
  perInput: InputReality[];
  /** Σ(locking+unlocking) over all inputs — the scored mass. ONLY trustworthy when ok===true. */
  scoreBytesRaw: number;
  failures: string[];
  /** VM-accepting inputs that still look like filler — inspect these even though they passed. */
  warnings: string[];
}

/**
 * ADVISORY filler-shape detector (empty / all-zero / long constant run = mkTail/length-model).
 * NOT the gate — VM acceptance is. Used only to enrich the message on a rejecting input and to
 * warn on the (rare) accepting-but-filler-looking case. Real canonical witnesses are
 * pseudorandom, so a very long constant run is worth a WARNING, never an automatic failure.
 */
export const looksPlaceholder = (u: Uint8Array): { placeholder: boolean; reason: string } => {
  if (u.length === 0) return { placeholder: true, reason: 'empty unlocking' };
  if (u.every((byte) => byte === 0)) return { placeholder: true, reason: `all-zero unlocking (${u.length} B zero-fill dummy)` };
  let maxRun = 1;
  for (let i = 1, run = 1; i < u.length; i++) {
    run = u[i] === u[i - 1] ? run + 1 : 1;
    if (run > maxRun) maxRun = run;
  }
  if (maxRun >= 256) return { placeholder: true, reason: `${maxRun}-byte constant run (mkTail/length-model filler shape)` };
  return { placeholder: false, reason: '' };
};

/**
 * ★ THE REALITY GATE ★ — the single mandatory check before ANY "sub-100k / banked"
 * claim. Runs the REAL BCH-2026 VM (normal consensus limits) over EVERY input of the
 * assembled intra-tx — each input against its REAL siblings (and its real incoming token,
 * if a covenant) — and requires every input to strictly VM-ACCEPT. Throws, listing the
 * exact offending inputs, if any input REJECTS. A score/wire number not backed by a
 * passing report is a PROJECTION, never a result.
 */
export const assertAllInputsReal = (
  inputs: RealTxInput[],
  opts: { vm?: Bch2026Vm; label?: string; outputValueSatoshis?: bigint } = {},
): RealityReport => {
  if (inputs.length === 0) throw new Error('[REALITY GATE] no inputs supplied — nothing to verify');
  const vm = opts.vm ?? createRealVm();
  const siblings = inputs.map((i) => ({
    lockingBytecode: i.lockingBytecode,
    unlockingBytecode: i.unlockingBytecode,
    ...(i.valueSatoshis !== undefined ? { valueSatoshis: i.valueSatoshis } : {}),
    ...(i.sequenceNumber !== undefined ? { sequenceNumber: i.sequenceNumber } : {}),
    ...(i.outpointTransactionHash !== undefined ? { outpointTransactionHash: i.outpointTransactionHash } : {}),
    ...(i.token ? { token: i.token } : {}),
  }));
  const perInput: InputReality[] = inputs.map((inp, index) => {
    const filler = looksPlaceholder(inp.unlockingBytecode);
    const out = evaluatePair(vm, inp.lockingBytecode, inp.unlockingBytecode, undefined, {
      index,
      inputs: siblings,
      outputValueSatoshis: opts.outputValueSatoshis,
    });
    const reason = out.accepted
      ? filler.placeholder
        ? `VM-accepts BUT looks like filler (${filler.reason}) — inspect`
        : 'real+VM-accepts'
      : `VM REJECT: ${out.error ?? 'not accepted (bad final stack)'}${filler.placeholder ? ` [${filler.reason}]` : ''}`;
    return { index, accepts: out.accepted, reason, unlockingLen: inp.unlockingBytecode.length, looksFiller: filler.placeholder };
  });
  const failures = perInput.filter((p) => !p.accepts).map((p) => `input[${p.index}] (${p.unlockingLen} B unlock): ${p.reason}`);
  const warnings = perInput.filter((p) => p.accepts && p.looksFiller).map((p) => `input[${p.index}]: ${p.reason}`);
  const scoreBytesRaw = inputs.reduce((s, i) => s + i.lockingBytecode.length + i.unlockingBytecode.length, 0);
  const report: RealityReport = { ok: failures.length === 0, inputCount: inputs.length, perInput, scoreBytesRaw, failures, warnings };
  if (!report.ok) {
    throw new Error(
      `[REALITY GATE${opts.label ? ' — ' + opts.label : ''}] ${failures.length}/${inputs.length} input(s) REJECT — ` +
        `this measurement is NOT real, it is a PROJECTION:\n  ${failures.join('\n  ')}\n` +
        `  Fix: every input must be a real redeem that VM-accepts against its real siblings (pass a token{} for a covenant input). No mkTail, no zero-fill, no length-model, no component sums.`,
    );
  }
  return report;
};

/** Returns the scored byte mass ONLY if every input is real + VM-accepts; else throws. */
export const realScoreBytes = (inputs: RealTxInput[], label?: string): number =>
  assertAllInputsReal(inputs, { label }).scoreBytesRaw;
