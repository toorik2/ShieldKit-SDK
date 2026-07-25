// manifest.mjs — the per-run TRUST REPORT (mirrors LeanBCH TRUST_MANIFEST's three tiers).
//
// The optimizer must never claim more than it proves. Output trust = MIN(parse tier, transform
// tier): every applied transform is PROVEN (a named LeanBCH.Opt theorem), the emit codec is
// PROVEN, but the input parse is an ORACLE validated per-run by the gate. So a run is only as
// trustworthy as its weakest link — this report states each link explicitly, and the CLI refuses
// to emit output unless the gate passes at the strength the report claims.
//
// Composed from machine facts (which passes ran, the gate verdict, the dialect's parse
// certification), not prose — the same discipline as LeanBCH/tools/manifest/gen.mjs.

// Each bytecode pass -> its LeanBCH.Opt soundness theorem (the PROVEN tier). Format-agnostic:
// proved over abstract `Op α` blocks, so they hold for any dialect.
export const PASS_THEOREMS = {
  cse: ['LeanBCH.Opt.InvokeCSE.invoke_cse'],
  fold: ['LeanBCH.Opt.FoldTable (L<=4 window-complete)', 'LeanBCH.Opt.Peephole (L5 curated)'],
  'move-arrange': ['LeanBCH.Opt.schedule_refines', 'LeanBCH.Opt.schedule_refines_move_cond'],
};
export const EMIT_THEOREM = 'LeanBCH.Opt.Codec.parse_encode';

const TIER = { PROVEN: 3, VALIDATED: 2, ORACLE: 1 };
const tierName = (n) => Object.keys(TIER).find((k) => TIER[k] === n);

/** An honest one-line claim: name each link's status; the weakest link is whichever is lowest. */
function claimFor(outputTrust, parseTier, transformTier, parseCert) {
  if (outputTrust === 'PROVEN')
    return 'semantics-preserving by the named LeanBCH.Opt theorems; parse Lean-proven — PROVEN end to end.';
  if (transformTier === 'PROVEN')
    // transforms proven; the only non-proven link is the parse (self-certified this run, not yet Lean).
    return `transforms are semantics-preserving by the named LeanBCH.Opt theorems + Codec.parse_encode; `
      + `the input PARSE is per-run ${parseCert} (not yet Lean-proven) ⇒ overall ${outputTrust}.`;
  return `contains an UNPROVEN pass ⇒ DIFFERENTIAL-VALIDATED only (overall ${outputTrust}).`;
}

/** Build the per-run trust report.
 *  @param dialect       the active dialect (its `name` + parse certification level).
 *  @param parseCert     'round-trip-byte-exact' | 'structural-only'.
 *  @param passes        [{name, bytesRemoved}] applied, in order.
 *  @param gate          {check1, check2, check3, strength, trials} | null (null = not gated).
 *  @param cost          {inBytes, outBytes, ...} summary (optional).
 *  @param emitSafety    'ok' | 'refused-in-place' | 'def-region-only'.
 */
export function buildReport({ dialect, parseCert, passes = [], gate = null, cost = null, emitSafety = 'ok' }) {
  const transforms = passes.map((p) => ({
    pass: p.name, bytesRemoved: p.bytesRemoved ?? null,
    theorems: PASS_THEOREMS[p.name] || ['(no theorem — UNPROVEN pass)'],
    tier: PASS_THEOREMS[p.name] ? 'PROVEN' : 'ORACLE',
  }));
  // parse tier: round-trip-byte-exact self-certifies the oracle up to VALIDATED; structural stays ORACLE.
  const parseTier = parseCert === 'round-trip-byte-exact' ? 'VALIDATED' : 'ORACLE';
  // transform tier: PROVEN iff every applied pass has a theorem (+ the emit codec is proven).
  const transformTier = transforms.every((t) => t.tier === 'PROVEN') ? 'PROVEN' : 'ORACLE';
  const outputTrust = tierName(Math.min(TIER[parseTier], TIER[transformTier]));

  return {
    tool: 'leanbch-optimizer',
    dialect: dialect?.name ?? 'unknown',
    parse: { tier: parseTier, certification: parseCert, note: 'input parse is an oracle; the gate re-validates it per run' },
    emit: { tier: 'PROVEN', theorem: EMIT_THEOREM },
    transforms,
    gate: gate ? {
      roundTripByteExact: gate.check1 ?? null,
      differential: gate.check2 ?? null,
      e2eAcceptReject: gate.check3 ?? null,
      strength: gate.strength ?? null,
      trials: gate.trials ?? null,
    } : { note: 'not gated (report-only run)' },
    cost: cost ?? null,
    emitSafety,
    // the bottom line — never stronger than the weakest link:
    outputTrust,
    claim: claimFor(outputTrust, parseTier, transformTier, parseCert),
  };
}

export function printReport(r) {
  console.log(`── trust report (dialect: ${r.dialect}) ──`);
  console.log(`  output trust: ${r.outputTrust}   emit-safety: ${r.emitSafety}`);
  console.log(`  parse: ${r.parse.tier} (${r.parse.certification})   emit: ${r.emit.tier} (${r.emit.theorem})`);
  for (const t of r.transforms) console.log(`  transform ${t.pass}: ${t.tier}  [${t.theorems.join(', ')}]${t.bytesRemoved != null ? `  -${t.bytesRemoved}B` : ''}`);
  if (r.gate && r.gate.roundTripByteExact != null) console.log(`  gate: round-trip=${r.gate.roundTripByteExact} differential=${r.gate.differential} e2e=${r.gate.e2eAcceptReject} (${r.gate.strength})`);
  console.log(`  ⇒ ${r.claim}`);
}
