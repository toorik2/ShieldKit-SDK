#!/usr/bin/env node
// tools/manifest/gen.mjs — generate TRUST_MANIFEST.md from the MACHINE-CHECKED facts.
//
// The trusted base of a formal artifact should be readable off the tree, not asserted in prose that
// drifts. This composes three computed sources into one skeptic-facing document:
//   • Meta/necessity.json   — the necessity analyzer's computed proof-term closure: the headline
//                             theorems, their axiom footprints, and every module's LOAD-BEARING /
//                             REFERENCE-PROOF / VALIDATED-EXECUTABLE classification.
//   • tools/health/index.json — the health map's declaration/claim census.
//   • tools/health/katcount.mjs — the tree-wide build-time KAT count enforced by CI.
// The three TIERS (PROVEN / VALIDATED-not-proven / ASSUMED-oracle) and per-headline axioms are pulled
// live; only the trust NARRATIVE (why each validated surface is trusted, the oracle contract) is prose.
//
// Regenerate:  node tools/manifest/gen.mjs   (writes TRUST_MANIFEST.md at the repo root)
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const nec = JSON.parse(readFileSync(join(ROOT, 'Meta', 'necessity.json'), 'utf8'));
const health = JSON.parse(readFileSync(join(ROOT, 'tools', 'health', 'index.json'), 'utf8'));

// The health map's `claims` field is a prose-keyword census, not a KAT census.  Invoke the
// same counter used by the conservation gate so the manifest's build-time-check number has
// exactly the same meaning as CI's number.
function countBuildTimeKats() {
  const output = execFileSync(process.execPath, [join(ROOT, 'tools', 'health', 'katcount.mjs')], {
    encoding: 'utf8',
  }).trim();
  if (!/^\d+$/.test(output)) throw new Error(`unexpected katcount output: ${JSON.stringify(output)}`);
  return Number.parseInt(output, 10);
}
const katCount = countBuildTimeKats();

// ── headline grouping (the ONLY hand-maintained bit: which promised area each headline belongs to) ──
const AREAS = [
  ['Consensus VM — self-hardening + cost certificate', [
    'LeanBCH.VM.runExt_WF_final', 'LeanBCH.VM.runScript_fuel_suffices_final',
    'LeanBCH.VM.verifyInput_cost_within_budget']],
  ['Optimizer — semantics-preserving size reduction', [
    'LeanBCH.Opt.schedule_refines', 'LeanBCH.Opt.schedule_refines_move_cond',
    'LeanBCH.Opt.whole_program_end_to_end', 'LeanBCH.Opt.bridge_block',
    'LeanBCH.Opt.decompile_end_to_end', 'LeanBCH.Opt.emit_ops_typed']],
  ['Optimizer — size FLOORS + INVOKE/CSE soundness', [
    'LeanBCH.Opt.NlcsFloor.movement_lower_bound_nlcs',
    'LeanBCH.Opt.Providers.invoke_const_provider', 'LeanBCH.Opt.InvokeCSE.invoke_cse']],
  ['Rewrite catalogs — sampled (rename/removal caught)', [
    'LeanBCH.Opt.FoldTable.u_DUP_SWAP__DUP', 'LeanBCH.Opt.FoldTable.u_2PICK_NIP__DROP_OVER',
    'LeanBCH.Opt.FoldTable.c_4PICK_TWODROP__DROP_k5', 'LeanBCH.Opt.FoldTable.c_TWODUP_TWODROP__EMPTY_k2',
    'LeanBCH.Opt.over_over', 'LeanBCH.Opt.roll2_rot']],
  ['Real-VM optimizer bridge — capstones (C1)', [
    'LeanBCH.Opt.PushButton.push_button_arith', 'LeanBCH.Opt.PushButtonFull.push_button',
    'LeanBCH.Opt.PushButtonBytes.push_button_arith_bytes',
    'LeanBCH.Opt.OriginalBytes.push_button_arith_bytes_symmetric']],
];

const ha = nec.headlineAxioms || {};
const mods = nec.modules || {};
const byBucket = (b) => Object.entries(mods).filter(([, v]) => v.bucket === b).sort((a, c) => a[0] < c[0] ? -1 : 1);
const short = (n) => n.replace(/^LeanBCH\./, '');
const axCell = (name) => (ha[name] ? ha[name].map(a => `\`${a}\``).join(', ') : '—');

const loadBearing = byBucket('LOAD-BEARING');
const refProof = byBucket('REFERENCE-PROOF');
const validatedExec = byBucket('VALIDATED-EXECUTABLE');
const lbDecls = (nec.closureLeanBCH || []).length;

let m = '';
const w = (s = '') => { m += s + '\n'; };

w('# LeanBCH — TRUST MANIFEST');
w();
w('> **GENERATED** by `tools/manifest/gen.mjs` from `Meta/necessity.json` (necessity analyzer) +');
w('> `tools/health/index.json` (health map) + `tools/health/katcount.mjs` (KAT counter). **DO NOT EDIT.**');
w('> Regenerate: `node tools/manifest/gen.mjs`.');
w();
w('What may a skeptic take on trust, and on what basis? LeanBCH is an *executable* model, so its claims');
w('fall in exactly three tiers. Everything below is **computed** from the kernel-checked proof terms —');
w('the load-bearing set is not asserted, it is the transitive proof-term closure of the headlines in');
w('`Meta/Headlines.lean`. A legal refactor never changes it (CI gate: `Meta/necessity.json` byte-stable).');
w();
w(`**At a glance:** ${lbDecls} declarations are load-bearing across ${loadBearing.length} modules; the entire`);
w(`proven base rests on exactly these kernel axioms: ${(nec.axioms || []).map(a => `\`${a}\``).join(', ')}`);
w(`(\`propext\` + \`Quot.sound\` + \`Classical.choice\` — the standard classical Lean base; **no** \`sorryAx\`,`);
w('`native_decide`, or `ofReduceBool`). Independently re-checkable: `#print axioms <headline>`.');
w();

w('## Tier 1 — PROVEN (machine-checked; kernel-verified)');
w();
w('Each theorem below is a promised deliverable, verified by the Lean kernel. The axiom column is the');
w('theorem\'s *own* footprint (computed per-headline). Any theorem renamed/removed ⇒ CI fails immediately.');
w();
for (const [area, names] of AREAS) {
  const present = names.filter(n => n in ha);
  if (!present.length) continue;
  w(`### ${area}`);
  w();
  w('| Theorem | Axiom footprint |');
  w('| --- | --- |');
  for (const n of present) w(`| \`${short(n)}\` | ${axCell(n)} |`);
  w();
}
w('> **Honest scope of the "real-VM bridge" capstones (red-team):** of the C1 group, only');
w('> `OriginalBytes.push_button_arith_bytes_symmetric` runs BOTH the original and the optimized');
w('> bytecode through the genuine consensus VM (`parse` → `VM.run` → `stepInstr`) and proves they');
w('> agree. `PushButton.push_button_arith` / `PushButtonBytes.push_button_arith_bytes` run the');
w('> OPTIMIZED side on the real VM but the ORIGINAL side on the abstract `Opt.run` machine (sound,');
w('> because both are gated by an acceptance hypothesis — but not "both on real hardware"). And');
w('> `schedule_refines` / `whole_program_end_to_end` / `decompile_end_to_end` / `emit_ops_typed` are');
w('> proven over the ABSTRACT value machine (α-generic), not `stepInstr`. All are non-vacuous (they');
w('> fire on a concrete block: 6+2→8 verified) and axiom-clean; the framing above is the honest split.');
w();
const orphanHeadlines = Object.keys(ha).filter(n => !AREAS.some(([, ns]) => ns.includes(n)));
if (orphanHeadlines.length) {
  w('### (ungrouped headlines — add to a group in tools/manifest/gen.mjs)');
  w();
  for (const n of orphanHeadlines) w(`- \`${short(n)}\` — ${axCell(n)}`);
  w();
}
if ((nec.notFoundHeadlines || []).length) {
  w(`> ⚠ **${nec.notFoundHeadlines.length} declared headline(s) not found in the env** (fix Headlines.lean): ` +
    nec.notFoundHeadlines.map(n => `\`${n}\``).join(', '));
  w();
}

w('## Tier 2 — VALIDATED (modeled + checked, NOT proven)');
w();
w('These surfaces are trusted by *external agreement*, not by a Lean proof — the same status CompCert');
w('gives its `Valex` re-checker and EELS/KEVM give "the spec is the reference implementation".');
w();
w('**Executable model surfaces** (definitions only — no in-tree proof; exercised by the conformance runner');
w('and the libauth differential):');
w();
w('| Module | defs | Validated by |');
w('| --- | --: | --- |');
const VAL_BY = {
  'LeanBCH.Tx.Wire': 'round-trip vs the vmb corpus + `conformance/Runner`',
};
const modelSurfaces = validatedExec.filter(([n]) => !n.startsWith('LeanBCH.Validation.'));
const valLayer = validatedExec.filter(([n]) => n.startsWith('LeanBCH.Validation.'));
for (const [n, v] of modelSurfaces) w(`| \`${short(n)}\` | ${v.defs} | ${VAL_BY[n] || 'conformance/differential'} |`);
w();
w(`**The \`LeanBCH.Validation.*\` layer** (${valLayer.length} modules) — known-answer tests extracted out of the`);
w('model files so the model reads as pure semantics; each `#eval`/`#guard`/`example` still executes under');
w('`lake build LeanBCHValidation`, and the KAT-conservation gate (`tools/health/katcount.mjs`) proves none');
w('was dropped in the move. Includes the libauth cost differential (`Validation.CostDifferential`).');
w();
w('**The validation harness itself** (trusted expected-values — the single differential "trust seam"):');
w();
w('- **@bitauth/libauth 3.1.0-next.8** — the reference JS VM; LeanBCH\'s numeric cost pins are diffed');
w('  against it (not proven equal). Pinned dependency.');
w('- **The official `vmb_test` conformance corpus** — streamed through the VM by `conformance/Runner.lean`');
w('  (`lake build vmbconf <corpus-dir>`). **External**: passed as a path arg, NOT copied into or pinned');
w('  in this repo (so the RESULTS.md pass-counts are reproduced against your own corpus checkout, not');
w('  gated in CI). The **signature op-cost tier** (`signatureCheckCount`×26000, sig signing-serialization');
w('  hash-iters) is NOT numerically validated: the cost-differential vectors are all `sc=0`, and corpus');
w('  sig families NULLFAIL under the reject-oracle before any cost is compared — so that tier is');
w('  soundness-safe (over-billing never wrong-accepts) but currently **unvalidated**, not "checked elsewhere".');
w(`- **${katCount} build-time KAT checks** (\`#eval\`/\`#guard\`/\`example\`) across \`LeanBCH/**/*.lean\` —`);
w('  the exact current count used by the KAT-conservation gate (`tools/health/katcount.mjs`), distinct');
w('  from the health map’s prose `claims` census.');
w();
w('**Proven, but not headline-gated** (`REFERENCE-PROOF`: real theorems, not in any headline\'s closure —');
w('kept on purpose; a silent break is *not* caught by the axiom gate):');
w();
w('| Module | theorems | Why it is not a headline |');
w('| --- | --: | --- |');
const REF_WHY = {
  'LeanBCH.VM.Standard': 'relay-policy (standardness) ≠ consensus; a separate proven model, validated by conformance',
  'LeanBCH.Opt.Passthrough': 'abstract PASS-1 justification; the composition re-derives it inline (in `schedule_refines`)',
  'LeanBCH.Opt.EmitConcreteHash': 'deferred hash capstone (probing SHA-256 forces kernel reduction; `native_decide` forbidden)',
  'LeanBCH.Opt.AcceptExample': 'a worked end-to-end witness on one real rewrite (demonstration, not a general claim)',
  'LeanBCH.Cost.Spine': 'reference cost-spine lemmas, superseded by the load-bearing cost model',
};
for (const [n, v] of refProof) w(`| \`${short(n)}\` | ${v.theorems} | ${REF_WHY[n] || 'proven; complementary to the headline set'} |`);
w();

w('## Tier 3 — ASSUMED (opaque oracle; the ONLY unproven trust input)');
w();
w('- **secp256k1 signature verification** — `LeanBCH/Oracle.lean` `structure Secp256k1` (the whole file,');
w('  ~40 lines; re-exported by `LeanBCH.Crypto` so importers are unchanged). An EXPLICIT parameter');
w('  structure, **not** an axiom: the VM\'s `OP_CHECKSIG*` arm receives a `Secp256k1` value and calls it.');
w('  It feeds **only** the accept/reject decision and **never any cost metric** — so no cost/limit');
w('  theorem depends on it. No honest implementation is provided in-Lean (consensus verification lives');
w('  in libsecp256k1). This one file is the single point a reader must take on faith.');
w();
w('## Code vs proof (the executable-model ↔ proof seam)');
w();
w('Each module\'s declarations split into DEFS (the executable model — what *runs*) and THEOREMS (the');
w('proof — what is *guaranteed*). This is CompCert\'s `Pass.v`/`Passproof.v` legibility, but computed');
w('from the kernel rather than asserted by filename. Rolled up by layer:');
w();
w('| Layer | modules | defs (code) | theorems (proof) |');
w('| --- | --: | --: | --: |');
const LAYERS = [
  ['VM (consensus semantics)', 'LeanBCH.VM.'], ['Optimizer', 'LeanBCH.Opt'],
  ['Cost model', 'LeanBCH.Cost.'], ['Tx / sighash / encoding', 'LeanBCH.Tx.'],
  ['Validation (KATs)', 'LeanBCH.Validation'], ['Oracle (assumed)', 'LeanBCH.Oracle'],
];
const seen = new Set();
for (const [label, pre] of LAYERS) {
  const ms = Object.entries(mods).filter(([n]) => n === pre.replace(/\.$/, '') || n.startsWith(pre));
  ms.forEach(([n]) => seen.add(n));
  if (!ms.length) continue;
  const d = ms.reduce((a, [, v]) => a + v.defs, 0), t = ms.reduce((a, [, v]) => a + v.theorems, 0);
  w(`| ${label} | ${ms.length} | ${d} | ${t} |`);
}
const restMods = Object.entries(mods).filter(([n]) => !seen.has(n));
if (restMods.length) {
  const d = restMods.reduce((a, [, v]) => a + v.defs, 0), t = restMods.reduce((a, [, v]) => a + v.theorems, 0);
  w(`| (core: Number/Opcode/Crypto/…) | ${restMods.length} | ${d} | ${t} |`);
}
w();
w('The optimizer is the CompCert-style layer — a *pass* (code) paired with its *proof* — kept in-tree as');
w('its own build target (not a separate package: the `LeanBCH.Opt.*` public API is frozen for');
w('verifier.cash/stackcert, and lake can\'t share that namespace across packages). Its VM boundary is');
w('lint-enforced: `LeanBCH.Opt.*` reaches the VM through 5 modules only. Per Opt module:');
w();
w('| Optimizer module | defs (pass) | theorems (proof) |');
w('| --- | --: | --: |');
const optMods = Object.entries(mods).filter(([n]) => n === 'LeanBCH.Opt' || n.startsWith('LeanBCH.Opt.'))
  .sort((a, b) => (b[1].defs + b[1].theorems) - (a[1].defs + a[1].theorems)).slice(0, 12);
for (const [n, v] of optMods) w(`| \`${short(n)}\` | ${v.defs} | ${v.theorems} |`);
w(`| … (${Math.max(0, Object.keys(mods).filter(n => n.startsWith('LeanBCH.Opt')).length - optMods.length)} more Opt modules) | | |`);
w();
w('## How a skeptic checks each tier');
w();
w('1. **PROVEN** — `bash tools/opt-ci/verify.sh` (builds all targets, 0 `sorry`, axiom gate over every');
w('   headline, fold-table reproducible, closure byte-stable). Spot-check any theorem: `#print axioms <name>`.');
w('2. **VALIDATED** — `lake build vmbconf && ./…/vmbconf <corpus>` (conformance) and the libauth cost');
w('   differential (`LeanBCH/Validation/CostDifferential.lean`). Disagreement is a bug in *this* model.');
w('3. **ASSUMED** — read one structure in `Oracle.lean`; confirm no cost metric reads its result.');
w();
w('---');
w(`_Generated from ${loadBearing.length} load-bearing + ${refProof.length} reference-proof + ${validatedExec.length} validated-executable modules; ${Object.keys(ha).length} headlines._`);

writeFileSync(join(ROOT, 'TRUST_MANIFEST.md'), m);
console.log(`TRUST_MANIFEST.md written: ${loadBearing.length} load-bearing / ${refProof.length} reference-proof / ${validatedExec.length} validated-executable modules; ${Object.keys(ha).length} headlines; axioms ${(nec.axioms||[]).join(', ')}`);
