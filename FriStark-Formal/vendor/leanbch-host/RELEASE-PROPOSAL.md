# LeanBCH — Release Proposal

**Status:** proposal, not a decision. Written 2026-07-21. Uncommitted by design.

**Evidence discipline.** Every claim below is either (a) verified by me this run, with the command or
`file:line` given, or (b) explicitly labelled as carried from an upstream analysis lane and NOT
re-verified. Nothing is asserted from recollection. Two facts in my own briefing turned out to be
wrong and are corrected in place (§0).

---

## 0. Corrections to the briefing I was given

Stating these first because the rest of the proposal depends on them.

1. **`vmbconf` IS built.** My briefing said `.lake/build/bin` holds only `planck_gold`. It holds
   `planck_gold`, `vmbconf`, `xcheck`, `xcheck_idx1`, `xcheck_idxN`. `vmbconf` is dated
   2026-07-20 13:22:39 (`ls -la --time-style=full-iso .lake/build/bin/`). The conformance runner is
   therefore *not* blocked on a build. It is blocked on the corpus: `git ls-files | grep -icE
   'vmb|corpus'` returns **0** — no vectors ship. The corpus lives outside the repo
   (`/home/toorik/Projects/bchd-src/txscript/data/vmb_tests` exists on this machine) and
   `conformance/run.mjs` takes its directory from `argv`.

2. **The `Opt/` severance boundary is one import wide, and I re-measured it.**
   `grep -rn '^import .*LeanBCH\.Opt' --include=*.lean .` filtered to non-`Opt` files yields exactly
   one cross-boundary hit: `Meta/Necessity.lean:12`. Everything else is `Opt/`-internal.

Measured sizes this run (`git ls-files`, `wc -l`): 95 tracked `.lean` / 35,291 lines total;
`LeanBCH/Opt/**` + `LeanBCH/Opt.lean` = 47 files / 23,469 lines (66.5%); non-Opt = 48 files /
11,822 lines. KATs: `node tools/health/katcount.mjs` → **313**, of which **24** are in seven
`LeanBCH/Opt/*` files → a severed release honestly counts **289**.

---

## 1. THE ASSET

### The honest answer has two parts, and they are not the same thing

**The most valuable asset is the consensus VM model** — `LeanBCH/VM/`, `LeanBCH/Cost/`,
`LeanBCH/Tx/`, `LeanBCH/Validation/`, `conformance/`. It is a fourth independent implementation of
BCH-2026 semantics, executable, differentially pinned, with a machine-checked resource-safety and
fuel core. It is the *engine*. Everything else worth releasing is something this engine produces.

**But it is not what should be released first.** What should ship first is a *finding plus a
deliverable*, not a repository:

> **The BCH ecosystem's shared conformance corpus (`vmb_test`) is structurally blind to operation-cost
> divergence — and here are vectors that close the hole.**

The sequencing argument is the whole recommendation, so it is worth stating plainly.

### Why the finding ships before the repo

A repository released as "a formalization of the BCH VM" is a **specification** offer. The BCH
ecosystem has not asked for one. The precedent that matters is KEVM versus EELS: KEVM is the more
rigorous artifact — a fully executable formal EVM semantics passing the official suite — and it was
not adopted as Ethereum's spec; EELS won because it *generates the fixtures clients run*. (Both
characterizations are lane-3 findings from fetched sources — `blog.ethereum.org/2023/08/29/eel-spec`
and `github.com/ethereum/execution-specs` were fetched; the KEVM side rests on search summaries and
is weaker evidence. I did not re-fetch either this run.)

Vectors, by contrast, are a **test** offer. Node implementers already consume `vmb_test`. A cost
vector is consumed with zero Lean exposure and zero adoption decision. Nobody has to believe
anything about Lean to run one.

And the finding is the only thing here that is *demonstrably* filling a real gap. I verified the
supporting structure myself: `conformance/cost/battery.txt` is 26 lines and `grep -c '89'` returns
**0** — the differential battery contains no OP_DEFINE vector, which is precisely why the OP_DEFINE
op-cost defect survived in it until commit `25f1265`.

⚠️ **The single most load-bearing empirical claim in this whole proposal is one I did NOT verify.**
Commit `25f1265`'s message asserts that `chip.functions` passes **556/556 both with and without** the
OP_DEFINE cost fix. That measurement is the entire proof that the corpus is blind. I did not re-run
it — `vmbconf` is built, but no corpus ships and I am read-only. **This must be re-measured before it
is stated publicly** (§7, item 1). If it does not reproduce, the lead claim of the release collapses
and the release should not happen in this form.

### Why not the alternatives

- **The VM model as a spec (release-first).** Inverts the adoption logic above. Also: I found **no
  FFI scaffolding anywhere** — `grep -rn '@\[extern\]\|extern_lib\|precompileModules'` over all
  `.lean` and `.toml` returns nothing, and `LeanBCH/Oracle.lean:36-37` (`Secp256k1.reject`) is the
  only `Secp256k1` value in the tree, documented "NOT a real verifier — it rejects every signature."
  A newcomer cannot execute the dominant spend type without writing a libsecp256k1 binding
  themselves. As a *spec* that is an embarrassment; as a *cost oracle* it costs nothing (§4).
- **The `Meta/` + `tools/` trust tooling as a standalone Lean asset.** Genuinely well built, but
  `leanprover-community/axiom-audit` already does the axiom half with the same default allowlist
  (lane-4 finding, fetched by that lane; not re-fetched by me). What is unusual is the *practice* —
  committing the proof-term closure as a reviewed lockfile and byte-gating it in CI — not the
  algorithm. That is a blog post, not a release. Ship it later or never; it does not need to be
  coupled to this decision.
- **The `Opt/` floor-provers.** See §2's competitive paragraph. Not now.

### Sequencing

| Phase | Ships | Gate to the next phase |
| --- | --- | --- |
| **P1** | Cost-divergence write-up + generated op-cost vectors, offered upstream (libauth `vmb-tests` / CHIP issue) | Does anyone engage? |
| **P2** | The consensus VM repo, public, as the provenance and regeneration engine for P1 | Is P1 being used? |
| **P3** | Trust tooling write-up; `Opt/` floor-provers only after the BN254 contest resolves | — |

P2 is worth doing *even if P1 gets no engagement*, but only as a low-cost artifact with honest
framing — not as a campaign. P1 failing is the signal to keep P2 small.

---

## 2. SCOPE — file manifest

Derived from `git ls-files` this run. Line counts measured.

### SHIPS

| Path | Notes |
| --- | --- |
| `LeanBCH/Core.lean`, `Epoch.lean`, `Kinds.lean`, `Number.lean`, `Opcode.lean`, `Crypto.lean`, `Oracle.lean` | Root modules. `Oracle.lean` is the trust boundary and should be the most-read file in the repo (§4). |
| `LeanBCH/Cost/{Arith,Hash,Metrics,Sig,Spine}.lean` | The five-metric cost model — the core of the P1 product. |
| `LeanBCH/Tx/{Types,Encoding,Sighash,Wire}.lean` | Byte-exact tx + sighash. `Sighash` is `LOAD-BEARING` (loadBearing 6, `Meta/necessity.json`) yet contains zero theorems — disclose (§3). |
| `LeanBCH/VM/{Instr,State,Eval,Meter,Extended,Shift2026,Verify,Standard,Invariants}.lean` | The engine + all 4,465 lines of proofs. |
| `LeanBCH/VM/SELF_HARDENING.md` | Checked clean of `stackcert`/`verifier.cash`/`competitor`/`BN254`/local-path strings. |
| `LeanBCH/Validation/**` (12 files) | Build-time KATs + the differential. Requires the re-pin (§7). |
| `LeanBCH.lean`, `lakefile.toml`, `lake-manifest.json`, `lean-toolchain` | `lakefile.toml:20` needs a one-line redaction (below). |
| `Meta/{Headlines,Necessity}.lean`, `Meta/necessity.json` | Headlines reduced to the 3 VM entries. |
| `tools/health/{katcount.mjs,map.mjs,kat-count.txt,README.md}`, `tools/manifest/gen.mjs`, `tools/opt-ci/verify.sh` | `verify.sh` becomes a 4-gate script; `gen.mjs` needs conditionalizing (§7). |
| `conformance/{Runner.lean,run.mjs,RESULTS.md,cost/**}` | The P1 deliverable lives in `conformance/cost/`. |
| `.github/workflows/verify.yml` | Exemplary — SHA-pinned actions, refuses to cache `.lake` with a written anti-vacuity rationale. Its four hardcoded numbers become false and must be rewritten. |
| `README.md`, `TRUST_MANIFEST.md`, `RED_TEAM_AUDIT.md`, `LICENSE`, `.gitignore` | Rewritten per §3/§5. |
| **NEW** `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `conformance/CORPUS.md` | Currently absent; §5. |

### WITHHELD — one line each

| Path | Reason |
| --- | --- |
| `LeanBCH/Opt/**` + `LeanBCH/Opt.lean` (47 files, 23,469 lines) | Active competitive advantage in an unresolved contest — see below. |
| `Opt/OpCostFloor_SCOPE.md` | Scope note for the withheld floor-provers. |
| `optimizer/` (73 files, 16,638 lines, incl. 12 `bn254_*` files) | Race tooling; in no lake target and unmentioned in the README. |
| `xcheck.lean`, `xcheck_arg.lean`, `xcheck_idx1.lean`, `xcheck_idxN.lean` | Differential drivers for the private optimizer. |
| `planck_gold.lean` | Coprocess for a separate private project (Planck). |
| `TOOLS.md` | Competitor framing (`:4`, `:12`, `:100`), absolute local paths (`:125-135`), names a third party. |
| `AGENTS.md` | `:3` describes LeanBCH as "the toolkit used by verifier.cash". |
| `tooling/manifest.json` | Internal agent tool catalogue; also declares a gitignored file `required: true` (§7). |
| `tools/foldgen/` | Generates the withheld `Opt/FoldTable.lean` only. |
| `LeanBCH/VM/Straightline.lean`, `LeanBCH/VM/RunStraight.lean` | **Judgment call, see note.** |

**Note on `Straightline`/`RunStraight`.** The adversary recommends dropping both (~641 lines) as
serving only the private optimizer. I disagree on `RunStraight` and I want the disagreement on
record, because it rests on a measurement: `Meta/necessity.json` currently buckets
`LeanBCH.VM.Straightline` as **LOAD-BEARING** (total 25, theorems 13, loadBearing 10) — lane 2
measured that it *drops* to `REFERENCE-PROOF` / loadBearing 0 only after severance, because its
only load-bearing consumer is `Opt/`. That is a fact about the headline roster, not about the code's
value. `run_straightline` (`RunStraight.lean:505-517`, lane-1 citation, not re-read by me) proves the
interpreter equals a fold over its step function on the straight-line fragment — that is a genuine
semantic result and the only one of its kind in the tree. **Recommendation:** withhold
`Straightline.lean` (its docstring at `:2` names the private product, and it is the seam artifact) but
*keep* `RunStraight.lean` if and only if it compiles without `Straightline`; if it does not, withhold
both and note the omission. I did not test that build.

### Competitive reasoning for `Opt/` — its own paragraph

Withholding `Opt/` is correct, but **not for the reason it is usually given, and the leakage argument
against releasing anything is weak.** I checked the coupling rather than assuming it. The cost model
that `Opt/`'s Piece A depends on is **already public**: `LeanBCH/Cost/Arith.lean:9-12` states the
formulas are "read straight off libauth's own arithmetic path (`instruction-sets/common/arithmetic.js`
+ `combinators.js`)", and the same constants are published in the VM Limits CHIP. `LeanBCH/Epoch.lean:17-27`
likewise documents every pin as read from libauth. So the operand-movement floor is derivable by
anyone from public data — it was never the moat. The real moat is the **tensor-rank lower-bound
machinery** (Fp2 rank exactly 3, Fp6 ≥ 5, composed `fp12Mul` ≥ 45 essential Fp-mults), and none of
that mathematics appears outside `LeanBCH/Opt/`. Severance is mechanically clean: one import.

What *does* leak is prose, and it is a sub-20-line diff. I found and verified every instance:
`README.md:45` (names the private `stackcert` engine, its capability set, and the dependency
direction); `LeanBCH/Cost/Arith.lean:8` ("the |a|·|b| operand pre-charge that **DOMINATES pairing
cost**" — a signpost to exactly the term a BN254 competitor should attack);
`LeanBCH/VM/Straightline.lean:2` ("the seam stackcert reasons over"); `LeanBCH/VM/Invariants.lean:346`
("the exact claim the **verifier.cash BCH-native track** and the CHIP cost-authority role need
theorem-backed"); `TRUST_MANIFEST.md:171` (names `verifier.cash/stackcert`); `lakefile.toml:20`
("a FROZEN public API that verifier.cash + stackcert import"); and transcription headers in
`Cost/{Arith,Spine,Sig,Hash,Metrics}.lean` + `Number.lean:6` naming `stackcert/Stackcert/Cost/*`.
`LeanBCH/Opcode.lean:11-12` cites a local `verifier.cash/node_modules/...` path as provenance —
harmless in content, but rewrite it to name the libauth package and version instead of a local path.

So: **withhold `Opt/` because the tensor-rank floors are a live advantage in an unresolved contest,
not because the rest of the tree leaks.** The rest is a redaction pass, not a reason to stay private.

---

## 3. THE CLAIM

### The lead sentence

> **LeanBCH is an executable model of the Bitcoin Cash 2026 script VM and its five-metric operation-cost
> model, written in Lean 4 core and differentially validated against libauth and the `vmb_test` corpus.
> It is not the consensus specification — BCHN is — and it is not proven equivalent to one; what is
> machine-checked is a narrow resource-safety core (three theorems, listed below), while the semantics
> themselves are validated by 289 build-time KATs and the conformance corpus, not by proof.**

Scope clause, immediately following, not in a footnote:

> **Scope.** Signature verification is an explicit opaque parameter, not an implementation
> (`LeanBCH/Oracle.lean`); no signature family is scored. The `26000 × sigChecks` op-cost tier — the
> largest single term in the cost model — is **not numerically validated anywhere**. The transaction
> sighash serializer, whose output length feeds the cost metric, carries **zero theorems**.

### Perimeter honesty — what is NOT proven, stated up front

This belongs in the README above the fold, not in `RED_TEAM_AUDIT.md`. All of the following I
verified this run except where marked.

- **There is no semantic-correctness theorem for any opcode.** No "OP_ADD pushes a+b", no
  accept/reject correctness statement. *(Lane-1 finding from reading all 178 theorem names in
  `Invariants.lean`; lane 1 records that it read ~15 of the 178 full statements, not all. I did not
  re-derive this. It should be re-checked before publication because it is a strong negative claim.)*
- **The three headline theorems are exactly three,** verified by me at `Meta/Headlines.lean:16-18`,
  out of 41 declared headlines — the other 38 are `LeanBCH.Opt.*` and are being withheld. A severed
  release ships **7%** of the current declared promise set. Say so.
- **The names oversell the statements, and must be renamed or restated.** `TRUST_MANIFEST.md:22`
  heads the group "Consensus VM — self-hardening + cost certificate". Per lane 1's kernel printouts,
  `runExt_WF_final` is a *one-sided* safety property (a VM that errored on every opcode would satisfy
  it), and `verifyInput_cost_within_budget` omits the P2SH redeem term and is conditioned on
  acceptance. The repo's own `RED_TEAM_AUDIT.md:42-43` grades the latter "near-definitional". Ship
  the plain-English statements, not the names.
- **The two strongest headlines are not composed.** `runScript_fuel_suffices_final` requires
  `budget ≤ maxOpCostCeiling`; the budget `verifyInput` actually passes satisfies it arithmetically,
  but lane 1 grepped and found **no declaration relating `opBudget` to `maxOpCostCeiling`**. A reader
  who assumes the headlines compose is assuming something unproven. *(Lane-1 finding, not re-verified
  by me. Cheap to close — §7.)*
- **The "2522" figure over-reads by roughly 1.75×.** `TRUST_MANIFEST.md:12` says "2522 declarations
  are load-bearing across 65 modules." I split `closureLeanBCH` myself with a regex for kernel
  auto-generation patterns (`.rec`, `.casesOn`, `.match_`, `.noConfusion`, `.eq_*`, …): **1,086 of
  2,522 (43%) are auto-generated**, leaving 1,436 that are plausibly authored — and that residue
  still includes definitions, not just theorems. The regex is a heuristic, not a kernel
  classification. **`gen.mjs` must print the split.** A generated document whose thesis is "computed,
  not asserted" must not hand a non-Lean reader a number that means something other than what it
  reads as.
- **Two outright false sentences ship today.** `README.md:57`: "The vendored `vmb_test` vectors retain
  their upstream MIT notice (see `Conformance/` provenance)" — I verified `git ls-files | grep -icE
  'vmb|corpus'` = **0** and there is no `Conformance/` directory. `README.md:42` lists a module
  `LeanBCH.Conformance` that does not exist (`lakefile.toml` roots the runner at `conformance.Runner`,
  outside the `LeanBCH` namespace). Under this estate's prime directive these are release-blocking.
- **A staleness marker in a repo with a no-placeholders rule.** `LeanBCH/Cost/Sig.lean:22-24` says
  "`serLen` is currently an EXTERNAL parameter … `serLen` here is a **placeholder** for that value",
  and promises `LeanBCH.Tx.Sighash` will close it. `Tx/Sighash.lean` exists and
  `Extended.lean:626-635` now computes the length from `Tx.encodeSigningSerialization`. The prose is
  stale; fix it or a reviewer will read "placeholder" literally.
- **`Cost/Sig.lean:11-12` says CHECKMULTISIG "is UNDER-MODELED here".** Verified. Disclose it next to
  the sig-cost caveat.
- **Provenance of a "generated" document is misstated.** `tools/manifest/gen.mjs:22` binds
  `tools/health/index.json` and never reads it, yet `gen.mjs:5-11` and the emitted banner at
  `gen.mjs:75` claim the manifest "composes three computed sources" including it. *(Lane-4 finding,
  isolated by two experiments; I verified the `.gitignore:2-3` half — that file is untracked, so
  `node tools/manifest/gen.mjs` fails on a fresh clone.)*

---

## 4. THE SIGNATURE HOLE

**Frame it as a boundary, and put it in the second paragraph of the README** — before the theorem
list, not after. The right presentation is: *the oracle is why the cost claims are trustworthy
without a crypto backend*, not *the oracle is a missing piece*.

### The precise, verified statement

`LeanBCH/Oracle.lean` defines `Secp256k1` as a two-field structure of
`(sig pubkey digest : Bytes) → Bool`. It is a **parameter, not an axiom and not `native_decide`** —
I read the whole file. Every headline is universally quantified over it, so each holds for *any*
backend, including a real libsecp256k1 binding.

The oracle is called from exactly three sites in `LeanBCH/VM/Extended.lean` — lines 148/149, 165/166,
191 — reached by OP_CHECKSIG (`0xac`), OP_CHECKDATASIG (`0xba`) and OP_CHECKMULTISIG (`0xae`), per the
docstrings at those arms, plus their VERIFY variants.

The cost meter's independence from the verdict is **real and I traced it**, but it is finer-grained
than "no cost metric reads the oracle":

- `stepMeterExt` (`Extended.lean:594`) takes `crypto` **only** to compute the stepped state.
- Its metric increment is `kappa s` (a function of the **pre-state**, `Meter.lean:105`) plus four
  corrections. `sigHashExtra` (`:626-635`) and `multiSigHashExtra` (`:641-668`) — the two that fire on
  signature opcodes — read **only `s`**, never the verdict.
- The two corrections that *do* read the post-state — `introBytes` (`:599-604`, gated
  `0xc0 ≤ opcode ≤ 0xd3`) and `defineBytes` (`:615-620`, gated `opcode == 0x89`) — fire on opcode
  ranges **disjoint from every oracle-calling opcode**.

So: **the per-step cost increment is independent of what the oracle returns.** That is exactly why a
cost-vector product is credible with a reject-only oracle — the numbers the vectors assert are the
numbers a real backend would produce.

**Two honesty requirements on that claim:**

1. **The total accumulated cost of a run is *not* oracle-independent**, because a NULLFAIL aborts the
   run early and the remaining instructions are never billed. State the per-step property, not a
   run-level one.
2. **There is no theorem saying any of this.** I grepped; none exists. `TRUST_MANIFEST.md:196`
   currently asks the skeptic to "read one structure in `Oracle.lean`; confirm no cost metric reads
   its result" — i.e. it delegates the tier-3 check to *manual inspection of a 953-line file*. That
   is the weakest link in the trust story and it is the one most load-bearing for the P1 product.

**Recommendation (this is the highest-value new theorem in the proposal):** prove

```
∀ (p : Program) (c₁ c₂ : Secp256k1) (s : State),
  (stepMeterExt p c₁ s).metrics = (stepMeterExt p c₂ s).metrics
```

The case analysis above suggests it is true and provable by opcode case-split. It converts
`TRUST_MANIFEST`'s tier-3 manual instruction into a machine check, and it is the theorem that makes
"our cost numbers do not depend on having a signature backend" a *claim* rather than an assurance.
**I have not attempted the proof and cannot cost it** (§7).

### What must be stated where the reader meets it

`conformance/RESULTS.md:104-108` already says it correctly and this wording should be lifted verbatim
into the README: the `26000·sigChecks` term "is NOT numerically validated anywhere … under the
reject-oracle a non-empty sig NULLFAILs *before* its cost is compared to a budget or to libauth, so
the corpus sig families exercise the reject/accept LOGIC, not the sig-cost NUMBERS. That tier is
soundness-safe (over-billing never wrong-accepts) but currently unvalidated, not 'checked
elsewhere'." `RESULTS.md:147` adds that the sig-cost fixes are "LATENT (inert under the
reject-oracle)". Both verified by me.

This is the sharpest limitation of the P1 product and must be in the pitch, not discovered later:
**the vectors are authoritative on the cheap terms and silent on the most expensive one.** Say it
first; it is what makes the rest credible.

---

## 5. PACKAGING

### README structure

1. **What this is** — the lead sentence (§3), then the scope clause.
2. **What is NOT proven** — the perimeter list. Above the fold.
3. **The corpus gap** — the P1 finding, with the reproduction command.
4. **The three theorems, in plain English**, each with its own "what this does not say" line.
5. **The oracle boundary** (§4).
6. **First five minutes** (below).
7. **How a skeptic checks each tier** — pointer to `TRUST_MANIFEST.md`.
8. **Maintenance contract** (§6) — including the staleness date.
9. Layout / build / licence.

### First five minutes

```
git clone … && cd LeanBCH
lake build                       # ~1 min, zero dependencies, no mathlib
bash tools/opt-ci/verify.sh      # the gate: builds, 0 sorry, axiom-clean, closure stable, KATs conserved
```

This part of the story is genuinely strong: `lean-toolchain` pins `leanprover/lean4:v4.31.0`,
`lake-manifest.json` has `"packages": []`, and lane 2 measured a cold severed core build at **52.5 s**
and a cold patched `verify.sh` at **52.8 s → ALL CHECKS PASS** *(lane-2 measurements on this machine;
I did not re-run either — the analyzer rewrites `Meta/necessity.json` in-tree and I am read-only)*.

Blocker: `verify.sh` currently **fails instantly** on a severed tree because line 21 hardcodes
`lake build LeanBCHOpt`. It must ship patched (§7).

### How a sceptic checks each tier

`TRUST_MANIFEST.md:190-196` already has the section and its shape is right. Build on it:

| Tier | Today | Change needed |
| --- | --- | --- |
| **1 PROVEN** | `bash tools/opt-ci/verify.sh`; `#print axioms <name>` | Drop "fold-table reproducible" from the success string (`verify.sh:155`) — it becomes false when gate 4 is deleted. Same for `verify.sh:69`, which claims the `schedule_refines` anchor "agrees" after that anchor is removed. **These are `echo` strings; no gate catches them.** |
| **2 VALIDATED** | `lake build vmbconf && ./…/vmbconf <corpus>` | **The corpus does not ship.** Currently unactionable. Add `conformance/CORPUS.md` with acquisition steps, or vendor the vectors with their MIT notice. Until then tier 2 is not independently checkable and the manifest should say so. |
| **3 ASSUMED** | "read one structure in `Oracle.lean`; confirm no cost metric reads its result" | Manual inspection of a 953-line file. Replace with the §4 theorem, or at minimum with a mechanical check that `crypto` appears in `stepMeterExt` only in the `step1Ext` application. |

### Licence

`LICENSE` is the stock unmodified Apache-2.0 with `LICENSE:178` filled in as "Copyright 2026 LeanBCH
contributors" — verified. But `grep -rl 'SPDX' --include=*.lean .` returns **zero files**: not one
source file carries a licence header. Add `SPDX-License-Identifier: Apache-2.0` to every shipped
`.lean`. Delete the false vendored-vectors sentence at `README.md:57`; if vectors are vendered later,
restore it with a real MIT notice.

### Reproducing the conformance result

Today: impossible from a clean clone. `vmbconf` builds; there is no corpus and no documented way to
get one; `conformance/run.mjs:25,27` writes and reads `/tmp/vmb_vectors.txt`, which also violates this
estate's never-`/tmp` convention. Required: `conformance/CORPUS.md` naming the exact upstream source
and commit, a `--corpus` flag, and an output path that is not `/tmp`.

Also: `conformance/RESULTS.md`'s pass counts (1140/1140 hashing, 1485/1485 cashtokens, …) have not
been re-measured since the OP_DEFINE cost fix landed in `25f1265`. Re-run before publishing them.

---

## 6. MAINTENANCE CONTRACT

### The honest annual cost

BCH ships one consensus upgrade per year, on 15 May. The bounded part is real: `LeanBCH/Epoch.lean:56`
defines `BCH_2026_05` as a 13-field record and its docstring calls it "the single re-audit surface on
a VM upgrade: bump this record."

But the "bump one record" story is **only partly true, and the file says so itself**.
`LeanBCH/Epoch.lean:10-15` — verified — states that `maxItemLen`/`maxNumLen` (VM/Eval),
`maxMemorySlots` (VM/Extended), `maxBytecodeLen` (VM/Verify) and `maxCtrlDepth` "are still bare
top-level `def`s read directly by the runtime, decoupled from this record … Folding them into `Epoch`
is future work." An upgrade touching structural limits touches proofs, not just a record.

**Honest annual estimate, in three tiers:**

| Scenario | Work | Confidence |
| --- | --- | --- |
| Repricing only (cost pins move) | Bump `Epoch`, regenerate `conformance/cost/`, re-run gate. **~1 day.** | Reasonable — `Epoch` genuinely parameterizes the cost tier. |
| New opcodes, no limit changes | New arms in `Extended.lean` + `kappa`, new KATs, new cost vectors. **~1–2 weeks.** | Low confidence — extrapolated from the shape of the BCH-2026 work, not measured. |
| Structural limits move | Touches proofs in `Invariants.lean`. **Cannot cost. Genuinely unknown.** | None. |

**Track record caveat, verified:** `git rev-list --count HEAD` = **151** commits, first 2026-07-05,
HEAD 2026-07-20. **142 of 151 fall in the first four days** (26/41/64/11), then 1–3 per day. The
project is **16 days old**. There is no observed maintenance behaviour because there has not been
time for any. Any claim of sustainability is a *promise*, not a record, and the release must say so.

### It is already stale, before release

`LeanBCH/Validation/CostDifferential.lean:9` and `:32`, and `conformance/cost/gen.mjs:4,12,15`, all
pin **libauth 3.1.0-next.8** — verified. That is the superseded vintage that carried the *wrong*
OP_DEFINE behaviour. **A cost oracle pinned to a known-wrong reference must not be published.**

### Staleness-visible mechanism

A released spec that silently rots is the failure mode, so make rot **loud and automatic**:

1. **A dated freshness header** in the README and `TRUST_MANIFEST.md`: the exact libauth version, the
   BCHN version the model targets (currently documented nowhere), the corpus commit, and the date.
2. **A CI expiry gate.** `verify.sh` fails — not warns — if `today > VALID_UNTIL`, set to the next
   15 May plus a grace period. A maintainer who has done the annual bump moves the date; one who has
   not gets a red badge that readers can see. This is the mechanism that makes silence impossible.
3. **A version-pin gate.** CI fails if the pinned libauth version is not the latest release, or at
   minimum prints the delta. Cheap, and it would have caught today's stale pin.
4. **Follow EELS' proven pattern:** encode the hardfork in the version (`0.2026.5`), so a consumer can
   see at a glance which consensus epoch an artifact models.

**If the maintainer will not commit to the annual re-pin, do not release the cost differential.** A
stale cost oracle that others cite is worse than no oracle. That is a genuine precondition, not a
rhetorical one.

---

## 7. WORK REQUIRED

Ordered. Costs are my estimates and are labelled where I cannot give one honestly.

### Blocking — the release is false or broken without these

| # | Item | Est. |
| --- | --- | --- |
| 1 | **Re-measure the 556/556-both-ways claim.** Acquire the corpus, run `vmbconf` with and without the OP_DEFINE fix. This validates or kills the lead claim. **Do this first — everything else is wasted if it fails.** | 0.5 day |
| 2 | **Re-pin the differential off libauth 3.1.0-next.8** → current release; regenerate `conformance/cost/`; confirm the battery still passes. | 0.5–1 day |
| 3 | **Fix the two false README sentences** (`:57` vendored vectors, `:42` nonexistent module). Prime-directive blockers. | 15 min |
| 4 | **Redaction pass** — `README.md:45`, `Cost/Arith.lean:8`, `Straightline.lean:2`, `Invariants.lean:346`, `TRUST_MANIFEST.md:171`, `lakefile.toml:20`, six `stackcert` transcription headers, `Opcode.lean:11-12` local paths. | 30–45 min |
| 5 | **Sever.** Remove `Meta/Necessity.lean:12`; reduce `Headlines.lean` to the 3 VM entries; strip `Opt/`, `optimizer/`, `xcheck*`, `planck_gold`, `TOOLS.md`, `AGENTS.md`, `tooling/`, `tools/foldgen/`. Use `git archive`, **never `cp`/`tar`** — `.gitignore:6-7` covers `.worktrees/` and `.claude/worktrees/`, which hold two full copies of the optimizer. | 1–2 h |
| 6 | **Patch `verify.sh`** — drop the `LeanBCHOpt` target (`:21`, `:29`), drop the `schedule_refines` anchor half (`:60-62`), delete gate 4 (`:71-85`), delete the opt-interface lint (`:144-150`), rebase `kat-count.txt` to **289**, **and fix the two now-false `echo` strings at `:69` and `:155`.** | 1–2 h |
| 7 | **Conditionalize `tools/manifest/gen.mjs`** — the unconditional Opt-capstone prose at `:104-112` and the optimizer section at `:215-225` emit dangling references to withheld theorems. Also fix the false provenance banner (`:5-11`, `:75`) and the dead `health` binding (`:22`). | 2–3 h |
| 8 | **Rewrite `.github/workflows/verify.yml`'s header** — 249 s / 6 checks / 41 headlines / 313 KATs all become false. | 30 min |
| 9 | **Fix the untracked-required-artifact trap** — `tooling/manifest.json:7` declares `tools/health/index.json` `required: true` while `.gitignore:2-3` ignores it, so `gen.mjs` crashes on a fresh clone. Either track it or make `gen.mjs` tolerate its absence. | 30 min |

### Required for the release to be *usable*

| # | Item | Est. |
| --- | --- | --- |
| 10 | **`conformance/CORPUS.md`** + a `--corpus` flag + drop the `/tmp` path (`run.mjs:25,27`). Without this, trust tier 2 is not independently checkable. | 2–3 h |
| 11 | **Re-run the full conformance suite** post-`25f1265` and update `RESULTS.md`. | 0.5 day |
| 12 | **README rewrite** per §3/§5, incl. the perimeter list and plain-English theorem statements. | 0.5 day |
| 13 | **`gen.mjs` prints the generated/authored split** of the 2,522 figure. | 1–2 h |
| 14 | **SPDX headers** on every shipped `.lean` (currently zero). | 30 min, scriptable |
| 15 | **`CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`**, version `0.2026.5`, freshness header + CI expiry gate (§6). | 0.5 day |

### High-value, optional, honestly uncosted

| # | Item | Est. |
| --- | --- | --- |
| 16 | **The oracle-independence theorem** (§4). Converts the weakest trust tier from manual inspection to a machine check, and directly underwrites the P1 product. | **Cannot cost — I did not attempt the proof.** Plausibly a day; plausibly much worse if `kappa`'s case split is unpleasant. |
| 17 | **The standardness-containment theorem** — `verifyStandard = verifyTransaction && isStandard && standardInterpreterOk` (`Standard.lean:192`, verified), so relay-acceptance implies consensus-validity *by construction*. I grepped: **no such theorem exists.** This is the exact invariant whose violation caused the May 2019 BCH chainsplit (lane-3 finding from a fetched BitMEX source; I did not re-fetch). It is community-legible in a way no other theorem here is. **Caveat:** `Meta/necessity.json` buckets `LeanBCH.VM.Standard` as `REFERENCE-PROOF`, loadBearing **0** — so this theorem would need Standard/ promoted into the load-bearing set, which is more than a one-liner. | Lane 3 called it "one or two lines"; I think that underestimates the promotion work. **Uncosted.** |
| 18 | **Compose the two strongest headlines** — prove `opBudget 10000 ≤ maxOpCostCeiling` and link fuel-sufficiency to the budgets `verifyInput` actually passes. Lane 1 confirmed the arithmetic by `decide`. | Likely hours |
| 19 | **Promote `decoded_runExt_WF_init`** (`Invariants.lean:4459-4462`, lane-1 citation) — the premise-free wire-decoder form of resource safety, which is the version a protocol developer actually wants and is currently *not* a headline. | Hours |
| 20 | **Fix the stale docstring** at `Invariants.lean:1039` ("All four are provable in principle; deferred, not assumed-false") — lane 1 reports `frozenCore_holds` now proves all four. A false sentence in prose about a sound proof. | 10 min |

**Rough total for a publishable P1+P2: 5–8 working days**, excluding items 16–19 and excluding
anything item 1 uncovers.

---

## 8. WHAT WOULD MAKE THIS A MISTAKE

Not releasing is the better call under any of these. The first is a hard gate.

1. **If the 556/556-both-ways measurement does not reproduce.** The entire lead claim is "the corpus
   is blind to op-cost divergence." If the corpus *does* catch it, there is no finding, no product,
   and no reason to publish now. **Do not proceed past item 1 without this.**

2. **If the maintainer will not commit to the annual libauth re-pin.** A cost oracle others cite,
   pinned to a superseded reference, actively harms the ecosystem it claims to serve. The repo is
   *already* in this state today. Releasing without a maintenance commitment converts a private
   staleness problem into a public one.

3. **If the release is framed as a specification.** "A formalization of the BCH VM" invites
   over-reading of three narrow theorems, of which one is graded "near-definitional" by the project's
   own audit. KEVM is the cautionary precedent: more rigour, no adoption. If the framing cannot be
   held to the test-vector register, the release does net harm to the maintainer's credibility.

4. **If the tensor-rank floors cannot be cleanly withheld.** I believe they can — one import,
   verified — but I did not run the severed build myself. If severance turns out to require exposing
   the rank machinery, stop: the BN254 contest is unresolved and the maintainer is currently second.

5. **If the perimeter-honesty list cannot be published in full.** The unvalidated `26000·sigChecks`
   tier, the theorem-free sighash serializer, the P2SH-omitting cost certificate, the 7%-of-headlines
   scope, and the 43%-auto-generated closure figure must all appear above the fold. A release that
   soft-pedals any of them is worse than no release — and in a repo whose own `RED_TEAM_AUDIT.md`
   records a previously overstated "100% / audited-exact" framing, it would be the second offence.

6. **If the timing is wrong for the maintainer.** 5–8 days of release engineering is 5–8 days not
   spent on the BN254 contest, where position is measurable and contested. The finding does not decay
   quickly; the contest does. **Deferring P1 by a quarter costs almost nothing.** That is the most
   likely correct reason to say "not yet", and it is not a criticism of the work.

---

## SUMMARY

**The asset.** The consensus VM model (`LeanBCH/VM`, `Cost`, `Tx`, `Validation`, `conformance` —
48 files, 11,822 lines) is the most valuable releasable thing, because it is the engine that
regenerates everything else annually. But it is **not what ships first**: ship the op-cost divergence
finding plus generated vectors, upstream, as a test contribution — the EELS play, not the KEVM play.
The repo follows as the vectors' provenance. `Opt/` (47 files, 23,469 lines) stays private because
the tensor-rank floors are a live advantage; the rest of the tree's competitive leakage is a
sub-20-line prose redaction, not a reason to stay closed.

**The one-sentence claim.** *"LeanBCH is an executable model of the Bitcoin Cash 2026 script VM and
its five-metric operation-cost model, differentially validated against libauth and the `vmb_test`
corpus — not the consensus specification, and not proven equivalent to one; three narrow
resource-safety theorems are machine-checked, the semantics are validated by 289 KATs and the corpus,
and signature verification is an explicit opaque parameter whose `26000 × sigChecks` cost tier is not
numerically validated anywhere."*

**Top 3 work items.** (1) Re-measure the 556/556-both-ways corpus-blindness claim — it is unverified
and the whole release rests on it. (2) Re-pin the cost differential off the superseded libauth
3.1.0-next.8. (3) Fix the two false README sentences and run the severance + redaction pass.

**Honest verdict.** **Worth doing — conditionally, and not this week.** The finding is real and the
gap it fills is real: I verified that `conformance/cost/battery.txt` has no OP_DEFINE vector, that no
corpus ships, and that the sig-cost tier is unvalidated by the repo's own admission. That is a
genuine, currently-unfilled slot in the BCH ecosystem, and it can be filled without exposing one line
of the competitive optimizer. But the project is **16 days old**, its cost differential is **pinned to
a known-wrong reference**, its README contains **two verifiably false sentences**, and its lead
empirical claim **has not been reproduced**. None of that is fatal and all of it is fixable in about
a week. The correct decision is: **do item 1 now** (half a day, decides everything), and if it holds,
schedule the remaining week for after the BN254 contest resolves. Releasing before item 1 would risk
publishing a false claim; releasing before the re-pin would publish a stale oracle. Both are avoidable
by waiting, and waiting costs almost nothing.
