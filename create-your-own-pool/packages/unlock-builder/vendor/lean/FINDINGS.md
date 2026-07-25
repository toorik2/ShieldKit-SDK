# LeanBCH findings ledger

Findings about LeanBCH itself, recorded permanently. A finding is never deleted; when it is resolved
it is struck through and its resolution recorded, so the correction history stays visible.

IDs are `LBCH-YYYY-NNN`. This ledger covers defects in **this** model. Findings about *other* engines
are handled under the disclosure charter and live in the RustBCH `ADVISORIES/` tree.

| ID | Summary | Class | Status |
|---|---|---|---|
| ~~LBCH-2026-001~~ | ~~CHECKMULTISIG: `kappa` treats the Schnorr path as ECDSA — bills `nKeys` where consensus bills 1-per-signature-reached~~ | cost-model | **FIXED + VERIFIED against BCHN** (2026-07-21) |
| LBCH-2026-003 | libauth 3.1.0-next.8 bills a Schnorr-multisig sig-check BEFORE the length check and verification; BCHN bills none | third-party (advisory-track) | **HELD — charter clocks not started**; corroborated against BCHN's *measured* accrual 2026-07-21 (900 vectors) |
| LBCH-2026-002 | The cost-differential measurement was ephemeral, and its summary sentence was false | evidence-integrity | **OPEN** |
| LBCH-2026-004 | `bchn-leg` reports `0/0/0` metrics on every BCHN reject (an initializer, not a measurement) — the `2,384` over-bill headline was measured against it | measurement-integrity (third-party tool) | **ROUTED AROUND** 2026-07-21 via `bchn-partial-probe`; headline retired, partition re-derived; leg not fixed (other repo) |

---

## LBCH-2026-001 — CHECKMULTISIG cost divergence

**Class:** cost-model · **Direction:** both, and the under-billing direction is soundness-relevant
**Found:** 2026-07-21, by binding a real secp256k1 oracle (commits `344e02a`, `4f2fe4e`)
**Site:** `VM/Meter.lean` (`kappa`, the CHECKMULTISIG arm) -> `Cost/Sig.lean`. Root-caused
2026-07-21 (commit `a8b7682`), **fixed** 2026-07-21 (commit `06cc3a3`) — see "The fix, and what it is
NOT" below — and **verified against BCHN** 2026-07-21, which closed the soundness direction: see
"Independent re-measurement" below and `conformance/evidence/LBCH-2026-001-threeway.tsv`.
*(The "not established" that stood here, and the "CAUSE UNKNOWN" heading in the next section, are
kept as correction history; both were superseded by the ROOT CAUSE section.)*

### What is wrong — CAUSE UNKNOWN, and two earlier diagnoses were both false

A measured divergence exists (table below). Its **cause has not been established.** Two proposed
explanations have already been checked and both are wrong; they are recorded so nobody re-proposes
them.

**Ruled out #1 — "libauth bills the checks actually performed."** False. `libauth` 3.1.0-next.8
`build/lib/vm/instruction-sets/common/crypto.js:246-250` computes
`allSignaturesAreNull = signatures.every(s => s.length === 0)` and then bills
`signatureCheckCount += publicKeys.length` gated on `!allSignaturesAreNull`; its Schnorr-multisig path
bills `+= 1` per signature (`:177`). This is *semantically identical to consensus* — BCHN
`src/script/interpreter.cpp:1690-1692` bills `metrics.TallySigChecks(nKeysCount)` under
`if (!areAllSignaturesNull)`, with the source comment *"not identical to the number of actual ECDSA
verifies, but … an upper bound"*, and `:1616` bills `TallySigChecks(1)` per signature on the Schnorr
path. **libauth is correct here.** Acting on this false claim would have meant publishing a second
cost divergence against a third party's code on the strength of a summary nobody had reproduced.

**Ruled out #2 — "LeanBCH bills `nPubKeys` unconditionally, missing the all-null guard."** Also false,
and this ledger asserted it in its first revision. `Cost.multiSigCost` is indeed unconditional, but
**its caller gates it**: `LeanBCH/VM/Meter.lean:143-149`, inside `kappa` (the live per-step fold used
by `stepMeter`), extracts the signature slice and bills
`Cost.sigCost .checkMultiSig 0 0 0` when `sigs.all (·.isEmpty)`, else `Cost.multiSigCost nKeys`.
`stepMeterExt` only *adds* hash-iteration corrections; it does not override the count. The error came
from reading `Cost/Sig.lean` alone and concluding absence without checking the call site.

**So all three engines implement the same rule**, and the divergence below is caused by something
else. Candidate directions, none verified: the stack-slice extraction at `Meter.lean:146-147` (wrong
offsets would make the all-null test evaluate on the wrong items); the deferred Schnorr-multisig
branch at `Extended.lean:228`; or aggregation across several signature ops within one input. The
`hashDigestIterations` divergence is very likely a *separate* cause (the `serLen` /
`multiSigHashExtra` term) and should not be assumed to share one.

### ROOT CAUSE (2026-07-21) — one defect, two opposite signs, plus a libauth divergence

Established by reading all three engines and then measuring vector `0u4tu8` end-to-end through each.
Witness committed at `conformance/evidence/LBCH-2026-001-rootcause.tsv`.

**`kappa` never detects the Schnorr multisig path.** `VM/Meter.lean:143-149` inspects only whether the
signatures are all-null; it never looks at the dummy element. BCHN bills the two paths *differently*:

| path | dummy element | BCHN bills | source |
|---|---|---|---|
| ECDSA / legacy | empty | `nKeysCount` (deliberate upper bound) | `interpreter.cpp:1692` |
| Schnorr | non-empty checkbits bitfield | **1 per signature reached** | `interpreter.cpp:1616` |

So `kappa` applies the ECDSA rule to both, which produces the divergence in **both directions**:

**(1) OVER-BILL — 1,360 vectors. LeanBCH's genuine bug.** On a Schnorr multisig with non-null
signatures LeanBCH bills `nKeys`, consensus bills `nSigsCount`. A 1-of-20 Schnorr vector bills 20
against libauth's 1 — precisely the per-arity table below (n=3: LeanBCH 3 vs libauth 1 on 210 vectors
= 1-of-3 Schnorr; vs 2 on 30 = 2-of-3; agreeing on 36 where every key is reached).

**(2) "UNDER-BILL" — 1,255 vectors, worst −26,768. NOT a LeanBCH bug: libauth is the outlier.**
libauth `crypto.js:177` bills `signatureCheckCount += 1` *and* the signing-serialization hash
iterations **before** the 64-byte Schnorr length check (`:185`) and before verification (`:188`). BCHN
calls `checker.CheckSig` **first** (`interpreter.cpp:1605`) and, on failure, returns `SIG_NULLFAIL`
before ever reaching `TallySigChecks(1)` — its own comment notes *"This can fail if the signature is
empty."* So for a null Schnorr signature BCHN bills nothing and libauth bills one.

Measured on `0u4tu8` ("2-of-15 Schnorr multisig (null signatures)", unlocking `<0b11 0x00> <0> <0>`):

| engine | sigChecks | hashIters | opCost |
|---|---|---|---|
| **BCHN, consensus mode** | **0** | 0 | — (`SIG_NULLFAIL` in execute) |
| libauth 3.1.0-next.8 | **1** | 22 | 30,962 |
| **LeanBCH** | **0** | 10 | 4,194 |

`30,962 − 4,194 = 26,768 = 1 × 26,000 + 12 × 64` — the reported worst case, decomposed exactly. The
oracle-independent controls (`evaluatedInstructionCount` 25, `stackPushedBytes` 1054,
`arithmeticCost` 0) are identical across libauth and LeanBCH, confirming the comparison scope.

**LeanBCH agrees with consensus here; the reference does not.** The direction that looked
soundness-relevant was an artefact of measuring against libauth rather than against BCHN — which is
exactly why the charter treats libauth as a pinned *witness* and never a referee. That doctrine has
now been paid for twice: `OP_DEFINE` (RBCH-2026-001) and this.

### The fix, and what it is NOT

Only manifestation (1) is a LeanBCH defect. `kappa` must branch on the dummy element: non-empty
(Schnorr) ⇒ bill one sig-check per signature actually reached; empty (ECDSA) ⇒ keep the current
`nKeys`-if-not-all-null rule.

> **CORRECTION (2026-07-21, at fix time).** The sentence that stood here — *"'reached' must be derived
> from the checkbits, not from execution"* — is **wrong**, and following it would have re-implemented
> `DecodeBitfield` in the cost layer for no gain. "Reached" is derived from the **signatures**, not the
> checkbits. BCHN requires `countBits(checkBits) == nSigsCount` (`interpreter.cpp:1562`) and returns
> *before* the tally loop when it does not hold, so on every state where the two derivations could
> disagree consensus bills **0** anyway. The signature-derived count is also strictly more
> informative: an EMPTY signature always fails `CheckSig` (`interpreter.cpp:2562-2564`), so the
> leading-non-empty run is oracle-free and pins the exact stopping point of the loop.

**FIXED (2026-07-21).** `VM/Meter.lean` now reads the dummy at stack index `nKeys+2+nSigs` and, when
it is non-empty, bills `Cost.multiSigSchnorrCost` over the number of **leading non-empty signatures in
`iSig` order**. The ECDSA arm is untouched.

**Relationship to consensus — an UPPER BOUND, never described as exact.** The exact Schnorr count is
oracle-dependent (BCHN stops at the first signature that fails to verify, `:1606-1611`), which a
pre-state `kappa` cannot know. The billed number is EXACT when every declared signature is non-empty
and verifies (the only path on which a transaction is accepted), EXACT when `nSigsCount = 0`, and
EXACT when a signature is empty; it is an UPPER BOUND when a non-empty signature fails to verify or
fails an encoding check, and when the bitfield is malformed or the stack underflows (BCHN bills 0
there). It is never below BCHN's tally **for that one CHECKMULTISIG invocation**, so the soundness
direction is preserved at the arm — over-reject is possible, over-accept is not. The full table is at
the edit site (`Cost/Sig.lean`).

> **Scope that sentence carefully — it is a per-invocation claim, not a whole-input one.** The
> re-measurement below finds **324 vectors whose whole-input LeanBCH total IS below BCHN's**. That is
> not a counterexample to the arm's upper-bound property: those inputs contain *several* signature
> ops, and LeanBCH stops at the first Schnorr CHECKMULTISIG (`Extended.lean:228`, deferred) so the
> later ops never execute and are never billed at all. Whole-input totals are therefore only bounded
> below by consensus on inputs LeanBCH runs to completion. The soundness conclusion survives, but it
> rests on a *second* fact rather than on this one: LeanBCH **rejects** all 324.

**The `.reverse` is load-bearing, and its absence would be an UNDER-bill.** `kappa` slices signatures
off the stack top-first, but BCHN's `iSig = 0` is the DEEPEST signature
(`idxBottomSig = idxTopSig + nSigsCount - 1`, `interpreter.cpp:1571`, read at `:1593`) — the order
`Extended.lean:225` already reverses into. Measured both ways on a 2-of-3 state with the deepest
signature present and the shallower one null: consensus bills 1, the reversed form bills 1, the
top-first form bills **0**. Pinned by KAT in `LeanBCH/Validation/VM/MultiSigBilling.lean`.

**ECDSA-path invariance is proved, not sampled.** `multiSigArm_ecdsa_unchanged`
(`LeanBCH/Validation/VM/MultiSigBilling.lean`) states that for **every** stack whose dummy element is
empty, the fixed arm bills exactly what the pre-fix arm billed. The pre-fix arm is transcribed
verbatim in that file so the two are directly comparable.

The `hashDigestIterations` spread (agree 2 / over 950 / under 1,665) is a **separate** term
(`multiSigHashExtra`) and is NOT addressed by this fix; the 12-iteration component above is
libauth's, not LeanBCH's. The Schnorr **execution** branch remains deferred
(`Extended.lean:228`) — this fix is to the cost model only and does not reduce the 803 rejections.

### Measured at fix time (2026-07-21)

Per-vector artifact: **`conformance/evidence/LBCH-2026-001-fix-deltas.tsv`** (1,486 rows). Corpus =
the 11 signature families, 5,803 vectors, 4,467 of which reach a comparable metric total. libauth leg
= `@bitauth/libauth` 3.1.0-next.8 at `optimizer/node_modules`, driven through
`createVirtualMachineBch2026().evaluate()`; that driver reproduces the committed `0u4tu8` witness
(sigChecks 1, hashIters 22) exactly.

| | before | after |
|---|---|---|
| vectors agreeing with libauth on `signatureCheckCount` | 2,229 | **2,799** |
| LeanBCH over-bills vs libauth | 1,912 | **1,342** |
| LeanBCH under-bills vs libauth | 326 | 326 |

- `signatureCheckCount` **decreased on 1,486 vectors and increased on 0** — corpus-wide monotone
  non-increase, the strongest available check on an over-bill fix.
- **Zero** vectors that agreed with libauth before now disagree; 570 newly agree (360 of them on
  vectors whose verdict LeanBCH already gets right).
- `evaluatedInstructionCount`, `hashDigestIterations`, `arithmeticCost`, `stackPushedBytes` and every
  verdict are **unchanged on all 4,467 vectors**.
- `0u4tu8` is unchanged at `sigChecks 0 / opCost 4,194`, still matching BCHN against libauth's 1 —
  the regression guard on the committed root-cause witness.
- The under-bill count vs libauth is unchanged (no NEW under-billed vectors), but 216 existing ones
  deepened. **All 216 are vectors LeanBCH rejects** because of the deferred Schnorr execution branch:
  LeanBCH errors at the first Schnorr CHECKMULTISIG and never executes the input's remaining
  signature ops, so their checks are never billed. Traced through libauth's own debugger on `7gnse0`
  and `lrceng`, whose redeem scripts each carry four signature ops (`0xae`, `0xaf`, `0xbb`, `0xba`)
  that libauth bills and LeanBCH never reaches. This is the deferral, not a billing error.

> **NOT reproduced:** the pre-fix table below (2,617 verdict-agreeing multisig vectors; sigChecks
> 1,255 / 1,360 / 2) could **not** be re-derived in this run — the multisig families supply 1,367
> metric-comparable vectors in total, and no partition tried reproduces 2,617. That is consistent
> with **LBCH-2026-002**: the original measurement was ephemeral and committed no per-vector
> artifact, so it cannot be checked. The numbers below are therefore left as recorded and are **not**
> confirmed by this run; the fix-time numbers above supersede them as the measured baseline.

### Independent re-measurement (2026-07-21) — the BCHN leg, and the soundness direction CLOSED

The fix-time measurement above compared LeanBCH against **libauth only**, which is why the
soundness question stayed open: libauth is not consensus (see LBCH-2026-003). This run adds the
**BCHN** leg — BCHN's own script engine, built from `bchn-src @ 864c53e` (v29.0.1) and driven through
`bch-conformance/legs/bchn/bchn-leg --mode consensus` — over the same 4,467 metric-comparable
vectors. Per-vector artifact: **`conformance/evidence/LBCH-2026-001-threeway.tsv`** (4,467 rows,
engine + corpus versions in its header).

*Both drivers were validated against committed evidence before use:* the libauth driver reproduces
`LBCH-2026-001-rootcause.tsv`'s `0u4tu8` row exactly (sigChecks 1, hashIters 22, opCost 30,962), and
the `costprobe` run reproduces all 1,486 rows of `LBCH-2026-001-fix-deltas.tsv` on three independent
columns (`sigChecksAfter`, `libauthSigChecks`, `opCostAfter`) with **0 mismatches**. The fix-time
table above is therefore independently confirmed, not merely restated.

**`0u4tu8` regression guard — re-measured three-way, all three engines re-run:**

| engine | verdict | sigChecks | opCost |
|---|---|---|---|
| BCHN (`--mode consensus`, and `--mode standard`) | reject | **0** | — |
| libauth 3.1.0-next.8 | reject | 1 | 30,962 |
| LeanBCH (post-fix) | reject | **0** | 4,194 |

Unchanged by the fix, as required — `0u4tu8`'s signatures are null, so the Schnorr arm bills 0 — and
still matching **consensus** against libauth's outlying 1.

**sigChecks, 4,467 metric-comparable vectors** (agree / LeanBCH over / LeanBCH **under**):

| reference | before | after |
|---|---|---|
| libauth | 2,229 / 1,912 / 326 | **2,799 / 1,342 / 326** |
| **BCHN (`bchn-leg`)** | 1,549 / 2,594 / 324 | 1,759 / ~~2,384~~ / 324 |

> **The BCHN `over` column above is measured against a broken comparand — see
> "The comparand was broken" below. All four triples were re-derived from scratch on 2026-07-21 and
> reproduce exactly, so the numbers are right about what they measured; what they measured is not
> what the column name says. Against BCHN's *real* accrual the after-triple is
> `2,195 / 1,948 / 324`.** The `agree` and `under` columns are unaffected.

**THE SOUNDNESS DIRECTION — LeanBCH billing LESS than BCHN.** 324 vectors bill under BCHN. **All 324
are vectors LeanBCH REJECTS** (BCHN accepts them), and **0 are new** — the fix introduced none. On the
1,817 vectors LeanBCH **accepts**, the split vs BCHN is **under 0 / agree 1,547 / over 270**, both
before and after. An under-bill on an *accepted* input is the only route from a cost defect to a
wrong ACCEPT, and there are none.

Cause of the 324, established structurally rather than assumed: all 324 are `core.signing-serialization`
Schnorr-multisig vectors whose locking script carries **four** signature ops (e.g. `lrceng`, `7gnse0`:
`… OP_CHECKMULTISIG OP_VERIFY … OP_CHECKMULTISIGVERIFY …`, with a non-empty `<0b1>`/`<0b10>` checkbits
dummy). LeanBCH errors at the *first* CHECKMULTISIG with a non-empty dummy — the deferred branch at
`LeanBCH/VM/Extended.lean:228` — and so never executes, and never bills, the remaining three. That is
deferral of **execution**, not a billing error, and it is the same population as the 216 deepened
libauth-relative under-bills recorded above. This closes the item the fix-time run left open ("cannot
assert per-vector consensus agreement on those 216 without a BCHN leg over the corpus").

**The historical `1,255 / 1,360 / 2` triple is confirmed NOT reproducible.** Searched systematically,
not asserted: 11 candidate partitions × {libauth, BCHN} × {before, after} yields **no** combination
producing that triple, and **no** partition has 2,617 members — the sizes tried run 840, 1,155,
1,157, 1,157, 1,367, 1,908, 3,661, 3,663, 3,663, 4,467, 5,803, straddling 2,617 without hitting it
(the multisig families hold 1,908 vectors in total, 1,367 metric-comparable). Its **"under =
2" column does reproduce exactly**, however: `0u4tu8` and `g8xdap`, both `m-of-15`, both LeanBCH 0 /
libauth 1 / **BCHN 0** — LeanBCH matches consensus and libauth is the outlier (LBCH-2026-003). The
multisig partition that *is* reproducible, on the 1,155 verdict-agreeing multisig vectors: before
333 / 820 / 2 → after **477 / 676 / 2**.

*Mode note:* `--mode consensus` and `--mode standard` give identical BCHN `sig_checks` on 4,466 of the
4,467 vectors. The single exception is `g49kxl` (a `nonstandard`-variant `m-of-20` vector), where
consensus accepts with 20 and standard rejects with 0; consensus is the correct referee for a
`nonstandard` vector, and LeanBCH bills 20 there, agreeing. So the table is mode-independent in
substance.

### The comparand was broken — the `2,384` headline is RETIRED (2026-07-21)

**RETIRED CLAIM, quoted verbatim so it is not quietly edited away.** The re-measurement section above
and `conformance/RESULTS.md` both carried this explanation of the 2,384:

> *"documented upper-bound behaviour on rejected vectors where a non-empty signature fails
> verification — harmless and inherent to billing without an oracle"*

and the headline it explained:

> *"`vs BCHN … after 1,759 / 2,384 / 324`"* — read as *"LeanBCH over-bills BCHN on 2,384 vectors."*

**That reading is void, and the explanation was never tested.** BCHN's `VerifyScript`
(`bchn-src/src/script/interpreter.cpp:2677`) accumulates into a **local** `metrics` (`:2691`) and
copies it into the caller's `metricsOut` at exactly two sites — `:2745` and `:2794` — **both success
returns**. Upstream's own comment at `:2744` reads *"must set metricsOut for all successful returns"*.
Every failure return leaves `metricsOut` untouched. `bch-conformance`'s leg passes a
default-constructed object (`legs/bchn/bchn-leg.cpp:315`) and reads it unconditionally (`:323-325`),
so **on every reject it reports `0/0/0` — an initializer, not a measurement.**

*Measured, not inferred.* Over all 5,803 vectors of the 11 signature families under
`--mode consensus`, the leg's **3,453 rejects span 9 distinct `native_error` classes and have exactly
ONE distinct metric signature: `op_cost=0, hash_iters=0, sig_checks=0, op_cost_limit=null`.** Positive
control: `op_cost_limit` is populated on **2,350/2,350 accepts and 0/3,453 rejects** — precisely the
`SetScriptLimits`-at-`:2695`-copied-only-on-success signature. Vector `ruwzjq` is self-refuting: BCHN
rejected it *for exceeding the VM cost limit* while reporting `op_cost = 0`.

**The comparand was then repaired rather than abandoned.** `conformance/evidence/bchn-partial-probe.cpp`
transcribes `VerifyScript`'s body verbatim — same flags, same order, same `EvalScript` calls, same
P2SH / CLEANSTACK / INPUT_SIGCHECKS gates — with one change: the metrics object is the caller's, so
BCHN's real accrual up to its error point is observable. BCHN's sources are **not** modified; it links
the same static libs as the leg. *Probe validated before use:* over all 5,803 vectors it agrees with
`bchn-leg` on **5,803/5,803 verdicts**, on the `native_error` string for **all 3,453 rejects**, and on
**all three metrics for all 2,350 accepts**.

**THE PARTITION — every one of the 2,384 assigned to a measured cause, no residual bucket.**
Per-vector artifact: **`conformance/evidence/LBCH-2026-001-overbill-partition.tsv`** (4,467 rows,
engine versions in its header, one `cause` column per vector).

| cause | n | what BCHN actually did |
|---|---|---|
| `A-leg-artifact-agree` | **436** | LeanBCH's count **equals** BCHN's real accrual. Pure instrument artifact. |
| `B1-sig-verify-fail` | **638** | Aborted at `SIG_NULLFAIL`: a non-empty signature failed verification. |
| `B2-sig-encoding-fail` | **1,052** | Aborted at `SIG_HASHTYPE` (666) / `SIG_NONSCHNORR` (276) / `SIG_BADLENGTH` (110): a non-empty signature failed **encoding**. |
| `D1-pubkey-encoding-fail` | **26** | Aborted at `PUBKEYTYPE` — the **pubkey**, not a signature, was malformed. |
| `D2-checkbits-malformed` | **232** | Aborted at `INVALID_BIT_COUNT` (228) / `INVALID_BITFIELD_SIZE` (4) — **before reaching any signature at all**. |
| | **2,384** | sums exactly. |

So **1,948 are genuine over-bills** against BCHN's real accrual and **436 are not**. Both of the
prior candidate explanations were wrong in opposite directions: the 2,384 is *not* wholly artifact
(only 436 is), and the stated "non-empty signature fails verification" story covers **1,690** of it
(`B1`+`B2`), not all — `D1`+`D2` (**258**) are cases where BCHN never reached a signature check.

**MECHANISM, source-verified on both paths.** *BCHN tallies a signature check only after that check
has passed.* Schnorr multisig: encoding check `interpreter.cpp:1598`, `CheckSig` `:1606`, `SIG_NULLFAIL`
return `:1611`, and only then `TallySigChecks(1)` at `:1616`. Legacy ECDSA multisig: the `SIG_NULLFAIL`
return sits at `:1686`, **before** the bulk `TallySigChecks(nKeysCount)` at `:1692` — so a failed ECDSA
multisig carrying a non-null signature tallies **nothing**, not `nKeysCount`. Every raise site for all
seven error classes above was grepped and lies inside `case OP_CHECKSIG/VERIFY` (`:1399-1448`),
`OP_CHECKDATASIG/VERIFY` (`:1449-1495`) or `OP_CHECKMULTISIG/VERIFY` (`:1496-1710`). LeanBCH bills the
leading non-empty signature run; BCHN's accrual stops at, and **excludes**, the first failing
signature. Measured consequence: `leanSig ≥ bchnTrueSig` on **all 1,948**, deltas 1–20, **never below**.

**Soundness re-checked against the repaired comparand — unchanged.** Under-bills vs BCHN's real
accrual: still exactly **324**, all on vectors LeanBCH **rejects**, **0** on a LeanBCH accept. On the
**1,547** vectors both engines accept, LeanBCH equals BCHN **1,547/1,547 exactly**. The `over 270` on
LeanBCH-accepts is **real, not artifact** (identical against leg and probe): all 270 are
`core.signing-serialization` invalid vectors where BCHN stops at `SIG_HASHTYPE` — the already-documented
`SIGHASH_UTXOS|ANYONECANPAY` check LeanBCH is missing, which is why it wrongly accepts *and* bills more.
That is the known verdict defect, not a new billing one.

**Hypothesis tested and REFUTED: there is no libauth-vs-BCHN divergence class on measurable ground.**
The set where LeanBCH and libauth agree with each other but differ from the leg's BCHN is **1,042**;
against BCHN's *real* accrual it shrinks to **606**, and **all 606 are BCHN rejects**. On the **2,081**
vectors BCHN **accepts** — the only population where both counters run to completion — **libauth
differs from BCHN on 0**. The apparent 1,040-vector gap was the zeroed counter, plus the genuine
tally-ordering difference below.

**LBCH-2026-003 is CORROBORATED, now against a real BCHN number.** On `0u4tu8` and `g8xdap` BCHN's
*measured* accrual is `sigChecks 0, hashIters 10, opCost 4,194` — which LeanBCH matches on **all three
metrics exactly**, while libauth bills `1 / 22`. These are the only 2 of 2,386 BCHN rejects where
LeanBCH matches BCHN on all three. libauth `crypto.js:177` increments `signatureCheckCount` **before**
the Schnorr-length check at `:184` and **before** `verifySignatureSchnorr` at `:187`; BCHN tallies at
`interpreter.cpp:1616`, after both. Measured reach: libauth over-bills BCHN's real accrual on **900**
vectors (640 `SIG_NULLFAIL`, 260 `SIG_NONSCHNORR`), **all rejects**, and **under-bills on 0**.
*Third-party — RECORDED here, not published; the advisory charter clocks remain unstarted.*

### The 570-vs-210 asymmetry — real, not instrumental

The fix produced **570** newly-agreeing vectors against libauth but only **210** against BCHN, with
**0** newly *disagreeing* against either. The 210 are a strict subset of the 570, and all 210 are
**BCHN-accepts**; the 360-vector shortfall is entirely **BCHN-rejects**.

**The tempting explanation — "BCHN's counter is a hard 0 on those 360, so the fix's true reach is 570
and BCHN merely cannot score it" — was tested with the repaired probe and is FALSE.** Re-scored against
BCHN's real accrual, the newly-agreeing count vs BCHN is **still 210**; **0 of the 360 become
agreeing**. On all 360, LeanBCH's post-fix count equals libauth's *and* sits exactly **1 above** BCHN's
real accrual (254 + 64 at `lean=libauth=1, bchnTrue=0`; 24 + 18 at `lean=libauth=2, bchnTrue=1`).

The asymmetry is therefore a property of **libauth**, not of the instrument and not of LeanBCH: the fix
moved LeanBCH from per-key onto **libauth's** per-signature number, and on rejected vectors libauth's
number is itself one-too-high relative to consensus, by the `crypto.js:177`-before-`:187` ordering above.
Alignment with libauth bought alignment with BCHN on exactly the 210 vectors where libauth *is*
consensus-faithful — the accepts, where the two agree on 2,081/2,081. Against BCHN's real accrual the
fix moved the triple `1,985 / 2,158 / 324` → `2,195 / 1,948 / 324`: a genuine 210-vector improvement.

### Leg defect, for the record

`bch-conformance/legs/bchn/bchn-leg.cpp:323-325` should emit `null` for `op_cost` / `hash_iters` /
`sig_checks` when `!ok`, as `costprobe` already does honestly (`SKIP <id> no-metric-phase`). Until it
does, **every reject-inclusive BCHN metric comparison reproduces this artifact.** `sig_checks_limit`
(`:331-333`) is computed from `scriptSig.size()` independently and stays valid. Not fixed here — it
lives in another repo, and this run routed around it with the probe instead.

### Measured

Over the 2,617 verdict-agreeing multisig vectors (`conformance/RESULTS.md`, CHECKMULTISIG section):

| metric | agree | LeanBCH over | LeanBCH **under** |
|---|---|---|---|
| `signatureCheckCount` | 1,255 | 1,360 | **2** |
| `hashDigestIterations` | 2 | 950 | **1,665** |
| total consensus `opCost` | 2 | 1,360 | **1,255** |

Worst observed under-bill: **−26,768** on vector `0u4tu8` — larger than one whole signature check
(26,000), so this is not a rounding-scale disagreement.

Per-arity `signatureCheckCount` shape (verdict-agreeing vectors of the three `m-of-N` families that
declare their key count in the family name):

| n (keys) | LeanBCH bills | libauth bills | vectors |
|---|---|---|---|
| 3 | 3 | 0 / 1 / 2 / 3 | 270 / 210 / 30 / 36 |
| 15 | 15 | 0 / 1 / 15 | 18 / 30 / 8 |
| 20 | 20 | 0 / 1 / 2 / 20 | 46 / 112 / 12 / 26 |

### Why this was invisible until now

Under `Secp256k1.reject` — the only oracle that existed in the tree before 2026-07-21 — a non-empty
signature NULLFAILs *before* its cost is compared to anything. The `26000 · signatureCheckCount` term,
the single largest term in the cost model, was therefore **never observable**, and
the "UNDER-MODELED" note then standing in the `Cost/Sig.lean` header (rewritten by the fix) was never
quantified. Binding a real verifier made the
term measurable for the first time; this finding is the immediate result.

### Honest bound — what this is NOT

This is a **metric divergence, not a demonstrated consensus divergence.** Comparing each vector's cost
against its own per-input budget `(41 + |scriptSig|) · 800`: libauth exceeds budget on 4 of 4,467
vectors, and there are **zero** vectors where LeanBCH stays within budget while libauth exceeds it.
So no wrong-accept is reachable from this corpus.

A vector engineered to sit between the two totals is **not** ruled out, and the under-billing
direction is exactly the one that would matter if such a vector existed. Absence of a witness in this
corpus is not absence of a witness.

### Resolved: which rule is right (2026-07-21)

**BCH-2026 consensus, as deployed, bills the declared key count as an upper bound — not the checks
performed.** BCHN `src/script/interpreter.cpp:1690-1692`:

```cpp
if (!areAllSignaturesNull) {
    // This is not identical to the number of actual ECDSA verifies, but, it is an upper
    // bound that can be easily determined without doing CPU-intensive checks.
    metrics.TallySigChecks(nKeysCount);
}
```

and `:1616` bills `TallySigChecks(1)` per signature on the Schnorr-multisig path. libauth matches
this exactly; so does LeanBCH's `kappa`. **The rule is not the defect** — so the open question is no
longer "which side is right" but "why do implementations of the same rule disagree by 1,360 vectors".

Note that libauth is a pinned witness rather than the referee, and it independently bills `OP_DEFINE`
incorrectly (RustBCH `ADVISORIES/RBCH-2026-001.md`) — so a libauth disagreement is never by itself
proof of a LeanBCH bug. Here BCHN was read directly and settles it.

---

## LBCH-2026-002 — the cost-differential evidence was ephemeral, and its summary was false

**Class:** evidence-integrity · **Found:** 2026-07-21 by adversarial re-verification of `4f2fe4e`

### Two defects, one root

**(a) A false summary sentence.** `conformance/RESULTS.md` stated that the 288 rejecting non-multisig
vectors "differ only by **+1 `stackPushedBytes`** each". Re-verification — using an independently
written libauth driver that reproduced every *other* figure in that section exactly — found this
false: a subset also differ in `signatureCheckCount` and `hashDigestIterations`, i.e. **in the very
`26000·sigChecks` term the section claims to have validated**, reported as a one-byte push accounting
difference. Corrected in place, with the original sentence quoted rather than silently replaced.

**(b) The measurement left no artifact.** `costprobe` was built, run, and compared — but **no
per-vector output was committed**. The 756/288 split, and the correction above, cannot be re-derived
from anything in this repository; only by rebuilding a libauth reference driver and re-running the
whole comparison. The reported subset size (72 of 288) is therefore recorded as **UNREPRODUCED**: it
is attributed to the verifier, not independently re-derived.

(b) is why (a) survived to be committed. A generated, committed artifact would have made the false
sentence checkable by inspection.

### Aggravating detail

At least three separate `@bitauth/libauth` 3.1.0-next.8 installs are reachable in this estate —
`optimizer/node_modules/`, the path hard-coded at `conformance/cost/gen.mjs:13`, and RustBCH's. A
cost comparison that does not state which install it used is not reproducible even in principle.

### Remediation

`costprobe` should emit a committed per-vector TSV under a conformance evidence directory, and the
summary prose in `RESULTS.md` should be **rendered from that artifact** rather than hand-written
beside it. This is the general lesson from a day in which every false statement found across this
estate was in hand-written prose *summarising* a sound measurement — never in a measurement.

### Progress (2026-07-21) — still OPEN, but the practice is now in place

Two per-vector artifacts now exist and carry engine + corpus versions in their headers:
`conformance/evidence/LBCH-2026-001-fix-deltas.tsv` (1,486 rows) and
`conformance/evidence/LBCH-2026-001-threeway.tsv` (4,467 rows, three engines). The remediation was
exercised end-to-end and **worked**: a later run independently reproduced all 1,486 rows of the first
artifact on three columns with 0 mismatches, which is exactly the checkability (b) asked for.

**Why the finding stays OPEN.** (i) The *original* ephemeral measurement is still not re-derivable —
its "2,617 verdict-agreeing multisig vectors / 1,255 / 1,360 / 2" was searched for systematically
(11 candidate partitions × {libauth, BCHN} × {before, after}) and **no** combination reproduces it,
so the recorded triple cannot be checked and remains history rather than evidence. Its "under = 2"
column is the one part that does reproduce. (ii) The 756/288 split and the "72 of 288" subset of (a)
are still **UNREPRODUCED** — no run since has re-derived them. (iii) The prose in `RESULTS.md` is
still hand-written beside the artifacts, not *rendered from* them, so the failure surface that let
(a) through is unchanged.

---

_Related: `conformance/RESULTS.md` (measurements), `TRUST_MANIFEST.md` (tiers),
RustBCH `docs/VERIFICATION-ARCHITECTURE.md` (why prose beside a measurement is the failure surface)._
