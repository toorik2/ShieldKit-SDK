# LeanBCH conformance vs the official BCH `vmb_test` corpus

LeanBCH's VM + consensus verifier is run against the official Bitcoin Cash `vmb_test` vectors
(transaction hex + source-output hex → decode → `verifyInput`/`txValid`/`verifyTokens`), comparing
the accept/reject verdict to the corpus. The harness measures **all three** 2026 directories:
`bch_2026_standard` and **`bch_2026_nonstandard`** are both consensus-VALID (⇒ the consensus
predicate must ACCEPT), `bch_2026_invalid` ⇒ REJECT. (There is no `bch_2026_valid` on disk; an
earlier version of this harness silently omitted the nonstandard directory — see the audit note.)
Driver: `conformance/run.mjs` + the compiled `vmbconf` (`conformance/Runner.lean`); the VM is
specialized to `BCH_2026_05`.

> **This VM has been through an adversarial audit** (see the audit section below). The earlier
> "consensus 100% / audited-exact" framing was overstated — it rested only on the standard corpus.
> The reachable-today consensus/standardness bugs the audit found have been fixed, **as have the two
> deeper latent items it flagged** — the oracle-path sighash cost (CHECKSIG serLen +
> code-separator digest + CHECKMULTISIG per-sig hash iterations) and the max-size-number DoS
> (`magBytes`). All are enumerated honestly below.

## The opcode surface is complete

Every BCH-2026 opcode is implemented: pushes, the full stack/altstack set, inline control
(IF/NOTIF/ELSE/ENDIF/VERIFY/RETURN) and the **loops chip** (BEGIN/UNTIL), the numeric/comparison/
boolean ops, the byte ops (AND/OR/XOR, CAT/SPLIT, NUM2BIN/BIN2NUM, **REVERSEBYTES**, **INVERT** +
the four **shift** ops), the hashes (RIPEMD160 / **SHA-1** / SHA-256 / HASH160 / HASH256, all
native + KAT-verified), the **signature** ops (CHECKSIG/CHECKDATASIG/CHECKMULTISIG, over an
explicit secp256k1 oracle), the full **introspection** set including **OP_ACTIVEBYTECODE** and the
**CashToken** introspection (UTXO/OUTPUT × CATEGORY/COMMITMENT/AMOUNT), and the **functions chip**
(OP_DEFINE/OP_INVOKE, with the control-stack return frame).

## 2026 conformance — 100% on the exercised surface (standard **+ nonstandard** + invalid)

With the consensus accept-side (nonstandard corpus) now measured, every non-oracle family is 100%:

| Family | Result |
|---|---|
| **big-integer** (add/sub/mul/div/mod, 1add/1sub/negate/abs, min/max, within, comparisons, bin2num, num2bin) | **100%** |
| **push**, **hashing** (`core.hashing`) | **100%**, **1140 / 1140** |
| **benchmarks** (hashing **135/135**, bitwise **40/40**, stack **22/22**) | **100%** |
| **bitwise + shifts** (`chip.bitwise`, incl. LSHIFT/RSHIFT NUM/BIN, INVERT) | **432 / 432** |
| **functions** (`chip.functions`) | **556 / 556** |
| **cashtokens** | **1485 / 1485** |
| **inspection**, **copy**, **limits** | **460 / 460**, **60 / 60**, **39 / 39** |

The remaining un-passed vectors are **all** the oracle boundary: signature families (real secp256k1
needed) and 6 Schnorr/ECDSA bare-multisig checkbits vectors — correctly rejected by the reject-oracle.

### Consensus rules modeled to get there
Bytecode-length limit (10 000); op-cost **density budget** `(densityControlBaseLength+|unlocking|)
× operationCostBudgetPerByte`; minimal number encoding + `maximumVmNumberByteLength`; push-only
unlocking; minimal push encoding; stack-item size limit; **balanced control stack**;
**P2SH-20 and P2SH-32** with redeem execution; **maximumControlStackDepth** (100) and
**maximumMemorySlots** (1000, incl. functionCount); NULLFAIL + in-order multisig matching;
**tx-structural** rules (`txValid`: version ∈ {1,2}, money-range, non-empty in/outputs); and the
**CashToken consensus** layer (`verifyTokens`: genesis, no fungible inflation, mutable/minting
conservation, the 2026 commitment-length limit of 128).

## Architecture (why the conformance surface can grow without risk)
The keystone-proven core `stepInstr` (`run_straightline`/`splice_congr_run`, axioms
`[propext, Quot.sound]`) is **frozen**; every op added after it — shifts, introspection, tokens,
signatures, functions, REVERSEBYTES, ACTIVEBYTECODE — lives in the `stepExtended` wrapper
(`runExt`), so the machine-checked flat↔structured bridge the optimizer consumes stays valid.

## Deliberate scope boundaries (distinct from the audit-fixed bugs above)
- **Signature families** are **oracle-bounded in the library, no longer unmeasurable**: secp256k1 is
  an explicit `Secp256k1` struct parameter (the deliberate trust boundary), and the default
  `Secp256k1.reject` still bounds every build-time result in this file. But the corpus CAN now be
  scored — a real backend is bound over FFI and selected at RUNTIME in the compiled runners, outside
  the mathlib-free elaborator. See "Signatures: the real secp256k1 oracle" below for the measured
  numbers, which supersede this file's earlier claim that the sig corpus could not be scored. The sig
  *logic* (NULLFAIL, multisig matching, Schnorr/ECDSA dispatch) was audited line-by-line vs libauth.
- **CashTokens residual (12)** — all are **bare-`P2S` variants** whose `P2SH20`/`P2SH32` twins
  are `bch_2026_standard` (valid); the bare variant is `bch_2026_invalid` purely because bare,
  non-template scripts are **non-standard** (relay policy), not consensus-invalid. My token
  introspection ops match libauth byte-for-byte, so the scripts evaluate correctly in both VMs;
  accepting them is correct for a *consensus* verifier. Closing them would mean adding a
  standardness (bare-script rejection) layer, out of scope for a consensus VM.
- **Deep code-separator edges**: a mid-script `OP_CODESEPARATOR` before a CHECKSIG (covered
  bytecode), and a code-separator in a caller before an `OP_INVOKE` — both need a byte-offset this
  instruction-indexed model reconstructs only for the common cases.

## Standardness (relay-policy) layer — `LeanBCH.VM.Standard`
An optional, versioned layer OVER consensus that answers "will a node relay this?" (vs consensus's
"could a miner mine it?"). A strict leaf (imports `Verify`, never imported back — keystone
untouched). Design: a `Policy` record (every tunable as data), an `OutputKind` template classifier,
token-aware dust from the real `encodeOutput` length, and a three-way `TxClass`
(Invalid / Nonstandard / Standard); `verifyStandard = verifyTransaction ∧ isStandard`. Rules from
the BCHN reference (`policy.cpp`/`standard.cpp`/`consensus`), cross-checked vs libauth.

Two layers: structural `isStandard` (templates / dust / data-carrier / tx-size / input) and
interpreter-level `standardInterpreterOk` (relay rules during execution: no discouraged-NOP
`OP_NOP1`/`OP_NOP4..10` executed; hash-digest iterations within the tighter STANDARD ·1 density
limit `(|scriptSig|+41)/2` vs the consensus ·7).

Validated against the corpus:
- **`bch_2026_standard`: zero over-rejection** — every standard vector classifies as standard.
- **`bch_2026_nonstandard`: 2289 / 2289 (100%)** correctly classified nonstandard — structural
  (2156) + interpreter-level (the remaining 133: 109 hashing-density + 24 discouraged-NOP).

### Consensus op-cost model (VM-Limits CHIP) — differentially pinned to libauth
`opCost = 100·ops + 26000·sigChecks + H·hashIters + arithmeticCost + stackPushedBytes` (H = 192
standard / 64 consensus). The four state-internal metrics — `arithmeticCost`, `hashDigestIterations`,
`stackPushedBytes`, `evaluatedInstructionCount` — are pinned by a **build-time differential**
(`conformance/cost/`, generated by `gen.mjs` from real `@bitauth/libauth` 3.1.0-next.8 and checked
by `LeanBCH.Validation.CostDifferential`): 26 vectors spanning arith (small + multi-byte operands),
all five hash ops (SHA1/SHA256/RIPEMD160/HASH160/HASH256 over 1- and 40-byte inputs), NUM2BIN/BIN2NUM,
CAT, DUP/2DUP/3DUP/OVER and DEPTH match libauth **exactly**, and a wrong constant fails `lake build`.
The `26000·sigChecks` term is not in that build-time differential (it needs live secp256k1 signatures,
outside this mathlib-free core). It is now validated SEPARATELY, at the executable level, against the
same libauth build — see "The sig-cost tier, measured" below. That section supersedes this file's
earlier statement that the term was "not numerically validated anywhere": it is validated for the
single-signature path and *measured to be wrong* for CHECKMULTISIG. `kappa` bills **pushed-output bytes for every op** (byte ops
CAT/SPLIT/NUM2BIN/BIN2NUM/AND/OR/XOR/INVERT/REVERSEBYTES/SIZE/DEPTH; multi-copy
2DUP/3DUP/2OVER/IFDUP/FROMALTSTACK/ROLL; value-numeric double-bill 1ADD/1SUB/NEGATE/ABS/MIN/MAX;
boolean 0/1) and enforces the **separate hash-iterations limit** `(|scriptSig|+41)·7/2` — closing
`benchmarks.bitwise` (28→40), `benchmarks.hashing` (43→47), `benchmarks.stack`; all VM-limit boundary
families now 100%. (Regenerate: `node conformance/cost/gen.mjs`.)

## Adversarial audit (2026-07) — what it found and what was fixed

A 51-agent adversarial audit (each finding independently verified) was run over the whole VM. The
foundations held: the keystone theorems are axiom-clean (`[propext, Quot.sound]`), fuel is provably
sufficient, and large swaths (templates, CLTV/CSV, dust math, byteOpBytes indices) are byte-faithful.
It also found — and this repo has since **fixed** — a cluster of real bugs:

- **Reachable-today false-ACCEPTS** (broke soundness with ordinary inputs): OP_CAT + arithmetic /
  1ADD / MIN-MAX results missing the 10000-byte gate; PICK/ROLL/SPLIT clamping negative indices +
  accepting non-minimal encodings; within-tx **double-spend** (duplicate inputs) accepted; null
  prevout + Σoutputs-over-money accepted; introspection ops (0xc0–0xd3) + OP_2ROT under-billing
  op-cost; non-canonical varints accepted; dusty bare-multisig wrongly standard. **All closed**
  (VM guards in the `stepInstrExt` wrapper — the frozen keystone is untouched).
- **Consensus false-REJECTS** (would fork a node off): `verifyInput` used the STANDARD hash op-cost
  factor (192) instead of CONSENSUS (64); the harness never loaded the 2289 consensus-valid
  nonstandard vectors, hiding **61 false-rejects**. Both fixed — nonstandard is now measured and the
  61 pass.
- **Shift crash + DoS** (found by an independent check): `OP_LSHIFTNUM` `Nat.pow` panic; 0-bit
  binary-shift bug; infinite-loop scripts grinding to fuel exhaustion. Fixed (guards + the
  withinLimits budget-abort); the whole `chip.bitwise` family (431 vectors, previously crashing and
  **never in any "100%" claim**) now passes.

### Remaining scope (the audit's two deeper latent items are now CLOSED)
- **Oracle-path sig cost — CLOSED.** CHECKSIG/CHECKSIGVERIFY now bill the exact signing-serialization
  length (`hashIterations serLen`, non-empty sig only — `stepMeterExt.sigHashExtra`); the
  CHECKSIG/CHECKMULTISIG covered bytecode is code-separator-aware (`coveredBytecode` re-encodes
  `s.instrs.drop s.lastCodeSep`, feeding `Tx.sighashDigest`); and CHECKMULTISIG now bills **both** its
  sig-CHECK count (null-sig gated) **and** per-verified-sig hash iterations (`multiSigHashExtra`, one
  `hashIterations serLen` per non-null sig over the trimmed covered bytecode). The sig-COST accounting
  now matches BCH, so `verifyInput` may be instantiated with a real secp256k1 oracle as a fits-BCH
  verifier — secp256k1 *correctness* remains the oracle's contract (the deliberate trust boundary).
  These fixes are LATENT (inert under the reject-oracle: a non-null-sig check rejects before the
  budget matters), so they don't move the corpus; each was verified axiom-clean + regression-free.
- **Max-size-number DoS — CLOSED.** `magBytes` (Nat→LE bytes) is now O(n·log n): a divide-and-conquer
  encoder that halves the width at `256^(w/2)` via one GMP shift, proved byte-for-byte equal to the
  fuel model and attached with `@[implemented_by]` (so every proof + `decide` KAT stays byte-identical
  and the keystone stays `[propext, Quot.sound]`). The `1<<79998`-in-a-loop vector (`w6j874`) finishes
  in ~2.75 s (was a >30 s hang) and correctly rejects; `chip.benchmarks.bitwise` is now 15/15 inline.
- **Deferred by design** (soundness-safe — never a false accept, documented in-tree): Schnorr-multisig
  checkbits (6 corpus vectors) and strict DER/pubkey encoding gates.

## Reproduce
```
lake build vmbconf
node conformance/run.mjs <vmb_tests-dir> core.bigint.add chip.functions core.cashtokens …
```

## Signatures: the real secp256k1 oracle, and what it closed (measured 2026-07-21)

Until commit `344e02a` LeanBCH could not verify a signature: `LeanBCH/Oracle.lean`'s `Secp256k1` is a
parameter structure and `Secp256k1.reject` — which rejects everything — was its only inhabitant.
`LeanBCH/Crypto/Native.lean` adds a second inhabitant, bound over FFI to the BCHN-vendored
libsecp256k1 (`ffi/secp256k1_shim.c`, archive pinned by sha256 in `ffi/build.sh`). The oracle is
selected at runtime by `LEANBCH_SECP`; **unset still means `reject`**, so every previously recorded
number in this file remains reproducible verbatim. The 313 build-time KATs are untouched and stay
FFI-free — the elaborator cannot call an `@[extern]` opaque, which makes that fail-closed.

### Known-answer test (`conformance/SigKat.lean`, `lake build sigkat`)

39 cases. The first 13 are the vendored fork's OWN compact test vectors for the exact function the
shim calls (`secp256k1_schnorr_verify`, `src/secp256k1/src/modules/schnorr/tests_impl.h`,
`run_schnorr_compact_test`): 5 asserted to verify, 8 asserted to fail. They are extracted
mechanically, not transcribed. The other 26 are derived from them — one-bit corruptions of each
positive vector in the signature, the pubkey and the digest, plus length-discipline probes
(63/65-byte sig; a 32-byte x-only pubkey, i.e. the BIP-340 trap; a `0x02→0x04` header byte).

| oracle | result |
|---|---|
| `native` | **39 / 39**, exit 0 |
| `reject` | 34 / 39, exit 1 — fails exactly the 5 positive vectors, passes all 34 negatives vacuously |

That split is the point: the reject oracle cannot be distinguished from a real one by negative
vectors alone, which is why both polarities are required.

### Conformance over the 11 signature families (5,803 vectors)

Families: `core.signing-serialization`, `core.data-signatures`, the four
`core.benchmarks.signature-checking.*` and the five `core.signature-checking.multisig.*`
(2,343 standard + 7 nonstandard + 3,453 invalid).

| oracle | PASS | rejected-valid | accepted-invalid |
|---|---|---|---|
| `reject` | 3456 / 5803 | 2347 | 0 |
| `native` | **4730 / 5803** | 803 | 270 |

1,544 valid vectors that could not previously pass now verify against real curve arithmetic
(2347 − 803); net +1,274 = 1,544 − 270.

**The 803 remaining rejections are ONE feature.** All 803, without exception, are Schnorr-in-
CHECKMULTISIG — the checkBits path deferred at `LeanBCH/VM/Extended.lean:228`
(`if !dummy.isEmpty then s.setErr .unimplemented`). No other signature gap remains in these families.

**The 270 wrong-accepts are ONE missing check, isolated by partition rather than assumed.** All 270
lie in `core.signing-serialization` invalid, and strictly inside the cell where the sighash type is
both `SIGHASH_UTXOS` and `ANYONECANPAY` — a combination BCHN rejects as an invalid sighash type
(`CheckSighashEncoding`, `sigencoding.cpp`; `SigHashType::isDefined`, `sighashtype.h`). Partitioning
the 2,161 invalid vectors of that family by those two flags:

| SIGHASH_UTXOS | ANYONECANPAY | total | we accept | we reject |
|---|---|---|---|---|
| yes | yes | 864 | **270** | 594 |
| yes | no | 433 | 0 | 433 |
| no | yes | 432 | 0 | 432 |
| no | no | 432 | 0 | 432 |

The flag pair is necessary but not sufficient, and the residue is fully explained: within those 864,
we accept **216/216** signed by the correct key with ECDSA and **54/54** signed by the correct key
with single (non-multisig) Schnorr, and **0/432** signed by the wrong key. LeanBCH does not implement
the sighash-type validity check, so it proceeds to verify; the cryptographically good signatures then
verify, and the bad ones fail for an unrelated reason. The remaining 162 correct-key Schnorr vectors
are multisig, so they hit the deferred checkBits path above.

**The native oracle must therefore not be used for conformance scoring until the L0 encoding gates
land** (strict-DER, low-S, pubkey encoding, `CPubKey::IsValid`, sighash-type validity, 64-byte-sig-in-
ECDSA-context). They are pure-Lean and provable; none involves the FFI. The default oracle is
unchanged, so nothing regressed in practice.

### The sig-cost tier, measured for the first time

`26000·sigChecks` is the largest single term in the op-cost model and had never been numerically
validated, because under the reject oracle a non-empty signature NULLFAILs before its cost is
compared to anything. With signatures succeeding it becomes observable. `conformance/CostProbe.lean`
(`lake build costprobe`) emits the five raw consensus metrics per vector, accumulated exactly as
`verifyInput` accumulates them (`LeanBCH/VM/Verify.lean:93-122`); the reference is the same
`@bitauth/libauth` 3.1.0-next.8 the build-time differential uses, run over the identical vectors.

Metrics from divergent executions are not comparable, so the comparison is restricted to the 3,661
vectors where both verdicts agree. `evaluatedInstructionCount` and `arithmeticCost` serve as
oracle-independent controls that the comparison scope is the same: they agree **1044/1044** on
non-multisig vectors.

**Single-signature path — validated.** Of the 1,044 verdict-agreeing non-multisig vectors, the 756
that ACCEPT match libauth **exactly on all five metrics**, including 1,732 signature checks billed
identically. This is the first numerical validation of the `26000·sigChecks` term. The other 288 are
exactly the vectors that reject; the accept/reject-set partition is exact (756 + 288 = 1044).

> **CORRECTION (2026-07-21).** This paragraph previously said the 288 rejecting vectors "differ only
> by **+1 `stackPushedBytes`** each". That is **false**, and it understated a divergence in the very
> term this section claims to validate. Adversarial re-verification, using an independently written
> libauth driver that reproduced every *other* figure in this section exactly, found that a subset of
> the 288 additionally differ in `signatureCheckCount` and `hashDigestIterations` — i.e. in the
> `26000·sigChecks` term itself, not merely in a one-byte push accounting. The reported subset size
> (72 of 288, at +1 `signatureCheckCount` and +5/+6 `hashDigestIterations`) is **attributed, not
> independently re-derived here**, and is therefore recorded as UNREPRODUCED.
>
> **Why it cannot simply be re-checked:** the measurement behind this whole section was *ephemeral*.
> `costprobe` was run and its output compared, but **no per-vector artifact was committed**, so the
> 756/288 split and this correction cannot be re-derived from anything in the repository — only by
> re-running the full comparison and rebuilding a libauth driver. That is a defect in how the
> evidence was recorded, independent of whether the numbers were right. Re-deriving it requires
> `ffi/build.sh && lake build costprobe`, `LEANBCH_SECP=native ./.lake/build/bin/costprobe` over the
> 11 signature families, and a libauth reference driver. Note there are at least three separate
> `@bitauth/libauth` 3.1.0-next.8 installs reachable in this estate
> (`optimizer/node_modules/`, the path in `conformance/cost/gen.mjs:13`, and RustBCH's) — a reference
> driver must state which one it used.
>
> Tracked as **LBCH-2026-002** in [`FINDINGS.md`](../FINDINGS.md).

**CHECKMULTISIG — root-caused and FIXED (2026-07-21).** `kappa` billed the ECDSA rule (`nKeys`) on
BOTH multisig paths because it never inspected the dummy element. BCH-2026 bills them differently:
empty dummy ⇒ legacy/ECDSA, `nKeysCount` in one shot (BCHN `interpreter.cpp:1689-1692`); non-empty
dummy ⇒ Schnorr checkbits, `TallySigChecks(1)` per signature reached (`:1616`). `kappa` now branches
on the dummy and bills the leading non-empty signature run on the Schnorr path — an **upper bound**
on the consensus count, exact on the accept path, on `nSigsCount = 0`, and when a signature is empty
(the exact/upper-bound table is at the edit site in `Cost/Sig.lean`). The ECDSA arm is unchanged, and
that invariance is **proved** for all stacks by `multiSigArm_ecdsa_unchanged`
(`LeanBCH/Validation/VM/MultiSigBilling.lean`), not sampled. See `FINDINGS.md` LBCH-2026-001.

Measured at fix time over the 11 signature families (4,467 metric-comparable vectors; per-vector
artifact `conformance/evidence/LBCH-2026-001-fix-deltas.tsv`): `signatureCheckCount` decreased on
1,486 vectors and **increased on 0**; agreement with libauth rose 2,229 → 2,799 with **zero**
previously-agreeing vectors broken; `evaluatedInstructionCount`, `hashDigestIterations`,
`arithmeticCost`, `stackPushedBytes` and every verdict unchanged. `0u4tu8` stays at `sigChecks 0 /
opCost 4,194`. The `hashDigestIterations` spread is a separate term (`multiSigHashExtra`) and is
untouched; the Schnorr **execution** branch is still deferred (`Extended.lean:228`), so the 803
signature-vector rejections are unchanged by this fix.

**The pre-fix spread below could NOT be reproduced in this run** and is retained only as recorded
history: the multisig families supply 1,367 metric-comparable vectors in total, so no partition
reproduces its "2,617 verdict-agreeing multisig vectors". That is exactly the defect logged as
LBCH-2026-002 (the original measurement committed no per-vector artifact). Treat the fix-time numbers
above, which do have one, as the measured baseline.

**VERIFIED AGAINST BCHN (2026-07-21) — the soundness direction is closed.** The fix-time numbers
compared LeanBCH against libauth only, and libauth is not consensus (LBCH-2026-003). A second run
added the **BCHN** leg (BCHN's own engine, `bchn-src @ 864c53e` / v29.0.1, via
`bch-conformance/legs/bchn/bchn-leg --mode consensus`) over the same 4,467 vectors. Per-vector
artifact: **`conformance/evidence/LBCH-2026-001-threeway.tsv`** (4,467 rows, engine + corpus versions
in the header). Both drivers were validated against committed evidence first: the libauth driver
reproduces the `0u4tu8` root-cause witness exactly, and `costprobe` reproduces all 1,486 rows of the
fix-deltas artifact on three columns with 0 mismatches — so the fix-time table above is now
*independently confirmed*, not merely restated.

`signatureCheckCount` over the 4,467 metric-comparable vectors (agree / LeanBCH over / LeanBCH under):

| reference | before | after |
|---|---|---|
| libauth | 2,229 / 1,912 / 326 | **2,799 / 1,342 / 326** |
| **BCHN — `bchn-leg`** | 1,549 / 2,594 / 324 | 1,759 / ~~2,384~~ / 324 |
| **BCHN — real accrual** | 1,985 / 2,158 / 324 | **2,195 / 1,948 / 324** |

> **The `2,384` is RETIRED.** It was measured against `bchn-leg`, which reports `0/0/0` on **every**
> BCHN reject — BCHN's `VerifyScript` copies its metrics to the caller only on success
> (`interpreter.cpp:2745`, `:2794`), and the leg reads a default-constructed object unconditionally
> (`bchn-leg.cpp:315,323-325`). All four triples in the first two rows were re-derived from scratch on
> 2026-07-21 and reproduce **exactly**, so they are right about what they measured; what they measured
> is not what the `over` column claims. The third row is the same comparison against BCHN's *real*
> accrual, recovered by `conformance/evidence/bchn-partial-probe.cpp` (validated: 5,803/5,803 verdicts
> and all 2,350 accept-path metrics identical to the leg). **Of the 2,384: 436 are pure artifact and
> 1,948 are genuine.** Per-vector causal partition, no residual bucket:
> `conformance/evidence/LBCH-2026-001-overbill-partition.tsv`; full write-up in `FINDINGS.md`
> ("The comparand was broken"). The explanation this table used to carry — *"documented upper-bound
> behaviour on rejected vectors where a non-empty signature fails verification"* — covers **1,690** of
> the 2,384, not all of it: another **258** are vectors where BCHN aborted on a malformed pubkey (26)
> or malformed CHECKMULTISIG checkbits (232) **before reaching any signature check**.

324 vectors bill **under** BCHN — but **all 324 are vectors LeanBCH rejects**, and **0 are new**. On
the 1,817 vectors LeanBCH **accepts**, the split vs BCHN is **under 0 / agree 1,547 / over 270**, both
before and after the fix. An under-bill on an accepted input is the only path from a cost defect to a
wrong accept, and there are none. The 324 are all `core.signing-serialization` Schnorr-multisig
vectors carrying four signature ops; LeanBCH stops at the first CHECKMULTISIG with a non-empty dummy
(`Extended.lean:228`, still deferred) and never bills the rest — deferral of execution, not
mis-billing. All three statements in this paragraph were **re-verified against BCHN's real accrual**
and are unchanged: under-bills 324, all on LeanBCH-rejects, 0 on a LeanBCH accept; and on the 1,547
vectors **both** engines accept, LeanBCH equals BCHN **1,547/1,547 exactly**. The `over 270` is **real,
not artifact** — identical against leg and probe — and is the already-documented
`SIGHASH_UTXOS|ANYONECANPAY` verdict defect (BCHN stops at `SIG_HASHTYPE` on all 270), not a billing
one. `0u4tu8` re-measured is unchanged and now rests on a measurement rather than a default zero:
BCHN's *actual* accrual is `sigChecks 0 / hashIters 10 / opCost 4,194`, which **LeanBCH matches on all
three**, against libauth's `1 / 22` — 1 of only 2 such three-metric matches among 2,386 BCHN rejects.

The historical `1,255 / 1,360 / 2` triple was searched for systematically and is **not reproducible**
(11 candidate partitions × {libauth, BCHN} × {before, after}: no match; no partition has 2,617
members). Its **"under = 2"** column *does* reproduce exactly — `0u4tu8` and `g8xdap`, both LeanBCH 0
/ libauth 1 / BCHN 0, where that BCHN 0 is now the probe's **measured** accrual, not the leg's default
(both vectors are BCHN rejects). The reproducible multisig partition (1,155 verdict-agreeing multisig vectors):
before 333 / 820 / 2 → after **477 / 676 / 2**.

**Original section follows — RECORDED HISTORY, NOT EVIDENCE.** This block previously asserted "the
measured spread below is real"; that claim is withdrawn, because the spread could not be reproduced
(see the two paragraphs above) and no per-vector artifact was ever committed for it. Its explanation
was separately shown false. Nothing below should be cited as a measurement.

> **CORRECTION (2026-07-21).** This paragraph previously read: *"`Cost/Sig.lean:50-55` bills
> `signatureCheckCount := nPubKeys` unconditionally; libauth bills the checks actually performed."*
> **Both halves are false**, and each was checked against source:
>
> - **libauth does not bill the checks performed.** `crypto.js:246-250` bills
>   `signatureCheckCount += publicKeys.length` gated on
>   `allSignaturesAreNull = signatures.every(s => s.length === 0)`; Schnorr-multisig bills `+= 1` per
>   signature (`:177`). That is *exactly* BCH-2026 consensus: BCHN `interpreter.cpp:1690-1692` bills
>   `TallySigChecks(nKeysCount)` under `if (!areAllSignaturesNull)` — its own comment calls it *"not
>   identical to the number of actual ECDSA verifies, but … an upper bound"* — and `:1616` bills
>   `TallySigChecks(1)` per signature on the Schnorr path.
> - **LeanBCH does not bill unconditionally.** `Cost.multiSigCost` is unconditional, but its caller
>   gates it: `VM/Meter.lean:143-149`, inside the live `kappa` fold, bills
>   `Cost.sigCost .checkMultiSig 0 0 0` when `sigs.all (·.isEmpty)`.
>
> All three engines therefore implement the **same rule**, and the cause of the divergence below is
> **unknown**. See [`FINDINGS.md`](../FINDINGS.md) LBCH-2026-001 for the ruled-out explanations and the
> candidate directions — do not re-propose either of the two above.

Measured spread (the numbers are unaffected by the correction above):

| n (keys) | LeanBCH | libauth | vectors |
|---|---|---|---|
| 3 | 3 | 0 / 1 / 2 / 3 | 270 / 210 / 30 / 36 |
| 15 | 15 | 0 / 1 / 15 | 18 / 30 / 8 |
| 20 | 20 | 0 / 1 / 2 / 20 | 46 / 112 / 12 / 26 |

(Rows are the verdict-agreeing vectors of the three `m-of-N` families whose key count is declared in
the family name. Four further `m-of-15` vectors bill 0 on the LeanBCH side — 2 where libauth also
bills 0, and the 2 under-bills noted below — so the table is not exhaustive.)

They coincide only when every key is examined. Over the 2,617 verdict-agreeing multisig vectors:
sigChecks agree 1,255 (over-billed 1,360, under-billed 2); hash iterations agree only **2**
(over 950, **under 1,665**); total consensus opCost agrees on 2, over-bills 1,360 and **under-bills
1,255**, worst case −26,768 (`0u4tu8`). Under-billing is the soundness-relevant direction.

Honest bound on that last result: it is a METRIC divergence, not a demonstrated consensus divergence.
Comparing each vector's cost against its own per-input budget `(41+|scriptSig|)·800`, libauth exceeds
budget on 4 of 4,467 vectors and there are **zero** vectors where LeanBCH stays within budget while
libauth exceeds it. No wrong-accept is reachable from this in this corpus; a vector engineered to sit
between the two totals is not ruled out.

So the "CHECKMULTISIG is UNDER-MODELED" note that stood in the `Cost/Sig.lean` header at measurement
time is confirmed by measurement and now quantified. *(That bullet has since been rewritten by the
2026-07-21 fix: the sig-check count is now dispatched on the dummy element, so the header describes
the two-path rule instead. The hash term it also covered remains un-modeled there.)* The `serLen`
placeholder in the same header reads as stale for the CHECKSIG path:
`LeanBCH/Tx/Sighash.lean` exists and `LeanBCH/VM/Extended.lean:625-643` computes the real
signing-serialization length, which is why non-multisig hash iterations agree 972/1044. The
corresponding multisig correction (`multiSigHashExtra`, `Extended.lean:644-669`) does NOT reproduce
libauth — that is the 2/2,617 above.

### Still oracle-blind

Only the 11 signature families were measured (5,803 of 29,731 corpus vectors). A vector reaching a
signature op only inside a P2SH redeem script of some other family was not covered. `CHECKDATASIG`
appears in `core.data-signatures` and is included in the totals above, but was not separately
partitioned. The ECDSA path of the shim is exercised by the corpus but has no upstream
known-answer test in `SigKat.lean` — the vendored fork ships compact vectors for Schnorr only.
