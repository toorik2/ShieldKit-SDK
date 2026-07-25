# PRINCIPLES — verifier.cash  v0.11
pin: BCH2026 CashVM · libauth 3.1.0-next.8 · noble/curves 1.9.7 · cashc feat/reusable-functions@1c8f838 (2026-06 track) → cashc-resched 1c707c1d / 0.14.0-next.1 (2026-07 native/moonshot crown track) · groth16_cashscript@43dd254 · node v26.1.0 · 2026-06-22 (B5 added 2026-07-11)
policy: AI-only readership ⇒ dense, no prose. living/falsifiable/VM-versioned (§6). measurement>principle.

## obj
min B = total on-chain bytes of SOUND Groth16(BN254) verifier runnable as tx-chain under BCH per-input limits.
real obj = cheapest SOUND trustless-verify primitive on Script VM. bytes=fees=fixed amortized cost buying unbounded off-chain compute. leaderboard=forcing-fn, not goal.
targets: BCH-native 738,099B/63tx · singleton floor 21,042B.

## master eq (the spine)
B ≈ O_total/800  +  n·(prologue+handoff+skel)  +  Σ lock_irr
- budget/input=(41+ulen)·800, max 8,032,800 ⇒ pad buys 1B/800opcost [DER]
- n ≥ O_total/8.03M [DER];  pad≈60%, prologue≈⅓ of B [CIT /solutions]
⇒ both dominant terms ∝ O_total ⇒ byte-min ≈93% OP-COST-MIN. O_total↓ pays twice (pad↓ & n↓). retrodicts 196→63 chunk history.

## floor/gap
B_floor ≈ (N_mul,min·c_mul,min)/800 + code_once + handoff_min·n_min
- N_mul,min = min Fp-mul count, optimal-ate BN254, shared finalexp, precomp e(α,β) [OPEN §8.1]
- c_mul,min = min Fp-mul opcost this VM (limb width, Karatsuba/Toom, Montgomery/Barrett) [OPEN §8.2]
metric = monotone ↓ of MEASURED gap (B_meas−B_floor). always carry gap, not number.

## principles  [layer·conf]   conf∈{inv,hi,wk,open}
A invariant (math/econ):
 A1·inv  soundness=adversarial hard gate, prior to size. 1 forgery⇒score 0. every removed byte: prove no forgery enabled (γ≠δ/Veil-Cash; subgroup+on-curve; non-minimal enc; A-neg). adversarial vectors, not 1 tampered limb.
 A2·wk  [REVISED v0.4 — MEASURED, supersedes "WIDTH>COUNT"] aggregate op-cost is BASE-dominated, NOT modmul-dominated. measured: finalexp base 63.8%/arith 28.4%/push 7.7%; miller4 base 54.7%/arith 38.7%/push 6.6%; fp2 base 49.2%/arith 47.1%. base = evaluatedInstructionCount×100; dominated by Fp12=12 separate-int limbs shuffled via OP_PICK/OP_ROLL/OP_INVOKE (no array/struct type). ⇒ PRIMARY lever = cut INSTRUCTION COUNT ([v0.7: naive OP_CAT/OP_SPLIT packing MEASURED WORSE +5% — F4] the win = direct-extension Fp12 + SCHWARTZ-ZIPPEL witness-and-check Fp12 mul (~0.40× op-cost, removes the OP_INVOKE/OP_MOD shuffle storm; A1-gated FS bind) + shared 4-pair Miller; fewer/cheaper invokes). SECONDARY = fewer/narrower modmuls (arith, the minority). per-modmul width² is real but ~⅓ of total, not the driver.
 A3·inv  verify≪compute. verifier=fixed cost amortized ∀uses. optimize primitive, not artifact.
 A4·hi   fixed/var split: bake/precompute all VK-derived once (e(α,β), small mults of IC, Frob coeffs); proof+inputs in witness ⇒ proof-agnostic lockings.
B cost-model (empirical; re-measure per VM):
 B1·hi   opcost=currency; bytes couple 800:1 ONLY while op-cost-bound. chunk∈{code-bound,opcost-bound}; opcost-bound⇒bytes=opcost/800 exact. REFINEMENT(v0.6): witness/compute→verify levers cut op-cost but ADD witness bytes AND can push a chunk op-cost-bound→code-bound, after which more op-cost reduction yields ~0 bytes (SATURATES). classify each chunk's bound-type before/after; in the singleton (code-bound,0 pad) op-cost wins = 0 bytes.
 B2·hi   opcost↓=double payoff(pad↓+n↓). instr-count↓ w/o opcost↓ helps only code-bound chunks.
 B3·wk   chunking=graph-partition: cut where live-state min(handoff) & prologue-reuse max(contiguous same-fn runs). ≡ register-pressure+code-locality.
 B4·wk   pack chunk opcost just<8.03M, min pad slack; n→O_total/8.03M. [⚠ 8.03M is the CEILING (10k-unlock chunk); the REAL per-input budget is (41·unlockLen)·800 — see B5.]
 B5·hi   [MEASURED 2026-07-11, moonshot; authority intel/VM_COST_MODEL.md §1/§3] op budget is PER-INPUT and SCALES with THAT input's unlock: budget=(41+unlockLen)·800, NOT the flat 8,032,800 (=ceiling for a 10k-unlock chunk ONLY). ⇒ WITNESS-AS-FUEL: every unlock byte finances 800 op; at the density edge (op≈800·unlockByte) witness bytes AND op are LOCKED — you CANNOT buy op-budget with pad (moving a pad byte costs ~800 op = the budget it grants; D10/F17 measured-definitive). COROLLARY: the scored input that CONSUMES a per-step witness must ALSO carry it — offloading witness to a sibling data-input REMOVES the ~800op/byte fuel the consumer's own recompute needs. ⇒ the ONLY lever that lowers a recompute-bound chunk is cutting OP; moving/cutting/compressing witness is density-trapped. (This flat-budget error inflated the SZ-miller moonshot projection ~60k→measured 133.6k — F18, [[E-moonshot-debake]].) + baseInstructionCost=100 is charged per SCANNED opcode INCLUDING conditionally-skipped OP_IF branches ⇒ conditional/rare code MUST be a DEFINE'd helper (scanned only when OP_INVOKE'd), never an inline OP_IF branch (D3).
C contingent (BCH policy=lever, not physics):
 C1·hi   floor partly artifact: 10kB cap, base-cost 100, pad-to-buy-budget, no shared-code ref. don't treat 800/10k/100 as fundamental.
 C2·wk   rule-change > in-VM cleverness: virtual-bytes kills pad tax; read-only-inputs(TXv5) kills prologue tax structurally; base 100→10 ≈ 54-57% off (MEASURED base share 55-64% of finalexp/miller4, NOT the repo's cited ~40% which assumed modmul-dominance). play+shape rules(CHIPs). leaderboard=today's rules ⇒ protocol=parallel track.
D method (epistemic):
 D1·inv  measure-then-deploy: every claim=falsifiable real-VM opcost/byte Δ w/ accept+reject gate. no estimates in record.
 D2·inv  principles subordinate to measurement. assert to break.
 D3·hi   co-design proof-system w/ VM cost-fn. Groth16 min proof-size but pays pairings (no precompile + quad modmul; hashes cheap-ish 64/192/iter). open Q: lowest-opcost SOUND verifier under THIS cost-fn? (STARK/hash, no-pairing IP, folding). pairing-port may be local optimum.
 D4·hi   research/measure BEFORE commit (domain is assumption-hostile: 3 falsifiers logged). GATE: research only if answer changes next action AND verify cheaper than rework; else build+measure. WORKFLOW DOCTRINE: (a) RESEARCH = parallel option dives + ADVERSARIAL verify (N skeptics refute before we build); (b) EMPIRICAL = generate-variants→compile+measure(libauth)→CORRECTNESS-GATE→rank-by-opcost; (c) HYBRID = research space→measure top candidates→verify winner. KEEP SOLO: architecture, principle revisions, synthesis. ISOLATION: cashc+libauth pure ⇒ parallel measure safe via unique temp paths (worktrees need git; workspace root isn't). cost≠constraint (funded+ultracode); correctness+coverage are. [[workflow-doctrine]]

## triage (gate before spending hrs)
1 layer? principle risked (esp A1)?
2 expected ΔO_total; target chunk code- or opcost-bound(B1)? code-bound⇒opcost win=0 there.
3 a-priori payoff bound: term ≤X% of O_total? (base-cost capped by C1 — don't chase 2% for a wk)
4 soundness obligation(A1): which forgery does removal NOT enable?
5 measure(D1): real-VM opcost+bytes, valid-accept+adversarial-reject, gap.
reject on 1–4 fail; never skip 5.

## §6 overturn protocol (anti-ossify)
repro measurement contradicting principle → log out/ + harness cmd → rewrite principle, bump version, changelog. conf ratchets ↑ by survived attack, ↓ by contradiction. nothing immune (incl A: hash-system win ⇒ A2 atom modmul→hash-iter).

## §7 constants [provenance; pinned-VM only]  DER=derived CIT=cited MEAS=measured-by-us
budget/input=(41+ulen)·800, max 8,032,800 [DER]
byte↔opcost (opcost-bound)=800 opcost/B [DER]
max u/lock bytecode=10,000B [CIT]
NFT commit state=128B → store hash256(32B) [CIT]
Fp-mul = OP_MUL 1252 + OP_MOD 2212 = 3,464 opcost [MEAS exact; cited 3,800 loose]. fp12Mul(12-int tower)=827,974 opcost/3,354 instr [MEAS]; SZ-witness fp12Mul ~334-382K (0.40-0.46×) [MEAS, A1-gated]. effective ~16,166 opcost/mulFp in miller4 ⇒ ~78% glue/shuffle tax. Montgomery/Barrett ~1.6× WORSE (REJECT).
fp2 8-op vec: 2,548,182 opcost, 526B [MEAS]
vkx shamir 3ch: opcost 6.92M/5.86M/0.40M; lock 1456/1454/1565B [MEAS]
miller4(4-pair): 709,563,868 opcost, 10,303B [MEAS]
finalexp: 141,107,998 opcost, 6,469B [MEAS]
verify.cash(full,runtime VK): 892,701,751 opcost, 15,721B; valid✓ invalid✗ [MEAS]
singleton groth16.cash: 19,814B, 787ops (floor) [MEAS]
OP-COST DECOMP [MEAS, instrumented _harness]: fp2 arith47.1/base49.2/push3.8% (instr12,526); finalexp arith28.4/base63.8/push7.7% (instr900,963); miller4 arith38.7/base54.7/push6.6% (instr3,877,793). ⇒ BASE(instr×100) is the dominant term in the pairing; arith(modmul width²)=minority. lever=instruction-count reduction (see A2 v0.4).

## §7b leaderboard ground-truth (zk-verifier-bench results.json, 2026-06-22) [MEAS upstream]
SCORE = Σ_steps(locking+unlocking). tx-count NOT a unit (benchmark.md L4-7; types.ts L44,216). step=1 input eval. harness evals each step independently; continuity = whatever the step script enforces (hash256 commitment OR cross-input read).
BN254 full chunked 738,099B decomp [entry scores]:
 vkx-covenant 28,231 (3.8%) · Miller(4 SINGLE-pair chains+combine) 435,518 (59.0%) · finalexp ~274,350 (37.2%) · pairing total 709,868 (96.2%)
 vkx shamir(baked) 22,671 → covenant(threaded) 28,231 = +5,560 (+24.5%) handoff/covenant tax /3 chunks. much absorbed by padding in op-cost-bound steps ⇒ removable = covenant lock-logic + hash opcost only.
refs: BN254 singleton 21,042 · BLS381 full-chunked 928,447 · BLS381 singleton 20,975 · pairing-chunked BN254 435,518 · scrypt 11,717,684 · nchain(BLS381,BSV) 522,477. official statement = Groth16/BN254 (vk gen via src/checkpoints/gen-pairing-vectors.ts).
IMPLICATIONS: (a) cross-input/multi-input single-tx (OP_INPUTBYTECODE state read) = bounded handoff win only; tx-count irrelevant to score. (b) 96% of B is pairing ⇒ aim Miller+finalexp opcost. (c) Miller is 4 SEPARATE single-pair chains ⇒ HYPOTHESIS: shared 4-pair Miller (share f² across pairs, singleton miller4-style) cuts opcost→bytes (TEST; chunked already has lazy-reduce/fp12Sqr not in singleton, so partial). (d) finalexp alone = 37% ⇒ high-value single target (one shared finalexp, cyclotomic sqr, better hard-part addition chain).

## §7c attack plan (research-surface-expansion, adversarially verified, 2026-06-22 → catalogue/research/R-surface-expansion-2026-06-22)
SOUNDNESS FLOOR (verified, hard constraint): {G1 on-curve b=3 (A,C); G2 on-curve b2=3/(9+u) + subgroup [6x²]B==ψ(B) (B); ∞ subsumed; γ≠δ build-time(baked VK); e(-A,B) negation; finalExp==Fp12 ONE}. groth16.cash spend() MEETS it = SOUND deployable singleton. do NOT add 0≤c<p range checks for PROOF coords (subsumed — they flow through reducing mulFp). **WITNESS-CANONICITY RULE (v0.8, A1, the one exception): any ATTACKER-WITNESSED field element that does NOT flow through a reducing op before use MUST be explicitly range/canonical-checked (0≤·<p per limb) — applies to SZ-witness Q/R, residue-check c, witnessed inverses z⁻¹/f⁻¹; omitting = under-constrained forgery.** verify.cash spend() = UNSOUND primitive (2 requires) — NEVER deploy; chunked MUST inherit groth16 validation. OPEN: is 738K chunked 'spend' sound? (A1 gap flagged → #13; if not, true sound floor is higher).
PLAN (compose in residual order, impacts NOT additive):
 T1 free/low-risk: (1) SHARED 4-pair Miller (1 accumulated f, 1 f²/step; leaderboard runs 4 SEPARATE chains, miller4.cash L299-313) ~80-130K B, A1-neutral, HIGHEST conf — DO FIRST. (2) WITNESS the 2 Fermat inverses (easy-part Fp12 + vk_x Fp) MEAS 3.3M+2.44M op-cost saved; soundness z≠0/f≠0 + canonical-reduce. (3) BAKE e(α,β) + fixed-G2 Miller lines (VK constants, A4) ~1.5-2.7K B.
 T2 highest-leverage, needs work: COMPILER emitReplace fix (GenerateTargetTraversal.ts:546-561, O(depth) altstack-rotate = ~74% of miller4 EMITTED ops; ALL loop/branch assigns). measure emitted-vs-executed + soundness branch-balance. we own the fork.
 T2★ DEEP LEVER (biggest single op-cost cut, MEASURED): direct-extension Fp12 + SCHWARTZ-ZIPPEL witness-and-check Fp12 mul = ~0.40-0.46× op-cost on the dominant Fp12-mul mass of BOTH Miller & finalexp — removes the ~78% glue/shuffle tax. A1-GATE: FS transcript binds ALL coeffs + witness range/canonical (naive artifacts were UNSOUND). convergent w/ prior-art Garaga. (naive OP_CAT packing MEASURED WORSE — F4.)
 T3 the 37% prize, HIGH forgery-risk: RESIDUE-CHECK finalexp (ePrint 2024/640) collapses finalexp(37%) to ~few Fp12 muls. dedicated adversarial soundness verification (cube-cofactor/3-torsion, FS transcript, witness range) BEFORE any build.
 curve: STAY BN254 (BLS +20.5% bytes 928K vs 738K, & currently UNSOUND). reinvest cross-curve effort in BN254 finalexp + proof-system (#12).

## §7d integrated picture — all 6 research workflows complete (2026-06-22)
PARTITION = exact interval-DP (verifier DAG is a near-linear chain; cut at live-range valleys, pack iters to op-cost saturation, NEVER split the combine join). B3 operationalized.
MASTER COUPLING (sharpened): B ≈ O_total/800 + n_chunks·(prologue+handoff), n_chunks=O_total/8.03M ⇒ BOTH the ~60% padding AND the ~⅓ prologue scale with O_total ⇒ cutting pairing OP-COST is the master BYTE lever (hits padding AND chunk-count/prologue together), UNTIL chunks go code-bound (B1 saturation; current chunks deeply op-cost-bound ⇒ full runway).
PROLOGUE residue = PROTOCOL-bound (OP_DEFINE table resets per phase; read-only-inputs/TXv5 = C2, ~10-20× the in-VM ceiling; cuts prologue-dominated finalexp/vkx ~3-4×). HANDOFF near-optimal (hash256(32B)/step, A1-mandatory; cross-input read = 0/neg under Σ-steps).
BUILD ORDER (REORDERED v0.10 by E-miller4-shared — first build): P0 gate #13. **P1.0 COMPILER emitReplace fix O(depth)→O(1) FIRST** — it's the force-multiplier AND the PREREQUISITE for shared-Miller (MEASURED: shared Miller alone is +28M op-cost WORSE; the deep-loop reassignment base-bloat +113M eats the −84M arith saving — F5). P1 op-cost cuts UNLOCKED by P1.0 [shared-4-pair Miller · lazy-reduce ~1,550/mul · witnessed inverses (+witness-canonicity) · prepared-VK: bake e(αβ)+fixed-G2 lines · dedicated complex fp12Sqr] → re-plan via DP, MEASURE each (estimates ≠ reality). P2 deep [SZ-witness fp12Mul 0.40×] (A1: witness-canonicity + FS-bind-all-coeffs). P3 highest-risk [residue-finalexp −44-72%/−58% net] behind a DEDICATED adversarial gate. Protocol (parallel): champion read-only-inputs.
DIRECTIONAL B_FLOOR: stacked op-cost levers → pairing O_total ~2.5-3× down → SOUND in-VM ~250-400K B (vs 738K record, ~2-3×); sub-200K needs protocol. EXACT after P1 build + DP (measure-then-deploy).

## §8 open (multi-yr quests)
1 compute N_mul,min ⇒ floor=number (task#11)
2 cost instrument: opcost attribution /Fp-op /chunk + live gap; MEASURE c_mul, chase c_mul,min (task#10)
3 proof-system co-design (D3) — maybe largest lever + PQ route
4 protocol track (C2): quantify+champion CHIPs (read-only inputs, virtual bytes, base-cost)

## changelog
v0.11 2026-07-11 +B5 (op-density per-input budget + WITNESS-AS-FUEL + OP_IF-scan rule) — MEASURED promotion from the SZ-miller moonshot (intel/VM_COST_MODEL.md §1/§3; F17 D10 witness-offload refuted, F18 the flat-8.03M-budget error that inflated the ~60k projection to measured 133.6k). Header/pin bumped to reflect the 2026-07 cashc-resched 1c707c1d native/moonshot track. (Result numbers stay in RESULT.md; native crowns 170,366/315,318 canonical there.)
v0.1 2026-06-22 init. founding falsifier: "can't forge w/o proving key" overturned by tools/gen-proof-vectors.mjs (pick VK ⇒ valid proof=algebra) → unblocked pairing pipeline.
v0.2 2026-06-22 densified (AI-only readership policy).
v0.9 2026-06-22 RESEARCH WAVE 2 COMPLETE (6/6). +§7d integrated picture + build order P0-P3 + directional B_floor ~250-400K (~2-3× under 738K). partition=interval-DP (B3 op'd). master coupling sharpened: padding AND prologue both ∝ O_total. catalogue R-{sz-witness,compiler,proofsystem,bch-vm,residue-finalexp,chunking}. levers all designed+measured+adversarially-verified+soundness-gated.
v0.8 2026-06-22 +WITNESS-CANONICITY RULE (A1): attacker-witnessed field elts not flowing through a reducing op MUST be range/canonical-checked (SZ Q/R, residue c, witnessed inverses) — the one exception to "no range checks".
v0.7 2026-06-22 pairing-floor MEASURED: mulFp=3,464 exact(not 3,800); shared 4-pair Miller −190M/−26.7% DO-FIRST; finalexp A1-safe floor ~116M (wNAF3; REJECT Karabina); fp12 near-optimal (dedicated fp12Sqr −58.6M); DEEP LEVER=SZ-witness fp12Mul ~0.40×; REJECT Montgomery/Barrett(1.6× worse). F4: OP_CAT packing MEASURED WORSE ⇒ A2 remedy flips packing→SZ-witness.
v0.6 2026-06-22 +§7c verified attack plan (soundness floor mapped; groth16.cash SOUND, verify.cash UNSOUND; T1 shared-Miller/witness-inverses/bake-eαβ, T2 compiler emitReplace, T3 residue-finalexp). +B1 refinement (bytes=opcost/800 only while op-cost-bound; witness levers saturate). STAY BN254.
v0.5 2026-06-22 +D4 research-before-commit + workflow doctrine (research fan-out+adversarial-verify; empirical sweep generate→measure→gate→rank; hybrid; keep core solo; pure-tool isolation via unique temp paths).
v0.4 2026-06-22 3rd falsifier: A2 "WIDTH>COUNT" overturned by measured op-cost decomp — pairing is BASE/instruction-count-dominated (55-64%), not modmul/arith (28-39%). cause: Fp12 12-limb stack-shuffling (no array type). primary lever flips to instruction-count reduction. corrected cited C2 (base 100→10 ≈54-57% not ~40%). instrument = _harness evalArgs/runVectors now surface metrics decomp.
v0.3 2026-06-22 +§7b leaderboard ground-truth (738K decomp: 96% pairing). 2nd falsifier: repo claim "state can't pass across inputs of one tx" overturned (Richard Brady via OP_INPUTBYTECODE; Mathieu conceded) — multi-step-computation.md §"Across inputs (not viable)" WRONG. + score-model finding: score=Σ_steps, tx-count irrelevant ⇒ cross-input headline framing worth 0; real win=handoff mechanism only (bounded). B3 updated: partition across-steps-in-1-tx OR across-tx, identical score.
