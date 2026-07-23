# PF7 bounded ten-role verifier-context evidence

Observed: 2026-07-23. Scope is a local, defensive BCH-2026/libauth experiment;
there was no funding, broadcast, deployment, or mainnet action.

## Verdict

**PASS for the bounded verifier-context milestone only.** Source commit
`aa12905c0f4928b20e2b66475a438eb9c7dcb613` builds the unchanged fixed-VK
PF7 Groth16 equation as verifier roles `exec0..exec4, genesis, terminal` at
inputs 0..6 in an exact ten-input transaction context. All seven real
verifier roles accept in the normal libauth BCH-2026 VM.

Input 7 contains a 68-byte canonical `SHP1 || in0_be32 || in1_be32` packet
(69-byte push). The terminal compares the complete actual input-7 unlocking
bytecode to the packet generated from the same two public limbs used by the
existing ECIP/Groth16 statement. A one-byte packet mutation reaches the real
terminal and fails `OP_VERIFY`.

Inputs 7–9 are **not a settlement action**. `packet`, `state`, and `fee` have
only structural P2PKH source locks; they are intentionally unevaluated in this
milestone and inputs 8–9 have empty unlocks. The result is neither a valid
ten-input BCH transaction nor G1/G2/protocol/Chipnet evidence. The source
adapter fails closed if asked to turn this structural-role mode into a normal
CandidateBundle.

## Exact role and byte result

| Index | Role | Source lock | Unlock | VM role result |
| ---: | --- | ---: | ---: | --- |
| 0 | exec0 | 35 | 8,177 | accepts |
| 1 | exec1 | 35 | 6,654 | accepts |
| 2 | exec2 | 35 | 7,066 | accepts |
| 3 | exec3 | 35 | 7,066 | accepts |
| 4 | exec4 | 35 | 8,393 | accepts |
| 5 | genesis | 35 | 7,443 | accepts |
| 6 | terminal | 35 | 9,249 | accepts |
| 7 | packet | 25 | 69 | structural, unevaluated |
| 8 | state | 25 | 0 | structural, unevaluated |
| 9 | fee | 25 | 0 | structural, unevaluated |

The largest verifier unlock is 9,249 B: 251 B below the G1 9,500-B target and
751 B below the generic 10,000-B maximum. Seven verifier unlocks total 54,048
B; the packet makes the all-input unlocking sum 54,117 B. Source locks total
320 B, serialized structural wire is 54,561 B, and the structural score is
54,881 B (`wire + all source locks`). These totals are descriptive only, not a
standardness or fee claim because the three external roles do not execute.

## VM operation costs

| Role | Operation cost | Per-input budget | Margin |
| --- | ---: | ---: | ---: |
| exec0 | 6,001,855 | 6,574,400 | 572,545 |
| exec1 | 4,895,907 | 5,356,000 | 460,093 |
| exec2 | 5,168,502 | 5,685,600 | 517,098 |
| exec3 | 5,185,992 | 5,685,600 | 499,608 |
| exec4 | 6,141,638 | 6,747,200 | 605,562 |
| genesis | 5,667,649 | 5,987,200 | 319,551 |
| terminal | 7,154,078 | 7,432,000 | 277,922 |

The context change exposed and fixed an index bug: generated terminal reads had
used `EXPECTED_INPUTS - 2` for genesis. With external roles that points to
input 8, so the source now uses the explicit verifier-role `genesisIndex`.
The Groth16 equation, VK, proof fixture, and seven verifier unlock values are
otherwise retained; terminal grows from 9,176 to 9,249 B for packet binding.

## Adversarial result

`input-redteam.json` records the full six/seven verifier-role VM rows for a
valid proof and mutation contexts. Honest roles 0..6 all accept. The following
all produce at least one real verifier rejection in the complete ten-input
context: off-curve A, off-curve B, non-canonical B, rebuilt off-subgroup B,
all seven witness mutations, a public-limb mutation, and a canonical-packet
mutation. The packet mutation leaves roles 0..5 and genesis accepting but
causes terminal input 6 to reject `OP_VERIFY`.

## Remaining gates

This deliberately stops before action semantics. To advance, replace the three
structural roles with real binding/state/fee covenants and canonical outputs;
make public limbs runtime-derived from an authenticated packet rather than a
fixture-specific terminal comparison; execute every input; run standardness on
unmodified BCHN/Chipnet policy; add full action/state/fee mutation coverage;
and cross-check the exact final scripts with LeanBCH. LeanBCH was pinned and
used as the generator dependency at `51201015…`, but no independent LeanBCH
xcheck was completed for this bounded topology.

Raw build and red-team outputs are under [raw](raw).
