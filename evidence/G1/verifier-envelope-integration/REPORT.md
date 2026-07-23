# PF7 protocol-envelope integration decision

Date: 2026-07-23  
Scope: defensive, local BCH-2026 VM evidence only. No Chipnet funding, broadcast,
deployment, mainnet, new circuit, or production claim.

## Verdict

`bn254-onetx-pf7-sub62-r1` remains **fixed-VK verifier research only**. It is
not a G1 action transaction and cannot be made one by appending three inputs.
The existing seven-verifier cluster does not VM-accept as a ten-input cluster:
the real terminal redeem rejects (`OP_VERIFY`). The other six role results do
not change this all-input verdict.

There is no measured nine-input terminal/binding merge. The present terminal is
a verifier-role terminal, not the spec's action carrier; it neither parses an
action packet nor enforces the required binding/state/fee covenant relation.
Treating it as input 6 would weaken the specified binding semantics, so option B
is rejected as an unimplemented topology, not accepted as a reduction to nine.

Option A is the only semantics-preserving direction: seven verifier roles at
inputs 0..6, then a separately executed binding/action carrier at 7, state at
8, and fee at 9. It requires a new, end-to-end profile and real action corpus;
it is not a switch on the PF7 candidate.

## Existing PF7 evidence and headroom

The gate-green PF7 run from verifier.cash commit
`26468ae29004d2401619032de2a6ec8de269a4d6` measured seven verifier inputs:

| Metric | PF6 baseline | PF7 sub62 | Delta PF7-PF6 |
| --- | ---: | ---: | ---: |
| Scored all bytes | 54,949 | 54,541 | -408 |
| Wire bytes | 54,739 | 54,296 | -443 |
| Unlocking bytes | 54,461 | 53,975 | -486 |
| Seven/source locks | 210 (six) | 245 (seven) | +35 |
| Transaction overhead | 278 | 321 | +43 |

PF7 unlock lengths are `[8177, 6654, 7066, 7066, 8393, 7443, 9176]`. The
largest is 9,176 B: 324 B below the G1 9,500-B target and 824 B below the
generic 10,000-B ceiling. All seven source locks are 35-B P2SH32 locks. The
prior honest seven-role VM report is 7/7 accepted; its cited worst measured
operation cost was 5,667,649 against a 5,987,200 budget (319,551 margin).

These are verifier-only bytes. Under the G2 95,000 all/wire ceilings, PF7 alone
has 40,459 all-byte and 40,704 wire-byte headroom. That is not envelope headroom:
it excludes a real binding redeem, state covenant, fee input, required protocol
outputs, and their source locking bytecode. It must not be spent by arithmetic
projection.

## Real 10-input VM negative probe

`probe-10input-context.mjs` loads the actual PF7 `inputs_dump.json`, preserves
all seven real locks/unlocks, and evaluates each verifier input in libauth's
normal BCH-2026 VM with three additional 25-B P2PKH source outputs. The added
records have empty unlocks and are deliberately structural-only: they are not
called or evaluated as binding, state, or fee.

The serialized structural transaction is 54,419 B wire. It has no candidate
score or standardness claim. Input outcomes are six accepts and a terminal
reject: terminal index 6 fails `OP_VERIFY` at operation cost 7,147,893. Thus
the verifier cluster is not all-input VM-valid in a ten-input context. The raw
result is [ten-input-context-result.json](ten-input-context-result.json).

This is a rejection experiment, not a mocked action flow. It proves only the
current verifier boundary; it does not establish that the three external
protocol roles could be implemented in 123 added wire bytes or at any size.

## Why the present generator cannot produce A or B

The source is closed around an internal verifier-only topology:

- `build-adapter.mjs` accepts `pairfoldTopology` only 6, 7, or 8, and requires
  five striped fragments for fixed-G2 PF7.
- `c7/build.ts` computes PF7 as five executors plus genesis and terminal:
  `EXPECTED_INPUTS = 7`; it serializes only `allMeta` verifier roles to one
  OP_RETURN-output transaction and sends exactly those roles to
  `assertAllInputsReal`.
- Its public inputs come from `eligInstanceLocal()` proof/multiproof fixtures.
  The only `tx.inputs[...]` reads target the generated genesis context; there
  is no action-packet parser or binding-carrier API.
- `run-input-redteam.ts` explicitly accepts only six or seven input records and
  recognizes only the PF6/PF7 verifier role vectors.

Consequently appending input records cannot satisfy the requested public-packet
binding. Merging the terminal with the binding/action carrier would require a
new terminal locking program that simultaneously preserves the terminal proof
checks and implements the complete binding covenant. No such program exists in
this generator, and no VM evidence supports it.

## Required implementation package for option A

1. Introduce an explicit ten-role map:
   `exec0..exec4, genesis, terminal, binding, state, fee`; generalize every
   `EXPECTED_INPUTS`, sibling index, active-index, lock-hash, source-output,
   and transaction-output guard from positional verifier-only arithmetic to
   that map.
2. Add an authenticated action-packet parser to the binding carrier and make
   the verifier's public scalar source exactly the parsed packet fields. Bind
   the seven verifier locks, required input 8 state NFT/commitment transition,
   fee policy, and canonical non-OP_RETURN outputs as in
   `spec/kernel/G1_TRANSACTION_CANDIDATE.md`.
3. Replace the one-output OP_RETURN fixture with a complete real 10-input
   action transaction: actual binding and state P2S covenants, fee source and
   unlocking bytecode, token/value plan, fee output, and protocol outputs.
4. Extend the real gate and red team to all ten inputs. Require honest all-10
   acceptance, action-packet tamper rejection, verifier lock substitution,
   state substitution/amount/commitment rejection, fee substitution, output
   mutation, wrong-index, and cross-instance replay rejection.
5. Rebuild with the pinned CashC and LeanBCH toolchain, rerun the full runtime
   corpus, measure every scored byte and operation cost, validate standardness
   against BCHN/Chipnet policy, and cross-check the final scripts in LeanBCH.

Only after that package is green may a result be called a G1 transaction
candidate. Its circuit/profile identity must be new if the public-input binding
changes; PF7's fixed-VK research evidence cannot be relabelled as it.

## Reproducible build route after implementation

From a clean verifier.cash worktree at the pinned source revision: install root
dependencies with `npm ci`; install `harness` and `build` with
`corepack pnpm install --frozen-lockfile`; build the vendored CashC source from
its pinned Yarn lock; provide `LEANBCH_ROOT` at
`51201015fdaef4562debf2a2b1cab4013a45e8b4` with `optimizer/npm ci`; then run
the candidate through `node packages/cli/src/vc.mjs build <candidate-id>`.
The modified adapter must reject unless the ten-input real gate and extended
red-team corpus are present and green.

Commands and exact probe invocation are in [commands.txt](commands.txt).
