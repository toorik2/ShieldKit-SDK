# ShieldKit Protocol V2 Direct — Privacy and Rollout Boundary

**Status:** development-only and unqualified. This document is a claim boundary,
not evidence that the relation, ceremony, covenants, wallet, recovery path, or
deployment has qualified.

## The only permitted privacy claim

> A passive BCH observer cannot cryptographically determine which qualifying
> historical note produced a later nullifier from public chain data alone.

This is the complete permitted claim. It applies only to a qualifying historical
note and public chain data alone; it is not an anonymity, unlinkability, or
production-security guarantee.

## Required nonclaims

- Deposit funding is visible.
- Every action's transparent fee input and change are visible.
- Lab single-key bootstrap fanout clusters fee identity for a session (public
  fee-graph nonclaim; fee mechanics redesign is a separate programme).
- Transfer publicly pairs one nullifier with one new output.
- Withdrawal publicly pairs one nullifier with one transparent payout.
- Cashing out to the same local fee/change wallet as funding **collapses
  operational identity**; the product path must reject that destination.
- Timing, amount, action shape, RPC traffic, IP metadata, sender knowledge,
  recipient knowledge, and low pool activity can reduce practical privacy.
- Live-note count is not a guaranteed anonymity set.
- Disk use grows linearly with history.
- A single pool is not concurrent-write scalable.

In particular, direct actions disclose public-chain timing and transaction shape.
Transparent funding, fee, change, and withdrawal data can contribute value and
transaction-graph metadata. A local prover does not protect a compromised
machine, wallet, browser, RPC connection, or local storage. No public material
may call V2 Direct private, anonymous, trustless, or production-ready without
also supplying the final qualification evidence that would justify the narrower
statement.

## Capacity and topology

`maximumLiveNotes` limits admission of simultaneously live notes. It is not a
user count or an anonymity-set guarantee; it neither evicts a live note nor
reuses a slot. The disposable playground profile has a 32-live-note capacity.
At capacity, deposit 33 must be rejected before proving. Withdrawal can make
capacity available again, but it does not erase public historical metadata or
the append-only history retained for state reconstruction.

Each user action is one direct settlement attempt: one local witness, one local
Groth16 proof, one wallet-owned transparent funding input, and one BCH
settlement transaction. There is no batching, batcher, coordinator, sponsor,
faucet, fee-ticket system, remote prover, preparation transaction, recursive
proof, or root-history accumulator. The user supplies and signs the fee funding
input. One mutable state NFT also means one accepted writer at a time; a valid
proof may lose a state-tip race and need a fresh witness and proof.

## Version and network refusal boundary

V1 is a separate legacy protocol. Its `SHST` 80-byte state, `SCAR` 752-byte
packet, `shielded-action-v2` relation, profiles, setup, descriptors, artifacts,
instances, histories, and local stores **must not** be relabeled, converted, or
migrated into V2 Direct. V2 Direct accepts only its own `SKS2` 128-byte state,
`SDA2` 552-byte packet, and V2 Direct descriptor/artifact schemas. Cross-version
input must fail closed; recovery starts from V2 Direct genesis rather than
importing V1 state.

This plan authorizes V2 Direct only on Chipnet. Mainnet deployment is outside
this plan. The V2 Direct chain configuration rejects mainnet rather than
providing an acknowledgement or development override. Any proposed mainnet
deployment requires a separate reviewed decision and cannot be inferred from
this document, a local test, a development key, or a Chipnet result.

## Publication gates

No public V2 Direct profile, playground, or release is authorized by the local
implementation. Publication remains blocked until all applicable final-artifact
gates in the implementation plan have objective evidence, including:

- the selected verifier passes the unmodified maintainer benchmark, Libauth,
  BCHN mempool acceptance and mined execution, and LeanBCH on matching final
  transactions;
- the frozen circuit and packet have a five-independent-contributor phase-2
  ceremony, public beacon, two independent transcript verifications, and two
  clean-host reproductions;
- four independent audit scopes are closed with no blocking findings;
- final-key proof, transaction, codec, covenant, encryption, durability,
  recovery, concurrency, and published-machine performance gates pass;
- two clean-machine user journeys complete using pinned artifacts and
  out-of-band funding; and
- Chipnet completes a 30-day, at-least-1,000-direct-settlement rollout. Only
  after final-key and clean-machine gates may the disposable 32-live-note
  playground be switched publicly; its required fill/reject-33/withdraw/refill/
  recover/contention checks must also pass.

The required Q-04 qualification is exactly four independent deterministic
25,000-action histories, for a bounded total of 100,000 historical
nullifiers. Each history must include the specified checkpoint/reopen and
rejection probes and be independently replayed from its committed candidate
evidence. This plan makes no claim beyond that tested range, and it does not
authorize or require a larger campaign.

Local source tests, ignored development artifacts, development proof keys, and
partial VM measurements do not substitute for any publication gate.
