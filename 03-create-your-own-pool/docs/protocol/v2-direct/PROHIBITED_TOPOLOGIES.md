# ShieldKit Protocol V2 Direct — Prohibited Topologies

Status: design and implementation boundary for V2 Direct. This document does
not claim that the remaining covenant, BCH-VM, ceremony, or production gates
have been completed.

## The only intended user flow

```text
sync current public pool state
-> construct one private witness locally
-> generate one Groth16 proof locally
-> sign one wallet-owned transparent funding input
-> broadcast one BCH settlement transaction
```

One user action produces one direct settlement attempt. A competing accepted
action can spend the current state UTXO first; the losing user must refresh,
reconstruct the current witness, and re-prove. That single-writer race is a
deliberate and currently unavoidable V2 Direct boundary, not a hidden service
that an operator promises to solve.

## Forbidden components

V2 Direct forbids the following in its protocol topology and user-facing
claims:

| Forbidden component | Why it is forbidden |
|---|---|
| Batching or batch transactions | Each action is a direct one-user settlement; no privacy threshold is supplied by batching. |
| Coordinator or sequencer | No participant should need an operator to order, accept, aggregate, or release their action. |
| Sponsor | The user supplies and signs the transparent funding input. A sponsor changes fee and trust semantics. |
| Playground faucet | A faucet is not part of the pool protocol or live-user flow. |
| Fee ticket or fee-credit system | No separate credit asset, ticket redemption, or opaque fee accounting is allowed. BCH transaction fees are paid by the wallet funding input. |
| Remote prover | Witnesses, note secrets, membership paths, and proving occur locally. Sending them to a service is prohibited. |
| Preparation transaction | Deposit, transfer, or withdrawal is represented by one BCH settlement transaction, not a setup/prep transaction followed by a settlement. |
| Recursive proof | The V2 Direct relation verifies one action proof directly; it does not recursively aggregate proof history. |
| Root-history accumulator | A proof is against the current state roots. Historical roots are not accepted as a spend authorization route. |
| Silent V1 fallback or relabeling | V1 encodings, profiles, artifacts, circuits, and semantics are distinct. A V2 decoder or CLI must fail closed rather than reinterpret V1 data. |

The absence of a component is meaningful. For example, an external relayer that
only propagates an already-complete transaction is not a protocol coordinator,
but it must not receive secrets, modify the transaction, decide ordering, or be
needed for success.

## Privacy boundary

V2 Direct aims to hide which qualifying historical note supplied a valid spend:
the public chain sees the nullifier, roots, packet commitment, transaction
structure, and an encrypted output record, not an explicit input-note index.
That is not a blanket anonymity guarantee.

- Privacy depends on the pool's actual note population, timing, denomination,
  wallet behavior, funding inputs, withdrawals, and transaction graph.
- A fixed denomination avoids amount linkage inside the pool but does not erase
  transparent BCH funding or withdrawal metadata.
- Users must not reuse secrets, randomness, addresses, wallet inputs, or other
  identifying patterns if they expect privacy properties.
- The 32-note playground capacity is a disposal/demo parameter, not a claim of
  a 32-user anonymity set. Capacity can close deposit admission; it never
  deletes live notes, evicts users, or reuses slots.
- Local proof generation protects witness material from a remote prover, but it
  does not protect a compromised machine, wallet, browser, or local storage.

No documentation may describe V2 Direct as private, anonymous, trustless, or
production-ready without tying that statement to the outstanding cryptographic,
covenant, VM, and deployment qualification evidence.

## Fee and liveness boundary

The protocol does not hide or subsidize BCH mining fees. The wallet-owned,
tokenless funding input supplies the fee and transparent change; a withdrawal
also creates its exact-denomination payout. Fee selection, coin selection, and
the user's wallet transaction policy remain client responsibilities.

There is one mutable state NFT and therefore one writer. V2 Direct is designed
for history-scalable local witness/proof work, not parallel settlement
throughput. Users can lose the state-tip race even when their proof is valid.
Retrying means using the new current roots and reconstructing the proof; it is
not safe to replay a proof against an obsolete root.

## Fail-closed compatibility rule

Software that receives a version, magic value, network ID, profile ID, packet
length, state length, flags value, category byte order, artifact hash, or
transaction topology it does not recognize must stop with an explicit error.
It must not downgrade to V1, infer missing fields, normalize an altered packet,
or broadcast a partly validated action.

This is a topology rule as much as an API rule: a fallback service or legacy
path can reintroduce exactly the coordinator, remote-prover, preparation, or
trust assumptions that V2 Direct excludes.
