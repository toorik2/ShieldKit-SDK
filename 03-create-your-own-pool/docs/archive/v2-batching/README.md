# Superseded V2 Batching Design

Status: archival only. This is not an active protocol specification, an
implementation plan, or authorization to revive a batching path.

## Supersession record

The V2 Direct plan records an abandoned batching design and excludes batching,
a batcher, coordinator, sponsor, faucet, fee ticket, remote prover, preparation
transaction, recursive proof, and root-history accumulator from the active
protocol. The replacement flow is exactly one locally constructed witness, one
local Groth16 proof, one wallet-owned transparent funding input, and one BCH
settlement transaction per action.

No standalone technical batching-draft file is present in the reachable Git
history inspected for this Phase-A freeze. Accordingly, this archive preserves
only the confirmed supersession boundary; it does not reconstruct undocumented
batch algorithms, message formats, trust assumptions, or security claims.

## Quarantine rules

- Do not treat any archived item as an accepted V2 Direct input, profile,
  instance, state, packet, proof, transaction topology, or release artifact.
- Do not migrate or relabel batching-era material into V2 Direct. A V2 Direct
  profile must use the identifiers in
  `../../protocol/v2-direct/IDS_AND_DOMAINS.md`.
- Any future batching proposal is a distinct protocol-design effort. It must
  receive a new relation and profile namespace and must not weaken the V2 Direct
  one-settlement or packet-binding requirements.
