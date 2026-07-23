# G1 evidence status

Updated: 2026-07-23

Gate verdict: **OPEN**

Candidate: `g1-bn254-groth16-single-note-v0`

This ledger records evidence completeness. A row is complete only when its
linked record conforms to `policy/evidence.schema.json` and contains raw,
reproducible evidence for the exact candidate.

| G1 requirement | State | Evidence or owner |
| --- | --- | --- |
| Current BCH consensus, standardness, activation, and VM limits | partial | v29 source plus two synchronized same-host, read/sync-only Chipnet runtimes are recorded in `evidence/G1/bch-surface/`; transaction-policy behavior remains missing |
| Two independent current BCHN v29 peers reproduce behavior | missing | two local processes synchronized to one tip through partly distinct public peers, but are not independent operators |
| Pinned reproducible verifier toolchain | partial | exact PF6 rebuild passes on Node 20 and 25; PF7 sub62 also reproduces from the pinned source; bootstrap closure remains distributed |
| Real valid and invalid proof corpus in complete standard transactions | partial | the 608,499-constraint relation has three valid R1CS witnesses and five rejecting mutations; no zkey, proof, new verifier, or complete transaction exists |
| Complete all-byte/source-script/per-input/VM accounting | partial | PF7 sub62 records 54,541 scored / 54,296 wire bytes and all seven unlocks below 9,500; the protocol envelope is absent |
| Independent VM or formal cross-check | missing | libauth plus LeanBCH workstream |
| Real Groth16 and alternative comparison | missing | no alternative may be compared by projection |
| Explicit setup, upgrade, and failure model | partial | manifest/lifecycle v1 and the offline bundle builder fix the dev-versus-ceremony boundary; the real local initializer is in progress |
| Hash-bound typed verifier-bundle manifest | implemented, unqualified | strict schema, loader, profile/genesis derivation, and adversarial parser tests pass |
| Two independently initialized development bundles | missing | parser fixtures prove interface replacement only; real Groth16 setups are required |

G1 cannot pass from the 54,949-byte verifier alone. The remaining budget must
include the complete relation, state and binding covenants, encrypted recovery
record, transparent fee input, canonical change output, carrier preparation,
and at least five percent measured standardness headroom.

Current decisive results:

- the candidate relation now SHA-binds the exact 752-byte reference action
  packet and checks deposit, transfer, and withdrawal witnesses at 608,499
  constraints; setup, proof, and BCH settlement evidence remain absent;
- the verifier baseline is reproducible without source patches when every
  committed dependency closure is installed;
- it remains research-only with fixed verifier/deployment binding;
- the original PF6 inputs 0–2 exceed 9,500 bytes, but the measured PF7 sub62
  repartition clears that component ceiling with a 9,176-byte maximum unlock;
  it leaves only gross, not allocated, envelope headroom, and its seven
  verifier inputs do not directly fit the current six-verifier-input
  settlement draft; and
- a pinned no-wallet BCHN v29 build now records two separate local Chipnet
  datadirs with read/sync-only outbound public P2P handshakes and a common
  locally validated tip (height 315,801 at observation). The two processes are
  one local operator rather than independent peers, and no transaction
  acceptance or relay result was run; G1 therefore remains OPEN. See
  `evidence/G1/bch-surface/resumed-synchronized-20260723/`.
