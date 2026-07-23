# G1 evidence status

Updated: 2026-07-23

Gate verdict: **OPEN**

Candidate: `g1-bn254-groth16-single-note-v0`

This ledger records evidence completeness. A row is complete only when its
linked record conforms to `policy/evidence.schema.json` and contains raw,
reproducible evidence for the exact candidate.

| G1 requirement | State | Evidence or owner |
| --- | --- | --- |
| Current BCH consensus, standardness, activation, and VM limits | in progress | `evidence/G1/bch-surface/` |
| Two independent current BCHN v29 peers reproduce behavior | missing | live-node work after local inventory |
| Pinned reproducible verifier toolchain | in progress | `evidence/G1/verifier-baseline/` |
| Real valid and invalid proof corpus in complete standard transactions | missing | verifier reproduction and new profile build |
| Complete all-byte/source-script/per-input/VM accounting | in progress | verifier reproduction; protocol envelope remains missing |
| Independent VM or formal cross-check | missing | libauth plus LeanBCH workstream |
| Real Groth16 and alternative comparison | missing | no alternative may be compared by projection |
| Explicit setup, upgrade, and failure model | partial | `g0-v2` fixes the profile boundary; concrete bundle is in progress |
| Hash-bound typed verifier-bundle manifest | in progress | `spec/verifier-profile/` and `packages/core/` |
| Two independently initialized development bundles | in progress | verifier-bundle conformance tests |

G1 cannot pass from the 54,949-byte verifier alone. The remaining budget must
include the complete relation, state and binding covenants, encrypted recovery
record, transparent fee input, canonical change output, carrier preparation,
and at least five percent measured standardness headroom.

