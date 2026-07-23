# G1 evidence status

Updated: 2026-07-23

Gate verdict: **OPEN**

Candidate: `g1-bn254-groth16-single-note-v0`

This ledger records evidence completeness. A row is complete only when its
linked record conforms to `policy/evidence.schema.json` and contains raw,
reproducible evidence for the exact candidate.

| G1 requirement | State | Evidence or owner |
| --- | --- | --- |
| Current BCH consensus, standardness, activation, and VM limits | partial | v29 source, primary specs, and a genesis-only local runtime recorded in `evidence/G1/bch-surface/`; current synchronized behavior remains missing |
| Two independent current BCHN v29 peers reproduce behavior | missing | two isolated local processes are not independent and their loopback handshake failed |
| Pinned reproducible verifier toolchain | partial | exact 54,949/54,739 rebuild passes on Node 20 and 25; bootstrap closure remains distributed |
| Real valid and invalid proof corpus in complete standard transactions | missing | verifier reproduction and new profile build |
| Complete all-byte/source-script/per-input/VM accounting | partial | baseline recorded; three baseline inputs exceed the stricter G2 ceiling and the protocol envelope is absent |
| Independent VM or formal cross-check | missing | libauth plus LeanBCH workstream |
| Real Groth16 and alternative comparison | missing | no alternative may be compared by projection |
| Explicit setup, upgrade, and failure model | partial | `g0-v2` and manifest v1 fix the boundary; no real development setup exists |
| Hash-bound typed verifier-bundle manifest | implemented, unqualified | strict schema, loader, profile/genesis derivation, and adversarial parser tests pass |
| Two independently initialized development bundles | missing | parser fixtures prove interface replacement only; real Groth16 setups are required |

G1 cannot pass from the 54,949-byte verifier alone. The remaining budget must
include the complete relation, state and binding covenants, encrypted recovery
record, transparent fee input, canonical change output, carrier preparation,
and at least five percent measured standardness headroom.

Current decisive results:

- the verifier baseline is reproducible without source patches when every
  committed dependency closure is installed;
- it remains research-only with fixed verifier/deployment binding;
- inputs 0–2 exceed the 9,500-byte G2 ceiling by 353, 348, and 377 bytes; and
- a pinned no-wallet BCHN v29 build now starts on Chipnet locally, but the
  recorded nodes remained at genesis and did not complete a loopback handshake;
  no current or independent-peer claim follows.
