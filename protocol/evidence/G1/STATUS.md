# G1 evidence status

Updated: 2026-07-24

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
| Real valid and invalid proof corpus in complete standard transactions | partial | the 608,499-constraint development-only relation has three valid Groth16 proofs and independently verified outputs; the pinned deposit reaches a real ten-input BCH-2026/libauth VM context, but this is not BCHN-standardness, Chipnet, or a complete settled action |
| Complete all-byte/source-script/per-input/VM accounting | partial | `development-v0-real-proof/` records all ten real PF7 inputs accepting, 81,563 wire / 82,739 score bytes, and 18/18 attack rejections; exec0 is 9,596 B (>9,500), so the G1 component gate remains failed |
| Independent VM or formal cross-check | missing | libauth plus LeanBCH workstream |
| Real Groth16 and alternative comparison | missing | no alternative may be compared by projection |
| Explicit setup, upgrade, and failure model | partial | manifest/lifecycle v1 and the offline bundle builder fix the dev-versus-ceremony boundary; the real local initializer is in progress |
| Hash-bound typed verifier-bundle manifest | implemented, unqualified | strict schema, loader, profile/genesis derivation, and adversarial parser tests pass |
| Two independently initialized development bundles | partial | `development-v1-setup-replacement/` packages two real local setups with distinct setup/key/generated-PF7 verifier material and passes the strict pre-genesis interface comparator; it does not establish settlement closure, BCHN policy, or deployable genesis transactions |

G1 cannot pass from the 54,949-byte verifier alone. The remaining budget must
include the complete relation, state and binding covenants, encrypted recovery
record, transparent fee input, canonical change output, carrier preparation,
and at least five percent measured standardness headroom.

Current decisive results:

- **2026-07-24 ShieldKit-SDK post-`Num2Bits_strict` relation freeze** (`evidence/G1/relation-circuit/strict-fr-v2/`): dual-compile byte-identical R1CS/WASM/sym; three valid witnesses; 9/9 adversarial witness probes; package alias suite 4/4. Pre-repair R1CS/WASM hashes are non-authority. Not G1 PASS, setup, proof, or Chipnet.

- the candidate relation now SHA-binds the exact 752-byte reference action
  packet and checks deposit, transfer, and withdrawal witnesses at 608,499
  constraints; setup, proof, and BCH settlement evidence remain absent;
- the verifier baseline is reproducible without source patches when every
  committed dependency closure is installed;
- a source-pinned native rapidsnark feasibility run now proves and
  pinned-snarkjs-verifies all three exact low128-v0 witnesses at 2.546–3.362
  seconds and 562,484–566,628 KiB warm peak RSS. This passes the frozen desktop
  thresholds as an initial one-host feasibility sample only; it is not p95
  qualification, a selected backend, or a G1 PASS. See
  `evidence/G1/native-prover-rapidsnark/`;
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
- `development-v0-real-proof/` adds a hash-pinned actual development-v0
  deposit proof through the ten-input PF7 VM context: all 10 real inputs
  accept and 18/18 recorded mutations reject, but `exec0` is 9,596 B and
  direct proving peaks at 6.83--7.09 GiB RSS. This is development-only,
  bounded local evidence, not BCHN standardness, Chipnet, full settlement, or
  LeanBCH qualification.
- `development-v1-setup-replacement/` records the second local setup through a
  real v1 PF7 three-action VM check (deposit, transfer, withdrawal: 10/10 each;
  every role's lock bytecode is invariant across those witnesses; deposit
  mutations 18/18 reject) and a strict two-bundle pre-genesis replacement
  comparison. Both bundles remain development-only; `exec0` remains 9,596 B,
  and neither bundle or deterministic comparison outpoint is a deployable
  genesis, BCHN, or Chipnet claim.


## 2026-07-24 ShieldKit-SDK progress (post-strict-Fr)

- Relation freeze: `evidence/G1/relation-circuit/strict-fr-v2/`
- Dev setup: `evidence/G1/development-setup-v2-strict/`
- Desktop prove: `evidence/G1/desktop-prove-v2-strict/`
- PF7 fresh corpus: `evidence/G1/pf7-fresh-v2-strict/` (roles 0–6; ~55.3 kB context wire; unlocks ~9.27 kB)
- Profile final: profileId `sha256:34d907599331997dfc67083742f0fcbb37b971687b1ae420658a172de2119c49`
- Funding: **not ready** — complete settlement (inputs 7–9) still open (`evidence/G1/chipnet-funding-handoff-v2-strict/`)
- Gate G1 remains **OPEN**
