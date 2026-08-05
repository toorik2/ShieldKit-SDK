# V2 STARK — Requirement matrix (Chipnet production readiness)

**Status:** normative **claim** list for this product profile.  
**Evidence and runners:** [ShieldKit-Assurance](https://github.com/toorik2/ShieldKit-Assurance) only — do **not** implement Q/B campaign suites, evidence verifiers, or clean-host/soak runners in this repository.

**Exit:** all gates green with commit-bound Assurance evidence against a pinned subject commit of this product. Mainnet out of scope.

Eligibility labels: `development-only` | `beta-unqualified` | `final` (Chipnet-qualified).

## Product requirements (P)

| ID | Requirement | Product implements | Pass evidence (Assurance) |
|----|-------------|--------------------|---------------------------|
| P-01 | One local witness, one local STARK proof (prod params), one funding input, one settlement tx; banned topologies enforced | Product path | Assurance pack + three real action txs |
| P-02 | SKS3 codec exact 128B + invariants | JS + Rust codecs | Assurance multi-impl / mutation packs |
| P-03 | State invariants + capacities (incl. playground 32) | Model + AIR + state covenant | Assurance |
| P-04 | profileId SKP3 + instance descriptor pins | Profile/genesis code | Assurance |
| P-05 | SDA3 packet 552B + packetCommit | Codecs + AIR packing | Assurance |
| P-06 | Deposit/transfer/withdrawal transitions | Transition + AIR + covenant | Assurance |
| P-07 | EC-free notes/records/Faerie (CRYPTO) | Notes/crypto modules | Assurance |
| P-08 | Depth-32 note + indexed nullifier trees | Tree APIs + store | Assurance scale/history packs |
| P-09 | PUBLIC_STATEMENT sole ABI | Statement + binding | Assurance |
| P-10 | Topology roles FRI+binding+state+funding | Settlement assemble | Assurance |
| P-11 | Production FRI params only for final | Fail-closed friParam guards | Assurance |
| P-12 | Runtime material pins redeem hashes | Runtime install/refresh | Assurance |
| P-13 | Recovery from chain + note decrypt | Recover product path | Assurance |

## Build / freeze (B)

| ID | Requirement | Pass evidence |
|----|-------------|-----------------|
| B-01 | Relation, layouts, statement, params, topology frozen | Product commits + Assurance lock |
| B-02 | Same final txs accept: Libauth, BCHN mempool, mined Chipnet, LeanBCH | **Assurance** oracles/envelopes |

## Qualification (Q) — Assurance only

| ID | Requirement | Pass evidence |
|----|-------------|-----------------|
| Q-01 | Multi-impl codec/statement freeze | **Assurance** |
| Q-02 | Final-param corpus (D/T/W under frozen FRI+AIR) | **Assurance** |
| Q-03 | Final lock attack corpus | **Assurance** |
| Q-04 | Tree conformance depth 32 | **Assurance** |
| Q-05 | Notes/privacy | **Assurance** |
| Q-06 | Durability/recovery/faults | **Assurance** |
| Q-07 | ≤100kB tx, ≤10k unlock, VM≤100%, p95 prove≤60s, scale/recovery budgets | **Assurance** |
| Q-08 | Clean hosts: install→D/T/W→erase→recover | **Assurance** |
| Q-09 | Live Chipnet qualification per Assurance terminal rules | **Assurance** |

## Audit / reproduction (D)

| ID | Requirement | Pass evidence |
|----|-------------|-----------------|
| D-01 | **No ceremony.** Param freeze + multi-host prove→pack→tx reproduction | **Assurance** |
| D-02 | Independent security audit of AIR, packer binding, product covenants, EC-free crypto | External audit + Assurance graph |

## Dependency order

```text
A0 freeze
  → P0 size/prove under production params (hard stop)
    → P-02..P-08, B-01
      → B-02, Q-01, Q-02, Q-03, Q-04, Q-05, Q-06, Q-07
        → D-01, D-02
          → Q-08
            → Q-09
              → Chipnet production readiness declaration
```

## Hard stops

- P0 failure on size/forge/libauth under production params → no product CLI cutover.
- Any gate using development FRI params cannot close `final`.
- Depth &lt; 32 cannot close P-08 / relationId.
- Mainnet evidence is rejected for this programme’s readiness declaration.
