# Φ specification (public statement clauses)

**Normative product ref:** `vendor/freeze-a0/PUBLIC_STATEMENT.md`  
**Schema:** `shieldkit-v2-stark-statement-v1`  
**Status:** Wave C complete — PublicStatementΦ = ∀ PhiClause clauseHolds; out rows in NONCLAIMS.

Legend: **in** = Warrant v1 in-scope target · **partial** = KAT/checklist only today · **out** = NONCLAIMS / later · **bind** = binding covenant role, not FRI-alone

---

## Statement object fields (ABI)

| ID | Clause | Lean today | Target |
|----|--------|------------|--------|
| S1 | schema id exact | partial (product KATs) | Φ1 |
| S2 | networkId ∈ {1,2} | partial | Φ1 |
| S3 | kind ∈ {deposit,transfer,withdrawal} | **in** ProductV1 | Φ0/Φ1 |
| S4 | profileId / instanceId well-typed | partial | Φ1 |
| S5 | packetCommit = Poseidon2(SDA3 packet) | **in** packetCommitOk | Φ0/Φ1 |
| S6 | preState / postState SKS3 | **in** transition checks | Φ0/Φ1 |
| S7 | publicNullifier kind-active zeros | **in** kindActiveOk | Φ0/Φ1 |
| S8 | outputNoteLeaf kind-active zeros | **in** kindActiveOk | Φ0/Φ1 |
| S9 | withdrawalLockingBytecodeHash kind-active | **in** kindActiveOk | Φ0/Φ1 |
| S10 | transactionContextHash binding | bind / partial | Φ2 + bind role |
| S11 | friParamId / airId match pin | params gate on Bundle | Φ1 |
| S12 | statementId = SHA256(SKSTMT1‖RFC8785) | out/partial | optional Φ1 |

## What the proof asserts (freeze-a0 §)

| ID | Assertion | Lean today | Target |
|----|-----------|------------|--------|
| A1 | packetCommit from full 552B packet | **partial** ProductV1 | Φ1 |
| A2 | packet magic/network/kind/flags/instance match S | partial | Φ1 |
| A3 | packet pre/post bytes = S.pre/post | partial | Φ1 |
| A4 | kind-active inactive-zero rules | **in** | Φ0 |
| A5 | pre→post transition by kind | **in** stateTransitionOk | Φ0/Φ1 |
| A6 | note tree depth-32 membership/append | **out** (not private-trace) | NONCLAIMS or deep AIR later |
| A7 | nullifier tree insert when spend | **out** same | NONCLAIMS or later |
| A8 | EC-free note crypto | **out**/partial Poseidon only | NONCLAIMS slice |
| A9 | tx context hash | bind | Φ2 |
| A10 | fri/air pin | **in** params | Φ0 |

## Product topology (not FRI-alone)

| ID | Role | Formal target |
|----|------|----------------|
| T1 | FRI verifier inputs | Full.Verify |
| T2 | Binding recompute packetCommit / equate fields | Φ2 + Packing/Binding |
| T3 | State SKS3 / conservation | Φ1 transition + state role model |
| T4 | Funding P2PKH | out of formal Accept |

Omitting T2/T3 is **prohibited topology** (freeze-a0) — model in Packing/Topology + NONCLAIMS if unproved.

---

## Φ definition (name-on-the-line — Lean)

```text
PublicStatementΦ c  :=  ∀ cl : PhiClause, clauseHolds cl c
  where clauseHolds cl c := clauseBool cl c = true

Honest relation: PublicStatementΦ ↔ StatementHolds ↔ verifyProductAir
(Φ IS the production product-AIR statement; Bool form is executable.)
```

Product-claim structure (projections of Φ):

| Prop | Clause |
|------|--------|
| `AuthorizationHolds` | A4 kind-active |
| `TransitionClaimHolds` | A5 transition |
| `PacketBindClaimHolds` | A2 packet bind |
| `PacketCommitClaimHolds` | A1 packet commit |
| `NetworkClaimHolds` | networkOk |

Crown packing: `PublicStatementΦ_of a` = topology ∧ **required** binding ∧ **required** product Φ  
(no `| none => True`).

S3: `kindCodeOk` via `Kind.ofU8?` on packet byte @5 matching `st.kind`.

**Out** (NONCLAIMS only): A6, A7, A8, S12, T4, full script VM.

---

## Exit checks

- [x] Every **in** structural row has named Lean Prop / PhiClause
- [x] Every **out** row in NONCLAIMS
- [x] Mutations fail verifyProductAir / Φ families
- [x] Φ not bare StatementHolds alias
