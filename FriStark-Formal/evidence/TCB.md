# Trust boundary (TCB)

**Sandbox:** FriStark-Formal only.  
**Does not include:** LeanBCH / verifier.cash / shieldkit product trees as mutable TCB (vendor snapshots only).

---

## In TCB (machine-checked or residual)

| Component | Trust role |
|-----------|------------|
| Lean 4 kernel + this lake package | Definition of `Full.Verify` / Warrant theorems |
| `Params.V1` | Production pin 2048/8/24/8 fail-closed |
| Residual premises R | Crypto/literature assumptions (see SOUNDNESS) |
| Accept-path modules | Field, Hash, FS, Merkle, FRI, Deep, Domain, AIR, Full.Verify |
| Soundness modules | Statement, Semantic, EndToEnd, Warrant, reductions, Capacity scoreboard |

## In evidence TCB (differential / oracle — not crown)

| Component | Trust role |
|-----------|------------|
| `vendor/bch-fri-stark` @ pin | Python prove/verify oracle for parity corpora |
| pure/full IR exporters | Bundle materialization for Lean re-exec |
| multi-proof JSON d1/d2/d3 | Honest production-param witnesses for gates |
| dual-VM / leanbch-host snapshot | Host agreement **corollary**, not definition of Accept |
| forge vectors | Property tests under ontology |

## Outside TCB (explicit)

| Component | Why out |
|-----------|---------|
| Prover correctness | Separate program |
| Full BCH script interpreter | Until modeled; remainder in NONCLAIMS |
| Private execution trace | Openings model; no private-trace re-derive by default |
| Network / wallet / key management | Ops, not formal warrant |
| SHA-256 implementation correctness beyond CR/RO games | Residual surface |
| Empty residual / unconditional STARK soundness | Not claimed |

---

## Trust diagram

```text
                    residual games R
                           │
                           ▼
  public Φ  ◄──── theorems ──── Accept (Full.Verify [∘ unpack])
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
      pure/full IR    Python STK     dual-VM host
      (parity test)   (parity test)  (refinement test)
```

**Rule:** Only Accept + Φ + R appear in the crown sentence. Oracles may fail CI; they must not redefine Accept.

---

## Pin sources of truth

| Item | Source |
|------|--------|
| Production FRI params | `FriStark/Params/V1.lean` + `PIN.md` |
| Upstream STARK | `PIN.md` → vendor/bch-fri-stark SHA |
| Package content pin | last content commit (Lean/vectors/harness/CI), **not** STATUS-only |
| git HEAD | may include STATUS bookkeeping; recorded separately in STATUS.md |
