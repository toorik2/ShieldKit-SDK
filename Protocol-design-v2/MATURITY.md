# Maturity — Protocol-design-v2

## Banner (always true until Phase D is closed)

```
DEV KEYS ONLY — not for real-money privacy
Unaudited WIP · Chipnet-first · Mainnet gated until Phase D
Ceremony incomplete · Do not treat as production privacy software
```

The CLI prints this on every invocation (suppress only with `V2_QUIET_BANNER=1` for scripted tests).

## What this is

- A **design-complete V2 Direct** product path: SKS2 state, SDA2 packet, local Groth16, densFuel PF7 carriers, single self-funded settlement.
- A **Chipnet lab CLI** for pool create + deposit / transfer / withdraw / recover.
- Evidence-backed on Chipnet under 0-conf mempool bar.

## What this is not

- Not a finished privacy product for mainnet funds.
- Not ceremony-final proving keys (development zkeys under `.cache/v2-direct-circuit/`).
- Not independently audited (protocol / circuit / covenants / wallet).
- Not immune to timing, fee-graph, or small-set de-anonymization (see PRIVACY.md).

## Mainnet

**Gated.** Broadcast on mainnet requires:

1. `V2_ALLOW_MAINNET=1`
2. `--i-understand-mainnet`

Even then: **not** a privacy or security qualification. Phase D (ceremony, multi-party transcript, audits, soak) remains open — see `03-create-your-own-pool/docs/protocol/v2-direct/QUALIFICATION.md`.

## Phase D residual (publish as lab, not production)

- [ ] Freeze circuit + packet
- [ ] Groth16 phase-2 ceremony ≥5 contributors + public beacon
- [ ] Transcript verify on two clean machines
- [ ] Independent audits
- [ ] Extended Chipnet soak / multi-user playground

Until those close, every public claim must include this maturity document.
