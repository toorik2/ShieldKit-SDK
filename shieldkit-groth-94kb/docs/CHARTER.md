# ShieldKit charter

Document version: 0.5 · Product/protocol authority (not an implementation spec).

Primary path: **`shieldkit-groth/`**. Optional demo: **`archived-pool-designs/02-use-chipnet-demo-pool/`**.

## Mission

Toolkit for wallets/apps to **create and run their own BCH shielded pools** without hosted trust.  
Local secrets, local proofs, local verification; broadcast via any compatible path.  
Not: hosted privacy SaaS, general ZK framework, or third-party pool service. Playground is an example instance only.

## Users

| Role | Does |
|------|------|
| Pool creator | init → genesis → operate |
| App integrator | profile + instance, plan/prove/settle, recovery |
| Infrastructure | optional chain/index/broadcast — outputs untrusted |

## Standard / profile / instance

- **Profile** — immutable crypto, circuit, VK, scripts, encodings, hashes  
- **Instance** — one on-chain genesis of a profile  
- **Bundle** — authenticated artifacts for a profile  

Instances from one profile do **not** merge anonymity sets.

## Principles

1. Create-your-own-pool is the product.  
2. Secrets stay local.  
3. BCH history + profile + consensus transitions are authority.  
4. Notes recoverable from seed + profile + BCH history.  
5. Proof bound to exact profile, state, packet, and tx roles.  
6. No coordinator required to authorize a valid spend.  
7. Profile material immutable; change ⇒ new profile.  
8. Failures bounded by pool reserve; no minting BCH.  
9. Privacy claims need population/behavior context, not crypto alone.  
10. Evidence before promotion (no fixture-as-mainnet).  
11. After genesis: no admin/pause/rescue/upgrade/fee key.  
12. Verifier material only replaceable by new profile; local setup stays `development-only`.

## V1 scope

BCH only · fixed 0.1 BCH notes · deposit / transfer / withdraw · local prove · encrypted note records on chain · seed recovery.  
First target: **Chipnet**. Mainnet path may exist with WIP gates — not production-qualified by this charter.

## Non-goals (V1)

Arbitrary private contracts · multi-asset · hosted multi-tenant pools · mandatory sequencer · custody/exchange · unqualified “anonymous/safe” claims · protocol fee · treating dev setup as ceremony · mutating a live profile.

## Invariants (summary)

Exact reserve accounting · single tip · nullifiers once · domain-separated encodings · transparent fee input · 1 sat/B · recover from seed+history · fail closed on hash/identity mismatch · no maintainer spend key.

## Trust

| Role | May provide | Not trusted for |
|------|-------------|-----------------|
| Wallet | keys, proofs, plans | unverified external inputs |
| Chain/indexer | data | canonical ownership without local check |
| Broadcaster/relayer | submission | authorization |
| Artifact host | files | integrity without hashes |
| Maintainers | specs, releases | runtime fund authority |

## Release language

Allowed maturity labels: design draft · evidence experiment · profile candidate · Chipnet qualified · mainnet candidate · mainnet qualified.  
Prohibited without scoped evidence: “safe,” “anonymous,” “production ready,” “audited.”

Success = independent operators create/run instances, recover from chain, and spend with optional infra down — not “demo deployed” or “SDK published.”
