# Security

ShieldKit is unaudited research software for Chipnet. Do not use it with
mainnet funds or describe any profile as safe, anonymous, or production-ready.

## Report a vulnerability

Use a private [GitHub Security Advisory](https://github.com/toorik2/ShieldKit-SDK/security/advisories/new).
Do not put wallet material, seeds, private keys, credentials, or unredacted
runtime data in a public issue.

## What the protocol tries to hide

The PF10 design targets one narrow property: given only BCH consensus-visible
data, a passive observer should not be able to identify which eligible prior
note funded a later transfer or withdrawal. That target depends on correct
cryptography, secret handling, compatible note sets, and more than one plausible
note. It has not been independently audited or production-qualified.

The following remain public or outside the claim:

- transaction graph, time, shape, scripts, values, state roots, and nullifiers;
- deposit funding, fee inputs, change, and withdrawal destinations;
- network traffic, client IP, RPC/indexer queries, and timing correlation;
- a compromised device, leaked wallet, malicious application, or collapsed
  anonymity set.

Use a fresh external Chipnet P2PKH withdrawal address. Reusing a funding, fee,
or change address can trivially join the transparent edges of the flow.

## Secrets

- Keep wallets and data homes outside the repository.
- Give secret files mode `0600` and their directories mode `0700`.
- Never pass private keys or seeds directly on a command line.
- Back up the complete data home and retained wallet material. Public chain
  history can reconstruct public state; it cannot recreate lost note secrets.
- Treat logs, screenshots, proof inputs, journals, and support bundles as
  potentially sensitive.

The repository ignores common wallet, key, journal, database, build, and
handover paths. Ignore rules reduce accidents; they are not secret storage.

## Network and delivery

The unified PF10 product path is Chipnet-only. It has no faucet, sponsor, custody service,
automatic resend, or confirmation wait. A successful action means the exact
transaction was admitted and read back under the profile's zero-confirmation
policy. It does not mean the transaction is mined or final.

Public providers are untrusted inputs and can observe requests. The client must
verify returned transaction and state data locally. Ambiguous delivery is
resolved through explicit inspection and exact-byte rebroadcast, never an
automatic replacement spend.

## Profile-specific limits

| Profile | Security boundary |
| --- | --- |
| PF10 | Unified CLI's only money-moving beta backend; single-contributor setup; no audit, mainnet, or production qualification |
| PF6 | Unified mutations blocked; release record says `productionQualified: false`; portability and conditional withdrawal-layout risk remain |
| FRI-STARK | Unified mutations blocked; relies on local private build material; no encrypted-note privacy or Groth-pool compatibility claim; independent P7 journey was waived, not completed |
| V1 playground | Historical only; not a fallback for V2 |

Profile-specific evidence:

- [PF6 Lab boundary](./docs/lab/pf6.md) and
  [accepted risks](https://github.com/toorik2/ShieldKit-SDK/blob/main/designs/pf6/evidence/accepted-risks.json)
- [FRI-STARK Lab boundary](./docs/lab/fri.md) and
  [release verdict](https://github.com/toorik2/ShieldKit-SDK/blob/main/designs/fri/evidence/release/RELEASE_VERDICT.json)
- [PF10 release pins](./designs/pf10/pins/)

Internal reviews and green local tests are evidence, not independent audits.
