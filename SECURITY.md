# Security policy — ShieldKit

## Product status

**Unaudited — Work In Progress.**  
This repository is a development toolkit, not a production release certificate.

## Reporting

Report security issues **privately** via [GitHub Security Advisories](https://github.com/toorik2/ShieldKit-SDK/security/advisories/new) on this repository (preferred).

Do not open public issues that include secrets, mainnet keys, or live wallet material.

## Development-only default

Local Groth16 setup and the Chipnet playground example are **`development-only`**.  
They are **not** a multi-party ceremony and **must not** be presented as production privacy.

Mainnet production **claims** require a **ceremony-backed profile** and a **new genesis**.  
Mainnet **code path** is one config change (`network: 'mainnet'`) with WIP warnings — not production readiness.

## Mainnet broadcast

- Default network is **Chipnet**.
- Mainnet broadcast through kit helpers **refuses** without explicit acknowledgement (`--i-understand-mainnet` / `mainnetAcknowledged`).
- Development-only profiles on mainnet refuse unless a lab override is set (never document as production).

## Secrets

- Never commit seeds, WIFs, private keys, HANDOVER files, RPC passwords, or battery run state.
- `.cache/` is gitignored (local wallets, pin arts, e2e state, run logs).
- Default paths like `.cache/e2e-full-*/local-wallets.json` are **local only**; do not copy wallet JSON into the repo.
- Product assemble supports fee **policy A** (`feePrivateKey` in-process, desktop CLI) and **policy B** (`feePublicKey` + pre-signed `feeSignature`). Prefer B when integrating wallets that keep keys outside the process.
- Application code should hold keys; kit APIs should not persist secrets.

## Scope

No hosted provers, indexers, or broadcasters. Optional services are untrusted and must be verified locally.  
The Chipnet playground is an **example instance**, not a hosted pool product.
