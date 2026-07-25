# Security policy — ShieldKit-SDK

## Product status

**Unaudited — Work In Progress.**  
This repository is a development toolkit, not a production release certificate.

## Development-only default

Local Groth16 setup artifacts are permanently labeled **`development-only`**.  
They are **not** a multi-party ceremony and **must not** be presented as production privacy.

Mainnet production **claims** require a **ceremony-backed profile** and a **new genesis**.  
Mainnet **code path** is enabled by one config change (`network: 'mainnet'`) with WIP warnings — that is **not** the same as production readiness.

Architecture: `docs/BEAUTIFUL_PLAN.md`. UX audit: `docs/UX_REDTEAM_AUDIT.md`.

## Mainnet broadcast

- Default network is **Chipnet**.
- Mainnet `sendraw` / broadcast through kit helpers **refuses** unless the caller passes an explicit acknowledgement (e.g. `--i-understand-mainnet`).
- Development-only profiles on mainnet refuse unless a separate lab override is set (never document as production).

## Secrets

- Never commit seeds, WIFs, private keys, HANDOVER files, RPC passwords, or battery run state.
- The kit facade **does not** accept or store private keys; the application holds keys and returns only signatures / broadcast results.

## Reporting

Report security issues privately to the repository maintainers. Do not open public issues that include secrets, mainnet keys, or live wallet material.

## Scope

This project does not operate hosted provers, indexers, or broadcasters. Any optional service is untrusted and must be verified locally.
