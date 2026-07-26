# Security

**Unaudited — Work In Progress.** Not a production release certificate.

## Report

Private: [GitHub Security Advisories](https://github.com/toorik2/ShieldKit-SDK/security/advisories/new).  
Do not open public issues with secrets, keys, or live wallet material.

## Development-only default

Local Groth16 setup and the Chipnet playground are **`development-only`** — not a multi-party ceremony, not production privacy.  
Mainnet path exists as config (`network: 'mainnet'`) with broadcast ack (`--i-understand-mainnet` / `mainnetAcknowledged`); that is not mainnet qualification.

## Secrets

Never commit seeds, WIFs, private keys, RPC passwords, or wallet JSON.  
`.cache/` is gitignored. Prefer fee policy B (`feePublicKey` + signature) when keys stay outside process.

## Scope

No hosted provers/indexers/broadcasters. Optional services are untrusted; verify locally.  
Playground = example instance, not a product pool service.
