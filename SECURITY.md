# Security

**Unaudited — Work In Progress.** Not a production release certificate.

## Report

Private: [GitHub Security Advisories](https://github.com/toorik2/ShieldKit-SDK/security/advisories/new).  
Do not open public issues with secrets, keys, or live wallet material.

## Development-only default

Local Groth16 setup and the Chipnet playground are **`development-only`** — not a multi-party ceremony, not production privacy. The built-in sequential-contribution runner is honestly labeled **`local-contribution-simulation`**. Signed external contribution receipts provide a protocol for independently operated contributions, but do not by themselves prove participant independence or production qualification.

Mainnet is selected by the profile network, RPC endpoint, and CashAddr prefix (`network: 'mainnet'` / `--network mainnet`; default remains Chipnet). The current pinned SCAR circuit fixes the wire `networkId` byte to **2 for both chain configurations**; it does not use that byte to distinguish BCH mainnet from Chipnet. Broadcast still requires `--i-understand-mainnet`, and any non-`production-qualified` profile is refused unless the explicit development-on-mainnet lab override is also present. This release creates no `production-qualified` profile.

## Secrets

Never commit seeds, WIFs, private keys, RPC passwords, or wallet JSON.  
`.cache/` is gitignored. Prefer fee policy B (`feePublicKey` + signature) when keys stay outside process.
Wallets, pool state, operation journals, ledgers, run inputs, and backups are generically ignored. New private state and journal files are written atomically with mode `0600`; their directories use `0700`.

**Local secret surfaces (operator-owned):**
| Surface | Contents | Rule |
| --- | --- | --- |
| `wallets.json` / fee keys | `privateKeyHex`, etc. | Disk only; never web-served |
| `state.json` `openNotes[].witnessSeed` | note material | Not for git/logs/screenshots |
| `--seed-hex` / recover inputs | account seed | CLI arg history risk |
| RPC URL with embedded auth | credentials | Prefer env; never commit |
| Browser SDK | seed per call | App must not log/persist seeds carelessly |

**Not in scope as “API keys in frontend”:** this toolkit is local CLI + optional browser recovery facade (`browser.mjs`). No hosted SaaS keys. If you wrap ShieldKit in a web app: never put fee private keys, RPC passwords, or proving secrets in browser-bundled env.

## Scope

No hosted provers/indexers/broadcasters. Optional services are untrusted; verify locally.  
Playground = example instance, not a product pool service.  
See [docs/PRIVACY.md](03-create-your-own-pool/docs/PRIVACY.md) for claim bounds (RPC query privacy **outside** claim).

## Protocol fail-closed (built-in)

| Check | Where |
| --- | --- |
| Mainnet ack + development-on-mainnet gate | `createKit` / `--i-understand-mainnet` |
| Empty / desynced open set | `OPEN_SET_DESYNC`, openNotes length |
| Tip forest vs chain seq | `TIP_FOREST_DESYNC` |
| Packet preState vs exact chain tip | authenticated raw transaction + `TIP_PRESTATE_MISMATCH`; unavailable verification fails closed |
| Prepare/send/state ordering | `0600` pending-operation journal; broadcast and state commit are separate, resumable phases |
| Nullifier / identity / hash mismatch | covenant + action paths; CHARTER |
| Pin lens mismatch | pool-act |
| Missing pool / wallets / verifier-set | fail before prove/broadcast |

CLI errors are **operator-facing** (codes + messages on stderr). Not multi-tenant UI: do not copy raw stack traces into end-user web copy if you host a UI.

## Pre-launch checklist map (vibe-coder list → ShieldKit)

| # | Item | Applies? | Status / action |
| --- | --- | --- | --- |
| 1 | Legal / privacy policy (GDPR/CCPA) | **Operator if you collect PII** | Toolkit stores no user accounts. Hosted wallet/UI → your privacy policy + data map. Local-only CLI: still know where `wallets.json` / seeds live. |
| 2 | Row Level Security | **N/A** | No multi-tenant DB. Analog: **note secrets + nullifiers + open-set integrity** (above). |
| 3 | Failure paths (auth bugs) | **Yes (crypto/ops)** | Cover: wrong tip, empty openNotes, double-nullifier, wrong fee UTXO, mainnet without ack, corrupt witnessSeed, OP_VERIFY after offline gateOk. Tests: `pool-act-fail-closed`, witness/transition, tipForest e2e. |
| 4 | Security headers | **N/A for CLI**; **yes if you host HTML** | Learn site is static local files. Hosted frontends: CSP, no secrets in JS. |
| 5 | OWASP (SQLi/XSS/auth) | **Partial** | No SQL app layer. Real risks: XSS if you render chain/user data in a UI; path injection on `--pool`; secret leakage; supply chain on pin artifacts. Protocol attack surface = covenants + proofs (separate audit). |
| 6 | Client validation ≠ security | **Yes if web wrapper** | Browser SDK is recovery-only; prove/broadcast stay local. Never trust client-only checks for fee spend or tip state. |
| 7 | AI / env / log leaks | **Yes** | Audit: no `privateKey*` in frontend bundles; success JSON omits keys; ledger.jsonl has txids only; do not log wallets/seeds. `.gitignore`: `.cache/`, `**/*.wif`, `**/secrets/**`. |
| 8 | API keys in frontend | **Yes if you add them** | Move RPC auth / paid APIs server-side or local process only. |
| 9 | Rate limits / bill burn | **Operator** | Public Fulcrum default is free-tier friendly; self-hosted or paid RPC → throttle scripts; avoid tight tip-poll loops in production UIs. No SaaS API key bill inside toolkit. |
| 10 | CAPTCHA + CORS | **N/A for toolkit**; **yes for public forms** | No public signup. If you ship a public deposit UI: CAPTCHA + CORS to your origin. |
| 11 | Error messages | **Yes for product UI** | CLI: detailed codes OK. Hosted UI: generic user string; log detail server/operator-side. Never surface `privateKey` / seed / full wallet JSON. |

## Operator ship gate (minimum)

Before mainnet or real funds:

1. `development-only` and `local-contribution-simulation` are not production qualification. Production privacy needs independently governed [external contributions](03-create-your-own-pool/docs/EXTERNAL_CONTRIBUTIONS.md), audit, and a new genesis ([CHARTER](03-create-your-own-pool/docs/CHARTER.md)).
2. Explicit mainnet ack; no accidental broadcast.
3. Fee keys not in git, not in browser bundle, not in shared screenshots.
4. Tip path: openNotes + tipForest match chain; doctor/tip before large acts.
5. Failure drills: withdraw empty set, wrong tip, missing wallets, mempool reject.
6. Hosted wrapper (if any): privacy policy, no secrets client-side, rate-limit paid calls, generic errors.

Build fast. Don’t ship naked keys, naked open sets, or production claims on development pins.
