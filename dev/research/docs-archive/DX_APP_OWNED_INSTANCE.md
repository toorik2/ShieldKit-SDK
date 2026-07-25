# DX note: app-owned instance (additive)

Status: additive documentation (does not alter frozen g0-v3 document hashes).

## Primary developer experience (this kit)

The **primary DX** for ShieldKit-SDK application builders is:

1. Stand up or load an **app-owned** protocol **instance** (today:
   development-only profile + Chipnet).
2. Own the **frontend** and optional backend.
3. Supply chain I/O (RPC / raw history / broadcast) from the application.
4. Call the **app-kit** / golden-path CLI for deposit, one-note transfer,
   withdrawal, and recovery — without implementing PF7 dens-drop research.

Shared production pools and multi-party ceremony profiles remain valid protocol
directions; they are **not** the default onboarding story for this kit.

## Charter alignment

G0 locked decisions D-002 / D-003 historically emphasize shared-instance wallet
integration and de-prioritize “deploy your own pool” as a hero workflow. This
note **repositions DX only**:

- Protocol authority, no post-genesis admin, local secrets, and optional
  untrusted services **unchanged**.
- “Own pool” here means **own instance coordinates + own app**, not a hosted
  multi-tenant service operated by ShieldKit maintainers.
- Production mainnet still requires ceremony-backed profile + new genesis
  (no hot-swap).

Semantic charter text is not rewritten here; a full D-002/D-003 change would
require CHANGE_CONTROL RFC + G0 reopen.
