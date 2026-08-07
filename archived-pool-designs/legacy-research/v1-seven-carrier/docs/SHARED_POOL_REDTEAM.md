# Shared pool red-team (chain-as-log tip)

Date: 2026-07-27  
Scope: `packages/pool` tip rebuild + note wallet + product invariants; pool-act OPEN_SET_DESYNC removal.

**Related (on-chain):** full smart-contract / densFuel adversarial audit → [`SMART_CONTRACT_REDTEAM.md`](./SMART_CONTRACT_REDTEAM.md). This file is **not** a substitute for that SC audit.

| Attack class | Result | Notes |
|--------------|--------|-------|
| Truncated settlement history | **Fixed** | `STATE_CONTINUITY` / rebuild fails before accept |
| Reordered / discontinuous preState | **Fixed** | Same |
| Tip NFT stateCommitment mismatch | **Fixed** | `TIP_NFT_MISMATCH` |
| Tip NFT actionSequence mismatch | **Fixed** | `TIP_NFT_MISMATCH` |
| Fake tip cache without NFT check | **Fixed** | Accept only with `tipNft` match on product rebuild |
| Lost tip cache | **Fixed** | Full event replay restores tip; tested in backup-tip-wipe |
| Backup restore without residual tipForest | **Fixed** | Wallet stores note1/key1/nfLeaf1; mergeTipForestForAct(tip, restored.listOpen(), {}) only |
| Wrong wallet / wrong passphrase | **Fixed** | Decrypt fails; cannot invent notes from tip |
| Double nullifier | **Accepted residual** | Enforced by relation/circuit + tip nullifier tree on act; rebuild records nullifiers from public packets |
| Concurrent deposits | **Accepted residual** | Chain serializes tip spends; client must resync tip between acts |
| Fee underpay | **Accepted residual** | Frozen pin still uses fee P2PKH topology; act builder 1 sat/B fixed-point — not redesigned here |
| Privacy: tip stores others’ seeds | **Fixed (direction)** | Public tip has no foreign secrets; wallet is notes-only. Legacy tipForest openNoteMeta may still hold secrets if copied from old state — product path must not publish that |
| RPC/electrum lies | **Accepted residual** | Client verifies tip NFT commitment; electrum can omit history (DoS) but cannot forge matching NFT without chain consensus |
| OPEN_SET_DESYNC as user recovery | **Fixed** | Gate removed from `pool-act.mjs`; `assertNoGlobalOpenSetGate` product default allows myNotes ≪ liveNoteCount |
| Linking via metadata | **Accepted residual** | Timing, amounts (fixed denom), fee UTXO patterns still leak; out of scope for this pass |

## Residual risks (accepted)

1. Full genesis→now raw-tx collection on public Electrum is incomplete for large history without an indexer — rebuild API is pure; I/O layer must supply full ordered raw txs or equivalent public events.
2. ~~Withdraw needed residual openNoteMeta~~ **Fixed:** deposit writes full secrets into note wallet / openNotes; wipe+replay uses wallet only (`secretMetaByIndex={}`).
3. densFuel pin fee input still exists under the hood (hidden, not a second fee product model).
