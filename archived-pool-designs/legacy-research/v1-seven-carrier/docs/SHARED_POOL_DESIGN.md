# Shared multi-user shielded pool — design (chain-as-log tip)

## Product

- Shared anonymity set across many users (not personal-only pools).
- User verbs: **private balance · Deposit · Withdraw · encrypted backup**.
- Demo = real public pool. Blank machine: install → wallet → **sync tip from chain** → deposit → withdraw.
- densFuel pin: frozen. No tip-feeReserve / densFuel topology patches in product path.
- Fees: automatic, hidden inventory.

## Split state (first principles)

| Object | Contents | Secret? | Source of truth |
|--------|----------|---------|-----------------|
| **Public tip view** | `state`, `noteLeaves[]`, `nullifierLeaves[]` | No | Rebuild from public settlement log (genesis→now); verify vs tip NFT |
| **Private note wallet** | My note secrets + `noteIndex`/`leaf` at mint | Yes | Encrypted backup; never equals global live count |

**Invariant:** never require `myNotes.length === chain.liveNoteCount`.

Tip accept rule: rebuilt tip `state.stateCommitment` + `actionSequence` match the tip NFT commitment fields (and `liveNoteCount` / reserve consistent with tip value when available).

## Tip rebuild (chain as log)

1. Collect ordered raw transactions: genesis + every ten-input settlement spending prior tip vout0.
2. Extract authenticated action packets from settle input 7 (`extractRawSettlementHistory`).
3. Replay public events into a tip view:
   - **deposit:** append `outputCommitment` as note leaf; set state ← packet.postState
   - **withdrawal:** insert nullifier leaf; set state ← packet.postState
   - **transfer:** append output commitment; insert nullifier; set state ← packet.postState
4. Accept iff terminal state matches on-chain tip NFT (`stateCommitment`, `actionSequence`, identity).

Public tip does **not** store other users’ witness seeds. Open-note secrets live only in each user’s wallet.

## Private notes

Each deposit writes **full spend secrets** into the private wallet (encrypted backup includes them):

```
{
  noteIndex,                 // leaf index in public note tree
  leaf,                      // domain-tagged NOTE_TREE_LEAF
  key1,                      // sparse nullifier key (decimal)
  nfLeaf1,                   // domain-tagged NULLIFIER_TREE_LEAF
  note1: { sk, recoveryPublicKey, rho, r },
  witnessSeed, depositDigest, createdSeq,
  status: open|spent
}
```

Withdraw selects **any open note I own** by `noteIndex` (merkle membership), not global LIFO of strangers’ notes. After tip-cache wipe, `mergeTipForestForAct(publicTip, wallet.listOpen())` must succeed with **no residual tipForest openNoteMeta**.

## Acts

- **Deposit:** sync tip → mint note → prove tip transition → broadcast → save note only.
- **Withdraw:** sync tip → spend my note → prove → payout → mark spent.

## Failure modes

| Case | Result |
|------|--------|
| Truncated / reordered history | Rebuild rejects |
| Tip NFT mismatch | Rebuild rejects |
| Lost tip cache | Full replay restores tip |
| Lost wallet, no backup | Funds unspendable (expected) |
| Double nullifier | Circuit / tip rejects |

## Modules

`packages/pool/`: `tip-rebuild.mjs`, `note-wallet.mjs`, `product-api.mjs`  
Acts still use frozen densFuel unlock after prove.
