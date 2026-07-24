# Chipnet funding handoff — ShieldKit-SDK unlock-stabilize profile

Observed: 2026-07-24 (UTC)

## Status: READY FOR FUNDING

Engineering offline gates for complete settlement are closed. User Chipnet
coins are the remaining blocker for live E2E.

| Item | Status |
| --- | --- |
| V2 relation freeze (strict-Fr) | done |
| development-only setup / zkey / VK | done |
| Desktop Groth16 prove+verify ×3 | done |
| PF7 unlock-length stabilize (7600/9350) | done |
| Complete prep+settlement assembly ×3 | done |
| Libauth BCH-2026 10/10 accept | done |
| Mutation matrix (9×3 reject) | done |
| Unmodified BCHN v29 `testmempoolaccept` | **env limit** (binary not on host) |
| LeanBCH checkout | present at `.worktrees/leanbch-pf7` (build-time) |
| Live Chipnet broadcast | **blocked on user fund** |

## Profile / instance (development-only)

| Field | Value |
| --- | --- |
| profileId | `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7` |
| instanceId | `sha256:74770b7d277c1953842dcdf3e6a9446620b293512786dcf02c4e8a6d7641b5d6` |
| network | `chipnet` |
| setup | `development-only` |
| bundle | `.cache/profile-build-stabilize/profile-bundle` |
| bch-verifier-set | `sha256:a97647c206b1741937895de5276f466da969c935ea47d5f5677505c93d5ce171` |
| R1CS | `sha256:6a797e696a4fe01f500b232270944f93e5e6f171906c37511748ab0f50df0e17` |

Unlock pins (all actions): `[8177, 6654, 7066, 7066, 8393, 7600, 9350]`.

Settlement measurements (libauth, fee 1 sat/B):

| kind | wire | maxUnlock | fee |
| --- | ---: | ---: | ---: |
| deposit | 56964 | 9350 | 56964 |
| transfer | 56964 | 9350 | 56964 |
| withdrawal | 56974 | 9350 | 56974 |

Evidence: `evidence/G2/complete-settlement-unlock-stabilize/`.

## Fund this address (Chipnet only)

| Field | Value |
| --- | --- |
| Address | `bchtest:qp55a60g879wnpfh92h37vpa6wfwu8frkcwp4tlvg9` |
| Amount | **20485518 satoshis** (0.20485518 BCH) |
| Preferred vout | **0** (single P2PKH output) |
| Network | **Chipnet** — mainnet unauthorized |

### Amount breakdown (sats)

| Component | Sats |
| --- | ---: |
| Deposit prep funding (0.1 BCH note + PF7/binding carriers + fee budget) | 20100000 |
| Genesis state carrier | 1080 |
| Genesis fee ceiling | 500 |
| Transfer prep budget | 110000 |
| Withdrawal prep budget | 110000 |
| Transfer settlement fee (measured) | 56964 |
| Withdrawal settlement fee (measured) | 56974 |
| Margin | 50000 |
| **Total** | **20485518** |

Fee model: transparent fee + change @ **1 sat/B**; no pool subsidy. Fixed note denomination: **0.1 BCH** (10000000 sats).

Private key for this address is held only in session scratch
(`/tmp/grok-goal-6848531c4568/implementer/chipnet-funding-secret.json`) —
**never commit, paste into evidence, or push**.

## Post-fund plan (agent)

1. Confirm Chipnet payment to the address above for the exact amount (prefer
   vout 0). Record `funding_txid`, raw tx, confirmation height. Never log keys.
2. Rebuild development-only profile genesis bindings:
   `categoryInputOutpoint` / `stateNftCategory` → confirmed `funding_txid`
   (vout 0). Current category hash in the offline profile is a **placeholder**
   and must be rebound after fund.
3. Offline `planChipnetGenesisTransaction` + sign + broadcast genesis; confirm
   state NFT.
4. Prep + settlement **deposit** (0.1 BCH note).
5. Prep + settlement **one-note transfer**.
6. Prep + settlement **withdrawal**.
7. Seed+chain recovery evidence; capture txids, raw txs, node verdicts, artifact
   hashes.

## Node policy / env limit

- **Libauth BCH-2026 standard VM:** pass (10/10 + mutation matrix).
- **LeanBCH:** checkout present (`.worktrees/leanbch-pf7`); used during PF7
  builds. No separate complete-tx LeanBCH node RPC in this host path.
- **Unmodified BCHN v29:** **not installed** on this host (`bitcoind` /
  `bitcoin-cli` / BCHN package absent). `testmempoolaccept` on the three
  complete txs was **not run** — environment limit, not an engineering fail of
  the candidate.
- To clear the BCHN gate later: install unmodified BCHN v29, Chipnet-only,
  loopback RPC, then `testmempoolaccept` on
  `.cache/complete-settlement-stabilize/{deposit,transfer,withdrawal}-tx.hex`
  (re-assembled against live genesis outpoints after fund).

## Hard bans

Mainnet; committing keys/WIFs/`HANDOVER.md`; hosted proving; silent G0 edits;
fabricated headroom; browser/Android stretch.