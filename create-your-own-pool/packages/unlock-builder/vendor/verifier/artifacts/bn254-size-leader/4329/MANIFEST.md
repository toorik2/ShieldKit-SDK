# MANIFEST — BN254 size-leader singleton artifacts (crown = 4,329 locking / score 4,688)

Backfilled 2026-07-10 by byte-exact copy (`cp` + sha256 diff, COPY-VERIFIED) from the only on-disk
source of truth:

- **source repo:** `/home/toorik/Projects/verifier.cash` → `github.com/toorik2/verifier.cash` (private)
- **source path:** `tools/singleton-artifact/`
- **source commit (last touching the crown hex):** `160f3aa7928a31d25164c8ace1eb37f0e14fa278` (2026-07-03,
  "Close the byte-crown/Lean-crown split: 4,329 is now FULLY Lean-covered (sqr=mul proven)")
- **repo HEAD at copy time:** `f6dcf67c57f04d6c3c67ec6feb41888492f051dd`
- **compiler / pipeline env:** cashc rescheduling fork (mr-zwets/cashscript, local vendored clone
  `/home/toorik/Projects/cashscript` @ `1c707c1dbf87396b30ba5e0704b1db44475ce893`) for the trusted
  `baseline.json` compile; the recompiler + verified-optimizer pipeline lives beside the hexes in
  `tools/singleton-artifact/` (pipeline-sub6k, fold-pass, cse-pass, optimize.mjs, gate.mjs).
- **verification:** each hex is self-verifying via `gate.mjs` (round-trip byte-exact + per-body
  differential vs baseline.json + E2E multiproof 4/4 accept + 4/4 reject). See the two PROVENANCE-*.md
  copies in this directory (verbatim from the source dir) for the full lineage, soundness footing
  (`schedule_refines` ∪ `schedule_refines_move_cond`, Lean 0-sorry), and known provenance corrections.
- **track note:** size-leader (✗ exceeds-limits) — never runs on-chain, so A1 forge-audit is n/a;
  the applicable certificate is the gate above. The verifier.cash board shows Toorik BN254 singleton
  at **4,651**, which matches NO artifact here — board value stale/approx; the measured on-disk crown
  is **4,329 locking**.

## sha256 (verified identical to source at copy time)

| sha256 | file | locking | score |
|---|---|---|---|
| `9de9e4683baa1cdae03e5b46acd9d0d8b7481ea3707ca5e79f9041e42fabb479` | singleton-4688-locking4329-sqrmul.hex ★ CROWN | 4,329 | 4,688 |
| `4eb54ca1dd685adec91009e499ba0647500a52000f085121925ca98986c96c54` | singleton-4705-locking4346-foldcse.hex | 4,346 | 4,705 |
| `efec8259746b1b433caf17a1dad2729e3a936c6bbd58e8bdc3f7dc41dd66210a` | singleton-4718-locking4359-cse.hex | 4,359 | 4,718 |
| `f7e89c540f5f769bf2f6f5cb24157c845a8b337449f73fcc2d3617210240baf2` | singleton-5177-locking4818-marshcse.hex | 4,818 | 5,177 |
| `61777728c267248bf8a7796fe8d977c605ba0779186a4a87391a60edc241c0c8` | singleton-5272-locking4913-l5fold.hex | 4,913 | 5,272 |
| `5a1f3c1a08758f9da1637dc1fd9784c2ff9bd7f21015dc1fdb1a7c5c26bc1e85` | singleton-5279-locking4920-composed.hex | 4,920 | 5,279 |
| `37399ceb6de4893c6fd4b2a7f0d6fd35ccc45bebc86582efa67c5dc34ebbf82d` | singleton-5295-locking4936-ederive.hex | 4,936 | 5,295 |
| `f00b920131192eeebf29c62923fff08a0ca27992e07aa6c352b7a668f870b119` | singleton-5684-locking5325-constshare.hex | 5,325 | 5,684 |
| `acb779a0c78db23374e182cc43f3b40305d41422044b411feb13578cd52c7f3f` | singleton-5835-locking5476-foldcomplete.hex | 5,476 | 5,835 |
| `b31883bdcd249655ac5713c4f5045ffd0343e28a8f63e556722558ccc008a93a` | singleton-5972-locking5613-richpeep.hex | 5,613 | 5,972 |
| `51255125204d70de52f91db89ce37c6d984e30463fcc00be9e57b301dc6fccec` | singleton-5987-locking5628-search.hex | 5,628 | 5,987 |
| `d7ae8e3c9fbf7cc53b493aa344e76dc50d7820bc7ccc72b4a91b768c7944b273` | singleton-6054-locking5695-movearrange.hex | 5,695 | 6,054 |
| `147c9686594168c35e786486c3a97b15999510f555ca44dc131f6fa815b4e77a` | singleton-6087-locking5728-incremental.hex | 5,728 | 6,087 |

Registry entry: `bn254-size-leader-4329-sqrmul` in `../../registry.json`.
