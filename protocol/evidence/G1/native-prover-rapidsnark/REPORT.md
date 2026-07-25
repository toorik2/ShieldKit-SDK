# G1 native Groth16 prover feasibility: rapidsnark

Observation time: 2026-07-23. Status: **G1 OPEN**.

This is an initial desktop feasibility measurement for the exact
`relation-low128-v0` development artifacts, not a G4 p95 hardware
qualification, profile selection, ceremony claim, or G1 PASS. It uses no
wallet, BCH node RPC, funding, broadcast, hosted prover, or circuit/setup
change.

## Result

Official iden3 `rapidsnark` source commit
`81eddf1a536d26497b237c0b8a04fe90baf7e439`, built as a native OpenMP
no-ASM configuration, generated and pinned-`snarkjs@0.7.6`-verified every
proof for the exact v0 `final.zkey` and the deposit, transfer, and withdrawal
witnesses. Every generated public-signal array exactly matched its corpus
counterpart.

The earlier nine-proof warm sample is retained in `raw/warm-summary.json` as
exploratory build-feasibility context only. It predates the hardened adapter and
is not the adapter-execution record.

The hardened adapter then ran the same exact v0 corpus three times per action
(nine proofs total) with absolute caller paths, duplicate-key-safe UTF-8
manifest parsing, pin revalidation around every subprocess, bounded child
output, and atomic no-clobber publication. Its external full result is
`/tmp/shield-g1-rapidsnark-hardened-final-20260723-FZTJTq/adapter-output/result.json`
(`fd7b8d44b1dc63f9ab6b344943a45bf9d710c1281f41e4a98cf9b21fce1b4bbb`,
14,064 bytes). The committed structurally identical bounded transcription is
`raw/hardened-adapter-result.json`; it lists all nine proof and public-signal
hashes and is bound by this observation.

The hardened runs measured 4.033–4.537 seconds and 562,548–566,640 KiB peak
RSS (median 4.143 seconds and 566,564 KiB). Every native proof was
pinned-`snarkjs@0.7.6` verified and every exact two-scalar public-signal array
matched its corpus counterpart. This remains feasibility evidence only: one
non-isolated Linux laptop and three samples per action do not establish p95
target-hardware qualification.

The source-default ASM build failed before compilation because `nasm` was not
installed. The supported `USE_ASM=OFF` configuration then exposed GCC 16 source
compatibility (`<cstdint>` not directly included); the successful build leaves
the pinned source unchanged and adds `-include cstdint`. Its GMP 6.3.0 closure
was source-pinned by the upstream script and built with `-std=gnu17`, required
because GCC 16 rejects that legacy GMP configure probe under its default C
language mode.

## Exact identity

| Item | SHA-256 |
| --- | --- |
| native `prover` | `123856b3f2a39360c64d83a3ca8e5cca3ad18ea03a28c0cfddf2b2a7ea00a598` |
| GMP 6.3.0 archive | `a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898` |
| built static GMP | `089bad78e216180d236ac48865eca869a71dc2d1d291a43f7464f43629d9afd4` |
| exact `final.zkey` | `37a7ee2fe9e7ee1e2583d60e0e52d86360d7c7a7be5b23dbb0cc166bb5905453` |
| exact verification key | `d4b6b4e0a6c371a019ffa7457a7c2a265b7e3a90ae2a12619424a249903c9a59` |
| pinned `snarkjs` CLI | `6d787e37a4d1a2c6dd6032dadca09c0b3b007d4d4578bb6232a98136555d051a` |

The committed adapter is fail-closed: it requires lexical absolute manifest
paths; hash-pins direct regular non-symlink binary, `snarkjs`, zkey, VK, and
witnesses with device/inode/size/hash revalidation before and after each
relevant subprocess; bounds child output; validates exactly two canonical
BN254 scalar public signals; and publishes only an absent destination from an
identity-checked staging directory. Binaries and generated proofs remain
outside Git; the bounded result records their identities, hashes, and measured
summaries here.
