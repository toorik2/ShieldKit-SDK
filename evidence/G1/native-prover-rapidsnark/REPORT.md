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

Nine warm proofs (three per action) measured 2.546–3.362 seconds and
562,484–566,628 KiB peak RSS. The initial distribution median is 2.745 seconds
and 566,564 KiB; its maximum is below the frozen 30-second / 4-GiB desktop
budget. The result is feasibility evidence only: three warm samples per action
on one non-isolated Linux laptop do not establish p95 target-hardware
qualification.

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

The committed adapter is fail-closed: it hash-pins native binary, `snarkjs`,
zkey, VK, and witnesses; measures the direct native process with Linux
`VmHWM`; verifies every proof through pinned `snarkjs`; and rejects public
signal drift. Binaries and generated proofs remain outside Git; only their
identities, hashes, and measured summaries appear here.
