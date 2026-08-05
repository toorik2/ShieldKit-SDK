# FriStark-Formal pins

## Upstream BCH-FRI-STARK-Verifier
- repo: https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier
- commit: a600e828d68eb41840049cb16d0c21850ff9df57
- path: vendor/bch-fri-stark
- verified_rev: a600e828d68eb41840049cb16d0c21850ff9df57

## Freeze A0
- path: vendor/freeze-a0 (snapshot of ShieldKit docs/protocol/v2-stark)

## LeanBCH host
- path: vendor/leanbch-host
- commit: ba8e7730e35c6d0bb5d4fa6fbce717073304c71c
- toolchain: leanprover/lean4:v4.31.0

## Production FRI (Params.V1)
- BLOWUP=2048 QUERIES=8 GRIND_BITS=24 FOLD=8
- MASK_DEG=64 MERKLE_HASH_BYTES=32 EXT_NONRES=7
- P=2^64-2^32+1
- SECURITY_BITS=104 (target >=100)
