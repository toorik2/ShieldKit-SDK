# Development prover-artifact budget

Observed: 2026-07-23

Candidate: `g1-bn254-groth16-single-note-v0`

Scope: the compressed-artifact ceiling only. This is not a browser, Android,
proving-time, ceremony, verifier, transaction, or G1 qualification result.

## Result

The real development-v0 proving key and witness-generator WASM occupy
`170,577,395` bytes after deterministic zstd compression. The frozen ceiling is
`536,870,912` bytes, so this measurement uses 31.77% of the budget and leaves
`366,293,517` bytes.

| Artifact | Raw bytes | Raw SHA-256 | Compressed bytes | Compressed SHA-256 |
| --- | ---: | --- | ---: | --- |
| `final.zkey` | 321,581,772 | `37a7ee2fe9e7ee1e2583d60e0e52d86360d7c7a7be5b23dbb0cc166bb5905453` | 169,098,026 | `29d5cae27788ac7a948a346beb366ec14936b59293bd9fe67e7fb1dc78c1463b` |
| `g1_relation.wasm` | 9,977,099 | `1332f89bf4287fc51d7a6f4fd86acb45511a3aaf4ccd4859c6aecda4dd4b3b57` | 1,479,369 | `cbc4e5a6d93690986c3e76153a1486c0deac82333e6b72668cb76e075d6ad44a` |

The packager used `/usr/bin/zstd` 1.5.7, SHA-256
`6b799c822798547e33f3d928d04492ca4814d4b45088786b73d700f0cc0d905a`,
with `-q --no-progress -T1 -19 --no-check`. It revalidated the executable,
source identities, compressed streams, decoded sizes, and decoded hashes before
publishing a previously absent destination.

Root independently streamed both published archives through `zstd -d -c`.
Their decoded byte counts and SHA-256 identifiers exactly reproduced the input
artifacts.

The observable private-staging creation-to-publication interval was
102.854900445 seconds. This is a filesystem-timestamp interval because the
original terminal wrapper yielded before returning its elapsed counter.

## External artifacts

- Input manifest:
  `/home/toorik/Projects/ZK-Proofs/shield-g1-artifacts/prover-artifacts-low128-v0.input.json`
  (`1e0073663047acbd3a3881f583452f9790c685e92eb56ffb55822394f87d1efb`)
- Result:
  `/home/toorik/Projects/ZK-Proofs/shield-g1-artifacts/prover-artifacts-low128-v0/result.json`
  (`f26cfdc63fbdd04fa3e1551433ec0a6aea88c50191f122e93126220807366e03`)
- Compressed outputs:
  `/home/toorik/Projects/ZK-Proofs/shield-g1-artifacts/prover-artifacts-low128-v0/`

The inputs are permanently `development-only`; successful compression does not
promote their setup provenance.
