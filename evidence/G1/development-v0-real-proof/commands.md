# Recorded commands and environment

Environment: Linux `7.1.3-arch1-2 x86_64 GNU/Linux`; 20 CPU threads; 46 GiB
RAM; Node `v25.9.0`; npm `11.12.1`; snarkjs `0.7.6` CLI SHA-256
`6d787e37a4d1a2c6dd6032dadca09c0b3b007d4d4578bb6232a98136555d051a`.
The VM result used `@bitauth/libauth 3.1.0-next.8` BCH-2026 semantics in
verifier.cash commit `c9a0c1653709ae360d69611a997ac114bf9a4c8f`.

```bash
node packages/proof-corpus/proof-corpus.mjs /home/toorik/Projects/ZK-Proofs/shield-g1-artifacts/proof-corpus-low128-v0.manifest.json
node packages/local-setup/node_modules/snarkjs/build/cli.cjs zkey verify <r1cs> <ptau> <development-only-final.zkey>
node packages/local-setup/node_modules/snarkjs/build/cli.cjs groth16 verify <development-only-vk> <action-public.json> <action-proof.json>
cd /tmp/verifiercash-shield-10role-019f8ed4
C7_SHIELD_ADAPTER_FILE=/home/toorik/Projects/ZK-Proofs/shield-g1-artifacts/deposit-pf7-adapter.json C7_SHIELD_ADAPTER_SHA256=d895e004e163ed8c07f08b0ed98d339d9e0ac22a56f6c76d00b81436bca64637 C7_PROJECTED_BQ_7=1 C7_FIXED_G2_TABLE=1 C7_COMPOSED_P2SH=1 C7_COMPOSED_DIRECT_TERMINAL=1 C7_PAIRFOLD_TOPOLOGY=7 C7_SELF_CARRIED_TERMINAL=1 TERMINAL_FUSION9=1 harness/node_modules/.bin/tsx lanes/bn254-onetx/src/c7/build.ts
harness/node_modules/.bin/tsx lanes/bn254-onetx/src/c7/measure-terminal-raw-attacks.ts .vc/runs/g1-real-deposit/tmp .vc/runs/g1-real-deposit/tmp/raw-attacks-v3.json
sha256sum <artifact-path>; wc -c <artifact-path>
```

`<ptau>` is not duplicated here; the large external artifacts remain hash-bound
in `proof-corpus-result-summary.json` and `artifact-hashes.json`.
