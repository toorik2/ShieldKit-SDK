# G1 verifier partition qualification: PF7 sub62

Candidate `bn254-onetx-pf7-sub62-r1` is an existing, unmodified seven-input
PairFold topology in verifier.cash commit
`26468ae29004d2401619032de2a6ec8de269a4d6`. It was rebuilt in a disposable,
pinned toolchain environment and passed the runner's real BCH-2026/libauth VM
corpus. This is research/qualification evidence only; it is not G1 PASS,
production, ceremony, relay, Chipnet deployment, or release readiness.

## Measured result

| Metric | PF6 frozen baseline | PF7 sub62 measured | Delta |
| --- | ---: | ---: | ---: |
| inputs | 6 | 7 | +1 |
| all-bytes score | 54,949 | 54,541 | -408 |
| serialized wire bytes | 54,739 | 54,296 | -443 |
| total unlocking bytes | 54,461 | 53,975 | -486 |
| source locking bytes | 210 | 245 | +35 |
| maximum unlocking bytes | 9,877 | 9,176 | -701 |

Per-input unlocking sizes are `[8177, 6654, 7066, 7066, 8393, 7443, 9176]`.
Every input is at or below the frozen 9,500-byte ceiling; the tightest margin
is 324 bytes (and 824 bytes below the 10,000-byte per-input limit). The score
is `53,975` unlocking + `245` source locking + `321` wire overhead = `54,541`.

All seven source outputs are 1,000 satoshis with 35-byte P2SH32 locks. Five
share `aa20eb0c69daa0983d3159edeb08e34afe8cd9c19c780102768158404a1987bcc68387`;
genesis is `aa20dccd679da50f5ae616256fa8391a63d1875139dc3df77efc67ae1b15836c83dc87`;
terminal is `aa20101986aaf6d040ae959b0c4b60bbec064ba7cd1846cea27656723ed9957b7f5187`.
The fixture has one 1,000-satoshi `OP_RETURN` output and encodes a 6,000-satoshi
miner fee; it is not peer-relay evidence.

The primary result hash is
`e5e13c7ac614c8a48b1eebb0ee3a5a4a4c5e82a5d08e9d1ebdada6841b68d307`; the
complete transaction hex hash is
`b86886291035a4e8bafea8e9f8eb6cb86dea52ad1e67853b0316480f3abafdf4`.

## Real VM / adversarial corpus

The unmodified candidate runner reports `gateOk=true`, all seven honest VM
inputs accept, and no filler. Its input red-team corpus reports: honest 7/7
accept; three additional valid proof sets 21/21 inputs accept; worst-case 7/7
accept; off-curve A 7/7 reject; off-curve B 7/7 reject. Noncanonical-B rejects
at genesis and off-subgroup-B rejects at terminal. The off-subgroup run itself
has result SHA-256 `e870d8809b688472e541d9edcf1c0dbf6c36554c4a40b7615237125567549c48`.

The operating-cost measurement is 5,667,649 against budget 5,987,200, leaving
319,551 cost units of margin.

## Provenance and semantic boundary

The source candidate canonical-manifest hash recorded by the runner is
`8066cfd98936564912f67cd99e33a4346a22f89db64544d4e51bb024a2a5a8ce`;
its raw-file SHA-256 is `c03e8ae157998f513f058433e58e3252e05a2d2c39f5577a992d39c9daf3ff19`.
It preserves the same Groth16/BN254, runtime-proof, fixed-VK/deployment profile,
dense-proof fixture, fixed-G2 static mode, off-subgroup fixture, and runtime
corpus as PF6. The topology is deliberately different: PairFold 7, five striped
fragments, `idealVariant: gen6-7in`, and its declared fixed-G2 witness-table
allocation. This is a measured repartition, not a byte projection.

Toolchain: CashC `1c707c1dbf87396b30ba5e0704b1db44475ce893`, libauth
`3.1.0-next.8`, LeanBCH `51201015fdaef4562debf2a2b1cab4013a45e8b4`,
BCH-2026, Node v25.9.0, npm 11.12.1, PNPM 10.12.2 for build/harness. The
vendored CashC and LeanBCH optimizer closures were built in disposable staging
trees; no live checkout was changed.

## Limitations

- The candidate manifest's old expected score/wire fields (55,840 / 55,519) do
  not match this measured run. The runner bundle and raw generated artifacts
  above are authoritative for this observation; reconcile manifest expectations
  before any promotion.
- Fixed/hardcoded verifier material remains unsuitable as a shield.cash profile
  bundle or ceremony claim.
- This does not measure complete shield.cash state/action/encryption/fee-input
  envelope, current standard relay, two BCHN peers, or a verifier ceremony.
- Raw generated transaction and 1.7 MB red-team vectors are deliberately not
  copied into this evidence worktree; their hashes are retained in `hashes.txt`.
