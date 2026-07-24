# ShieldKit-SDK V2 relation freeze (post Num2Bits_strict)

Observed: 2026-07-24T03:11:38Z

Status: **source-level freeze evidence**. No setup/proof/PF7/BCH/Chipnet/G1 PASS claim.

## Source + toolchain

- Product: ShieldKit-SDK
- HEAD: `744603161e9cadde8cc1fb358023b0c392ac5842`
- Source SHA-256: `900f47cad912b3783bea4d5556f612f5d6e4360bd230f1ce71ed89d07e4d19d4` (pre-repair `3185e287f626152b0a6632e8a5476c1660327383fe26fd3b1d1aa316e76cbe36` **invalidated**)
- circom2@0.2.23 / compiler 2.2.3; Node v20.20.2
- CLI SHA-256: `5e36c6153c416e17b1fa822411b1fb9e4ab9b5cd4a0249cc3b5be3259315f5ad`
- package-lock SHA-256: `e9fe6edade40e0f6228e9892f1649f99ae20f9669660e0959dd74e7a430dc299`

## Dual compile (byte-identical A/B)

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| R1CS | 126,282,348 | `6a797e696a4fe01f500b232270944f93e5e6f171906c37511748ab0f50df0e17` |
| symbol map | 197,473,485 | `80835b11e8b4e7d04e54f3bad71f7bb6a79f4fdd619c5474466b94ca9cabab15` |
| witness WASM | 10,224,716 | `f14eaf5b9a83750a5fd62f1062df40ec66219d7737739b1e6e1e5ef745aede71` |

Counts: nonlinear 506,165; linear 145,310; wires 645,577; public inputs 2.

Artifact root (local, not git): `.cache/relation-freeze-v2-strict/`

## Witnesses

| Action | Packet digest | Input SHA-256 | Witness SHA-256 | Bytes |
| --- | --- | --- | --- | ---: |
| deposit | `c0423a01f8469bc2f6921674b983cd196499292d123996063545e5d9f022827a` | `170df659da2ada411b2deff1b9939377ee656fd845b0712a8215ec333bc1e942` | `79a14946b294ad1eccbd3245a9df168412d012bb2e4467f1eff2ca79d606252f` | 20,658,540 |
| transfer | `22fed947fedc5b6cd4f95d6bee2a97c120c45e0682343f2e03a21c6ce84616b8` | `4435ea2eac1e6c3265a4b0dc11960c2345b380fb25bff583493789db2fcdf137` | `3ba775781807c9391e554f7410f57335748c39082c1e4464e081413285fc000a` | 20,658,540 |
| withdrawal | `5e4c53fcc567e661738eeb327ae30b222dd4ecf59ffaf40855ffb06a310af1b5` | `540704c5ce0fe7ffbb207b09a8afc534dc8333b3626f91b7646b5b1124f2a6e9` | `71fad8d334197d99bce9ea323c719647203e32671d11aee1005ad34729fd09a9` | 20,658,540 |

## Adversarial + alias

- Witness probes: **9/9 pass** (results SHA-256 `3eca8e68f24a9a504e16183ea9d0006cc242595249f19f8e20b22899a00a3503`)
- Package suite: 4/4 including R1CS nullifier Fr-alias reject (`Num2Bits_strict` ×16)

## Ban

Do not use pre-repair R1CS `e51021f4db6355fa9118127158935c3e5d39fd314dee01df7415bd2fc8b659ff` or WASM `642d2d03d9d93a53f48207d1262d6c258c64c70bfb75bdac79b4eeae624b0b85` as authority.
