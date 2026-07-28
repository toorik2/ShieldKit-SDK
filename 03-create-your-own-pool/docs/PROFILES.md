# Profile pins

Content hashes, not toolkit semver. Setup/VK/zkey change ⇒ new profile + new genesis.

## Playground (Chipnet, development-only)

| Field | Value |
|-------|--------|
| Ref | `02-use-chipnet-demo-pool` (`playground`, `chipnet-playground`) |
| profileId | `sha256:15586a31bd2d57b6dd6048470c4531fd4421adebe58b73a2d4983c94c1a0d2b0` |
| instanceId | `sha256:f4fdcbe3e76bb1eb3637c0212fe78d6594eec1823edb1bf63fc38c3fb95c3615` |
| Capacity | 32 × 0.1 BCH (`reserveCapSatoshis` = 320000000) |
| stateNftCategory | `127401ae2be67c6c9ab33ad2e2ff7efac67ff098278f3cd56d1ac362d3579197` |
| Genesis txid | `97f5bb616d10d4568c61f07009c0a7590a06594df92a982bd84982443e282d2d` |
| Bundle tag | `playground-bundle-v4` |
| Bundle URL | https://github.com/toorik2/ShieldKit-SDK/releases/download/playground-bundle-v4/chipnet-playground-profile-bundle.tar.gz |
| Bundle sha256 | `sha256:f996a15ebdb5a1969474a11da302d110ab00a8b9631fd1b1bb29537ea1b757f7` |
| Proving key sha256 | `sha256:493ea7e7ac0d4f2fe891e279a0253fb7278292d18219e693d786c4cd9a757bc2` |
| Pin manifest | `shieldkit-pin-artifacts-v2.manifest.json` (current default) |
| Fetch | `npm run fetch-playground-bundle` |
| Descriptor | [`../../02-use-chipnet-demo-pool/instance.json`](../../02-use-chipnet-demo-pool/instance.json) |

Your pool pins live in that pool’s `instance.json` + bundle `manifest.json`.
