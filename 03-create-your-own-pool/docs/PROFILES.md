# Profile pins

Content hashes, not toolkit semver. Setup/VK/zkey change ⇒ new profile + new genesis.

## Playground (Chipnet, development-only)

| Field | Value |
|-------|--------|
| Ref | `02-use-chipnet-demo-pool` (`playground`, `chipnet-playground`) |
| profileId | `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7` |
| instanceId | `sha256:cfe741f64d0e47cf995a3c22bb7070e1afcf5c8a277594124d8ea445cde4a8ea` |
| Capacity | 32 × 0.1 BCH (`reserveCapSatoshis` = 320000000) |
| stateNftCategory | `a42804c79fdc61ac1c8c9d86025bbd1eaf0fdbe0d8ad3f9d13835e8adc7503b8` |
| Genesis txid | `6a9fe6f6ba0c075859240f3fe2535ab8420ec0f1eece1ed405b0b6f3578a36e6` |
| Bundle tag | `playground-bundle-v3` |
| Bundle URL | https://github.com/toorik2/ShieldKit-SDK/releases/download/playground-bundle-v3/chipnet-playground-profile-bundle.tar.gz |
| Bundle sha256 | `sha256:e3800562cf6b5f57258dc0ccc5029a17711ffd497767a103972b58d84a7de970` |
| Proving key sha256 | `sha256:254a7bb27113deb14abb58da2bb476861b689f47e062915a507482e29314882a` |
| Fetch | `npm run fetch-playground-bundle` |
| Descriptor | [`../../02-use-chipnet-demo-pool/instance.json`](../../02-use-chipnet-demo-pool/instance.json) |

Your pool pins live in that pool’s `instance.json` + bundle `manifest.json`.
