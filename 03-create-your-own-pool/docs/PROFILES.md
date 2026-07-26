# Profile pins

Content hashes, not toolkit semver. Setup/VK/zkey change ⇒ new profile + new genesis.

## Playground (Chipnet, development-only)

| Field | Value |
|-------|--------|
| Ref | `02-use-chipnet-demo-pool` (`playground`, `chipnet-playground`) |
| profileId | `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7` |
| instanceId | `sha256:bb27e427a13f62aac70727492c4762b8ba4fb031296de14bebb30565dbb3ce06` |
| Capacity | 16 × 0.1 BCH (`reserveCapSatoshis` = 160000000) |
| stateNftCategory | `af5831853433ccd226727bc508885ca472f30c10c201b34b007ee5c069944530` |
| Bundle tag | `playground-bundle-v2` |
| Bundle URL | https://github.com/toorik2/ShieldKit-SDK/releases/download/playground-bundle-v2/chipnet-playground-profile-bundle.tar.gz |
| Bundle sha256 | `sha256:7a34c7cdceab9af97278e9cdd8d3df51891c093bbd90e15e966c92eb2878d79e` |
| Proving key sha256 | `sha256:254a7bb27113deb14abb58da2bb476861b689f47e062915a507482e29314882a` |
| Fetch | `npm run fetch-playground-bundle` |
| Descriptor | [`../../02-use-chipnet-demo-pool/instance.json`](../../02-use-chipnet-demo-pool/instance.json) |

Your pool pins live in that pool’s `instance.json` + bundle `manifest.json`.
