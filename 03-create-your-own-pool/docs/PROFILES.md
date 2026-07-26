# Profile pin table

Content IDs only. **Not** toolkit semver. Changing setup/VK/zkey ⇒ new row (new profile + new genesis).

## Demo (optional Chipnet)

| Field | Value |
|-------|--------|
| **Instance ref** | `02-use-chipnet-demo-pool` (aliases: `chipnet-playground`, `playground`) |
| **Role** | optional live demo — not a hosted product |
| **Network** | chipnet |
| **setupMode** | `development-only` |
| **Maturity** | Unaudited — Work In Progress; **not** production privacy |
| **profileId** | `sha256:79782441a9d56f7d8199d9812ba566daddad63e20142fc9e7d2a33c7a66e5bf7` |
| **instanceId** | `sha256:bb27e427a13f62aac70727492c4762b8ba4fb031296de14bebb30565dbb3ce06` |
| **Capacity** | 16 live × 0.1 BCH (`reserveCap` = 160000000); ~10 live notes at release cutover |
| **stateNftCategory** | `af5831853433ccd226727bc508885ca472f30c10c201b34b007ee5c069944530` |
| **Descriptor** | [`02-use-chipnet-demo-pool/instance.json`](../../02-use-chipnet-demo-pool/instance.json) |
| **Bundle release tag** | `playground-bundle-v2` (artifact tag — **not** toolkit semver) |
| **Bundle URL** | https://github.com/toorik2/ShieldKit-SDK/releases/download/playground-bundle-v2/chipnet-playground-profile-bundle.tar.gz |
| **Bundle tarball sha256** | `sha256:7a34c7cdceab9af97278e9cdd8d3df51891c093bbd90e15e966c92eb2878d79e` |
| **Proving key sha256** | `sha256:254a7bb27113deb14abb58da2bb476861b689f47e062915a507482e29314882a` |
| **Fetch** | `npm run fetch-playground-bundle` |

## Your pool

Created via `03-create-your-own-pool` (`init` → bundle → `instance.json` → genesis).  
Pins live in **your** `instance.json` + bundle `manifest.json` — add a private table if you operate multiple instances.

## Toolkit compatibility

| Toolkit | Notes |
|---------|--------|
| `0.1.0` | Hygiene baseline; loads demo pins above when bundle present |

No automatic “version match” between toolkit and profile — you pin hashes explicitly.
