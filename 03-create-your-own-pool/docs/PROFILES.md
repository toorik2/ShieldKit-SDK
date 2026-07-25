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
| **instanceId** | `sha256:d96968b889dfdcfd65f0e89953d94a2ac2f0ca60c03bfa23867ce4293b8bc1aa` |
| **Descriptor** | [`02-use-chipnet-demo-pool/instance.json`](../../02-use-chipnet-demo-pool/instance.json) |
| **Bundle release tag** | `playground-bundle-v1` (artifact tag — **not** `v0.1.0`) |
| **Bundle URL** | https://github.com/toorik2/ShieldKit-SDK/releases/download/playground-bundle-v1/chipnet-playground-profile-bundle.tar.gz |
| **Bundle tarball sha256** | `sha256:6813fcb7d102b2c9616a5918ca9eaa51ca1b2e3d6bd945bc2a308f3bf3317f6b` |
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
