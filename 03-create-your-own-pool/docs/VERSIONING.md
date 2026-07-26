# Versioning

| Layer | ID | Mutable |
|-------|-----|---------|
| Toolkit | root `package.json` SemVer (`0.y.z` until 1.0) | yes |
| Profile | `profileId` = `sha256:…` | no |
| Instance | `instanceId` + genesis | no after birth |
| Blobs | release tag + sha256 | new tag if content changes |

New setup ⇒ new profile + new genesis.

**Toolkit tags:** `v0.y.z` · **Profile arts:** `playground-bundle-vN` (never tag a zkey as `v0.x.y`).

While 0.y.z, MINOR may break — [CHANGELOG](../../CHANGELOG.md).  
Maturity labels (Charter) are independent of toolkit version. Default claim: **Unaudited — Work In Progress**.

Development ptau: hash-only allowed only for pinned trusted Hermez `final_20`; ceremony path always full-verifies. Force full: `setup.verifyPtau: true` / `--verify-ptau`.
