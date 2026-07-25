# Versioning hygiene

## Layers (do not merge)

| Layer | Identity | Mutability |
|-------|----------|------------|
| **Toolkit** | SemVer in root `package.json` (`0.y.z` until 1.0) | mutable code |
| **Protocol** | Charter / docs versions | rare, explicit |
| **Profile** | `profileId` = `sha256:…` | **immutable** |
| **Instance** | `instanceId` + genesis | **immutable after birth** |
| **Maturity** | Charter labels | claims, not numbers |
| **Blobs** | GitHub release tag + sha256 pin | new tag if content changes |

**New setup ⇒ new profile + new genesis. No hot-swap.**

## Toolkit semver

- **Source of truth:** monorepo root `package.json` → `version`.
- **MAJOR** (when ≥1.0): breaking `createKit` / `init` / `loadInstance` / CLI / instance.json contract.
- **MINOR:** new capability or (while 0.y.z) may break — document in CHANGELOG.
- **PATCH:** fixes, docs, no contract change.

## Git tags (split)

| Tag shape | Object |
|-----------|--------|
| `v0.y.z` | Toolkit source (code) |
| `demo-bundle-vN` or `playground-bundle-vN` | Large profile artifacts only |

Never tag a zkey as `v0.3.0`. Never reuse/overwrite release assets.

## Maturity labels (charter)

`design draft` · `evidence experiment` · `profile candidate` · `Chipnet qualified` · `mainnet candidate` · `mainnet qualified`

Toolkit version does **not** imply any of these. Pre-1.0 default claim: **Unaudited — Work In Progress**.

## Related

- [CHANGELOG.md](../../CHANGELOG.md) · [PROFILES.md](PROFILES.md) · [CHARTER.md](CHARTER.md)
