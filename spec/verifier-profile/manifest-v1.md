# Verifier-profile bundle manifest v1

Status: normative interface definition for G1 implementation work. It is not
cryptographic qualification evidence and does not define a proof verifier.

## Scope and separation

A **standard** defines this manifest interface (`shield.cash`, version `1`). A
**profile** is the immutable cryptographic and BCH-verifier material described
by `standard`, `profile`, `setup`, `toolchain`, `network`, and `artifacts`. An
**instance** is the separate `genesis` object. Thus two instances can share a
profile, while any material change to a profile produces a new profile ID.

`network.name` is currently `chipnet`; no value in this interface authorizes
mainnet. `genesis.reserveCapSatoshis` is a decimal integer string and is the
immutable maximum reserve for that instance.

## Canonical bytes and hashes

Manifest bytes are strict UTF-8 JSON without a BOM, parsed with duplicate keys
rejected. The canonical JSON form is UTF-8 serialization with object member
names sorted lexicographically by Unicode code point, no insignificant
whitespace, JSON string escaping only for quotation mark, reverse solidus, and
U+0000--U+001F (lowercase four-digit hex), and finite JSON values only. Arrays
retain order. All identifier hashes are lowercase `sha256:<64 lowercase hex>`.
An artifact hash is SHA-256 of the exact regular-file bytes.

`profileMaterial` is a new object made from exactly these manifest members:
`artifacts`, `network`, `profile`, `setup`, `standard`, and `toolchain`.

```
profileId = "sha256:" + SHA256(
  UTF8("shield.cash/verifier-profile-id/v1\\0") || canonicalJSON(profileMaterial)
)
```

`instanceMaterial` is `genesis` with `instanceId` omitted. Its `profileId` and
`network` must equal the derived profile ID and profile network respectively.

```
instanceId = "sha256:" + SHA256(
  UTF8("shield.cash/verifier-instance-id/v1\\0") || canonicalJSON(instanceMaterial)
)
```

The loader recomputes both values and rejects disagreement. A caller that has
an authenticated existing genesis must supply its expected profile and instance
IDs; disagreement is a hot-swap failure, not a selection event.

## Required binding

`profile` names the proof system and curve and binds independent relation,
constraint-system, and public-input ABI hashes. `artifacts` contains exactly
one regular file for each required kind: `relation-definition`,
`constraint-system`, `public-input-abi`, `verification-key`, `proving-key`,
and `bch-verifier-script`. The first three hashes must equal their corresponding
profile hashes. Artifact IDs, kinds, and paths are unique. Paths are relative
POSIX paths with no empty component, `.`, `..`, backslash, or absolute path.

`bch-verifier-script` is the exact BCH locking/verifier material selected by
the profile, not an assertion that it is standard, sound, or executable. This
contract deliberately contains no proof-acceptance API.

## Setup modes

`setup.mode` is exactly one of:

- `development-only`: local initialization. Its transcript and contribution
  verification statuses must be `not-applicable`; every instance remains
  permanently development-only.
- `ceremony-production`: multi-party randomness. A complete transcript artifact
  is required; its SHA-256, path, and verifier metadata must be bound, and each
  contribution must have a unique participant commitment, contribution hash,
  and `verified` verifier record. This syntactic validation is not a claim that
  a ceremony is secure or production-qualified.

Changing setup, relation, ABI, constraints, keys, proving artifacts, scripts,
toolchain, or any profile-material byte changes the derived profile ID. A new
profile requires a new genesis; existing instances are never mutated.

## Loader contract

`loadVerifierProfileBundle(directory, expected)` reads `manifest.json`, rejects
non-canonical or duplicate JSON, unknown fields, missing or duplicate artifacts,
symlinks, path escape, non-regular artifacts, hash mismatch, setup-evidence
mismatch, identity mismatch, and caller-supplied profile/instance/network
mismatch. It returns a deeply frozen parsed manifest and derived IDs only after
all checks pass.
