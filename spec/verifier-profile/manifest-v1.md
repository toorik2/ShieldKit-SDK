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
immutable maximum reserve for that instance. It is nonzero, divisible by the
10,000,000-satoshi denomination, and no greater than the 2,100,000,000,000,000
satoshis that can exist under BCH's issuance schedule. This pre-genesis bundle
does not contain an actual genesis transaction outpoint; that transaction is a
later, authenticated instance record.

## Canonical bytes and hashes

Manifest bytes are strict UTF-8 JSON without a BOM, parsed with duplicate keys
rejected. The canonical JSON form is UTF-8 serialization with object member
names sorted lexicographically by Unicode code point, no insignificant
whitespace, JSON string escaping only for quotation mark, reverse solidus, and
U+0000--U+001F (lowercase four-digit hex), and finite JSON values only. The
manifest is at most 1 MiB. Arrays retain their required order: `artifacts` are
strictly ascending by `id`, and ceremony `contributions` are strictly ascending
by unbounded decimal `sequence`. All identifier hashes are lowercase
`sha256:<64 lowercase hex>`. An artifact hash is SHA-256 of exact regular-file
bytes and is computed by streaming I/O.

`profileMaterial` is a new object made from exactly these manifest members:
`artifacts`, `network`, `profile`, `setup`, `standard`, and `toolchain`.

```
profileId = "sha256:" + SHA256(
  UTF8("shield.cash/verifier-profile-id/v1\\0") || canonicalJSON(profileMaterial)
)
```

`genesis.categoryInputOutpoint` names the pre-existing UTXO spent to create the
CashToken category. Its `vout` is exactly string `"0"`, as required for a
CashToken genesis category. `txid` is 32 bytes of lowercase hex in
`OP_HASH256`/P2P wire byte order (the byte order used by BCH token category
fields), not block-explorer display byte order. `stateNftCategory` is derived
without hashing: it is exactly that nonzero `txid` string. The loader rejects
any other value. This fixes the category before the genesis transaction exists
and avoids deriving an identifier from an outpoint that transaction itself will
create.

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
constraint-system, public-input ABI, and `bchVerifierSetHash` hashes.
`artifacts` contains exactly one regular file for each required kind:
`relation-definition`, `constraint-system`, `public-input-abi`,
`verification-key`, `proving-key`, `witness-generator`, and
`bch-verifier-set`. The first three hashes and `bchVerifierSetHash` must equal
their corresponding profile hashes. `bch-verifier-set` is one canonical,
profile-authenticated file which enumerates the distributed BCH verifier
material; individual scripts are not independently selectable bundle artifacts.
Artifact IDs, kinds, and paths are unique and IDs are strictly sorted. Paths
are relative POSIX paths with no empty component, `.`, `..`, backslash, or
absolute path.

`bch-verifier-set` and `witness-generator` are authenticated material, not an
assertion that any verifier is standard, sound, executable, or proof-accepting.
This contract deliberately contains no proof-acceptance API.

The `bch-verifier-set` is pre-genesis profile material and therefore MUST NOT
embed its final `profileId` or any `instanceId`: `profileId` already hashes
that artifact. It binds verification-key/topology material and derives identity
claims from the public packet. Instance-specific packet/profile/instance checks
and exact verifier-lock pinning belong to later binding/state scripts; those
scripts are not artifacts in this pre-genesis manifest.

## Setup modes

`setup.mode` is exactly one of:

- `development-only`: local initialization. Its transcript and contribution
  verification statuses must be `not-applicable`; every instance remains
  permanently development-only. `setup.material.phase1` binds the exact ptau
  source identifier and hash without packaging the ptau as a runtime artifact.
  Its phase-2 material binds exact initialization and contribution command
  argv arrays, a randomness commitment, and the final zkey hash, which must
  equal the proving-key artifact hash. Command arrays are public provenance and
  MUST NOT contain entropy, toxic waste, seeds, credentials, or other secrets;
  secret contribution randomness is represented only by its one-way
  commitment.
- `ceremony-production`: multi-party randomness. A complete transcript artifact
  is required; its SHA-256, path, and verifier metadata must be bound, and each
  contribution must have a unique participant commitment, contribution hash,
  and `verified` verifier record. Its phase-1 material binds the ptau source and
  hash, while phase-2 binds the exact initialization command and final zkey
  hash (equal to the proving-key artifact), a verifier record, and a
  contribution-chain SHA-256 derived from canonical contribution records. This
  syntactic validation is not a claim that a ceremony is secure or
  production-qualified.

Changing setup, relation, ABI, constraints, keys, proving artifacts, scripts,
toolchain, or any profile-material byte changes the derived profile ID. A new
profile requires a new genesis; existing instances are never mutated.

## Loader contract

`loadVerifierProfileBundle(directory, expected)` reads `manifest.json`, rejects
non-canonical or duplicate JSON, unknown fields, unordered/missing/duplicate
artifacts, unordered ceremony contributions, symlinks and realpath escapes,
non-regular artifacts, hash mismatch, setup-evidence mismatch, identity
mismatch, and caller-supplied profile/instance/network mismatch. It returns a
deeply frozen parsed manifest and derived IDs only after all checks pass.
