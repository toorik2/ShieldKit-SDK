# Verifier-profile lifecycle v1

Status: **G1 candidate normative lifecycle contract**. This document specifies
profile selection and replacement boundaries only. It does not attest that any
Groth16 setup, verifier, proof, ceremony, artifact, instance, or BCH
transaction exists or is qualified.

## 1. Stable interface, immutable selection

Implementations MUST load all verifier material through the loader contract in
[manifest-v1.md](manifest-v1.md). The JavaScript reference entry point is
`loadVerifierProfileBundle(directory, expected)`; other SDK targets MUST enforce
the same parsing, artifact, identity, and expected-binding rules. A caller that
has authenticated an existing instance genesis MUST supply that instance's
`network`, `profileId`, and `instanceId` as the expected binding. A mismatch
MUST fail; it is never an invitation to select a replacement bundle.

The stable interface is the only intended meaning of “plug-and-play”:

- wallet, application, transaction-planning, and conformance callers keep the
  same typed bundle-loading API;
- each selected bundle has a derived `profileId` and each instance has a
  derived `instanceId`; and
- no code path may replace verifier keys, proving artifacts, BCH verifier
  scripts, setup provenance, relation, ABI, or any other profile material for
  an existing instance.

Plug-and-play does **not** permit an in-place verifier hot swap, a silent
upgrade, a mutation of authenticated genesis, or reinterpretation of an old
instance's notes, nullifiers, commitments, state, or action history.

### Derivation boundary

The derivation order is fixed: (1) relation, ABI, keys, and BCH verifier-set
bytes; (2) `profileId`; (3) fresh genesis inputs and `instanceId`; (4)
instance-binding/state scripts; then (5) an actual genesis transaction. The
verifier set is in step 1, so it MUST NOT embed final profile or instance IDs;
doing so creates a fixed-point requirement because its bytes are profile-hashed.
It may bind verification-key/topology material and obtain profile/instance
claims from the input-6 public packet. Later binding/state scripts enforce that
packet's profile and instance IDs and pin exact verifier locks.

Manifest-v1 packages only pre-genesis profile artifacts and identity inputs. It
does not package instance-binding/state scripts or an actual genesis output.
Those are distinct later evidence and cannot be silently substituted into the
profile bundle.

## 2. Development initialization

A fresh local Groth16 initialization may produce a bundle only when
`setup.mode` is `development-only`, provenance method is
`local-initialization`, transcript status is `not-applicable`, and the
contribution list is empty. The mode, provenance, artifacts, toolchain, and
their hashes are profile material. A development bundle and every instance
created from it are permanently development-only.

Local initialization is not a ceremony, contribution, transcript, or
production qualification. Changing either setup/key material or setup
provenance changes `profileId`; it therefore requires distinct authenticated
genesis and produces a distinct `instanceId`, even when the relation and
public-input ABI are unchanged.

`initializerCommitment` alone is not complete setup provenance. Development
material MUST additionally bind the exact Phase 1 powers-of-tau source
identifier and SHA-256, the complete argv arrays for Phase 2 initialization and
local contribution commands, a commitment to the private contribution
randomness, and a final zkey SHA-256 equal to the proving-key artifact hash.
The ptau remains provenance metadata rather than a runtime bundle artifact.
The manifest and command arrays are public: they MUST NOT contain raw
contribution entropy, toxic waste, wallet seeds, credentials, or other secret
material.

## 3. Future ceremony adapter

No ceremony adapter is implemented by this candidate. When authorized, an
adapter MUST accept exactly these typed inputs before it can emit a
`ceremony-production` bundle:

1. `profileTemplate`: `standard`, `network`, `profile` relation identifier and
   hash, constraint-system hash, public-input-ABI identifier and hash,
   proof-system/curve, and pinned `toolchain` records.
2. `ceremonyRecord`: complete transcript regular-file bytes and path,
   transcript SHA-256, transcript-verifier name/version/SHA-256, and an
   ascending sequence of at least two contribution records. Each record has
   `sequence`, `participantCommitment`, `contributionHash`, and a `verified`
   verifier name/version/SHA-256 record.
   It also identifies the Phase 1 ptau source and SHA-256, Phase 2
   initialization command argv, and the verified final zkey SHA-256. The final
   zkey hash must equal the packaged proving-key artifact hash; contribution
   records are canonically hashed into the typed final-zkey chain, and the
   transcript remains a separately hash-bound artifact.
3. `artifacts`: exact regular bytes for all required bundle kinds:
   `relation-definition`, `constraint-system`, `public-input-abi`,
   `verification-key`, `proving-key`, `witness-generator`, and
   `bch-verifier-set`, plus the `ceremony-transcript`. The adapter MUST derive
   every artifact SHA-256 from those bytes and bind the relation, constraint,
   ABI, verifier-set, and transcript hashes in the manifest.
4. `newGenesis`: fresh category-input outpoint at vout `0`, Chipnet network,
   and immutable denomination-valid reserve cap. It MUST be created for the
   new profile; an existing instance genesis is not valid input for replacement.

The adapter output is one canonical `manifest.json`, its regular artifact
files, and loader-derived `profileId` and `instanceId`. The manifest MUST use
`setup.mode: ceremony-production`,
`provenance.method: multi-party-randomness`, and a complete transcript bound to
the transcript artifact. The adapter MUST reject incomplete transcripts,
unverified/duplicate/unordered contributions, unsupported paths, hash drift,
or identity disagreement. A syntactically loadable result is still not a claim
that the ceremony is secure or that any release gate has passed.

## 4. Replacement and migration boundary

Changing setup, keys, artifacts, verifier scripts, relation, ABI, constraints,
or toolchain emits a new profile. The new profile requires a new genesis and
new instance. Existing instances remain on their original profile and retain
their original semantics permanently.

There is no automatic migration, note conversion, wallet background rewrite,
or transaction-semantic compatibility layer. If a future protocol defines a
migration, it MUST be an explicit, user-authorized sequence of ordinary
old-instance and new-instance actions, with separate profile/instance
identifiers at every boundary and fresh conformance plus gate evidence. This
candidate neither defines nor authorizes such a migration.
