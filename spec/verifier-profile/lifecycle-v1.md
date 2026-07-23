# Verifier-profile lifecycle v1

Status: **G1 candidate normative lifecycle contract**. This document specifies
profile selection and replacement boundaries only. It does not attest that any
Groth16 setup, verifier, proof, ceremony, artifact, instance, or BCH
transaction exists or is qualified.

## 1. Stable interface, immutable selection

Implementations MUST load all verifier material through
`loadVerifierProfileBundle(directory, expected)` as specified in
[manifest-v1.md](manifest-v1.md). The caller that has authenticated an existing
instance genesis MUST pass that instance's `network`, `profileId`, and
`instanceId` as `expected`. A mismatch MUST fail; it is never an invitation to
select a replacement bundle.

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
