# @shield.cash/profile-builder

Status: offline G1 candidate tooling. It packages caller-supplied verifier
material; it does not generate Groth16 setup, keys, proofs, ceremony
contributions, BCH scripts, wallets, transactions, or network activity.

`buildVerifierProfileBundle(input)` accepts typed metadata plus each artifact
and toolchain record as either an API-only `Uint8Array`/`Buffer` or a regular,
non-symlink `sourcePath`. It calculates every artifact and toolchain digest,
constructs canonical manifest-v1 bytes, derives IDs through `packages/core`,
stages, reloads with the core loader, and only then creates a new destination.
Existing destinations fail closed and are never overwritten.

The builder derives `profileId` only after hashing the verifier-set bytes, then
derives `instanceId` from fresh genesis inputs. Its byte-level guard rejects a
verifier set that directly embeds either final identifier (ASCII or raw digest).
This is defense in depth, not a BCH-script semantic proof. Instance-binding and
state scripts are deliberately outside this pre-genesis package.

Development input is restricted to `development-only` plus
`local-initialization`; transcript and contributions are generated as the
required `not-applicable`/empty values. Ceremony input is packaging-only: it
requires caller-supplied transcript artifact and verified contribution records
in the lifecycle-v1 shape. It neither verifies a ceremony cryptographically
nor makes any qualification claim.

Both setup modes require typed phase material. Phase 1 carries an exact ptau
source identifier and SHA-256 without copying ptau into the runtime bundle.
Development mode additionally carries Phase 2 initialization/contribution argv
arrays, a randomness commitment, and a final-zkey hash bound to the supplied
proving-key bytes. Ceremony mode carries its typed final-zkey verification
record; this package validates only manifest structure and file hashes.

The CLI is `node cli.mjs --input metadata.json`. Relative `sourcePath` and
`destination` values are resolved relative to the metadata file. There is no
CLI command for generating fixtures or setup material.
