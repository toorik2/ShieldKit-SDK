# Development verifier-profile replacement comparator

`compareDevelopmentVerifierProfileBundles({ leftDirectory, rightDirectory })`
is a strict, read-only G1 interface-replacement comparator. It loads both
completed bundles through the core loader before comparing them, so canonical
manifest encoding, duplicate JSON names, regular-file requirements, symlinks,
artifact paths, and every artifact hash are checked before any comparison
output exists.

The only accepted inputs are the two bundle directories. Caller-supplied
profile, instance, network, or hash overrides are rejected. Both bundles must
be `development-only` with `local-initialization` provenance on exactly
Chipnet. They must retain the same standard, Phase-1 ptau source and hash,
compiler and generator toolchain records, Groth16/BN254 relation and constraint
material, public-input ABI, witness-generator hash, and fixed-note-reserve
genesis semantics, while changing setup commitments, final zkey, verification
key, BCH verifier-set, profile ID, instance ID, and category input outpoint.

Run it with:

```sh
node packages/core/compare-development-profiles.mjs --left bundle-a --right bundle-b
```

It emits one canonical JSON document only on success. This establishes only an
interface replacement property for completed local-development bundles. It
does not initialize setup, construct or broadcast a BCH genesis transaction,
prove BCH VM behavior, establish standardness, or qualify G1.
