# @shield.cash/local-setup

Offline, non-production Groth16 development initialization. It runs the pinned
local `snarkjs@0.7.6` CLI only through `execFile`, creates an initial zkey,
makes exactly one local Phase-2 contribution, verifies the final zkey against
the caller-supplied R1CS and ptau, exports a verification key, and writes
`setup-metadata.json` with a manifest-v1-compatible `setup` object.

The caller supplies regular non-symlink R1CS/ptau paths, expected SHA-256s,
exact ptau power, ptau source identifier, and the pinned CLI hash/version. The
tool verifies the ptau header and R1CS capacity before setup, runs ptau
verification, and refuses hash, capacity, version, symlink, or destination
overwrite drift. The current shield.cash ABI is enforced at setup: the R1CS
must have exactly two public inputs and zero outputs; its constraint and ABI
counts are recorded in metadata. Immediately before metadata publication, the
R1CS and ptau are rechecked as direct regular files with their original hashes.
The only output mode is `development-only`.

Entropy is supplied only through inherited stdin or `--entropy-fd` referring to
an already-open private regular file descriptor. It is never placed in argv,
metadata, logs, or environment data. The tool stores only a domain-separated
SHA-256 commitment and clears its in-memory buffer after use. Input must be
32--4096 bytes of UTF-8 text with no line break because snarkjs reads one
interactive entropy line.

This is not a ceremony runner or production setup. It does not create a wallet,
transaction, BCH script, network request, or proof corpus. The generated
development artifacts require separate profile-building, BCH, VM, and gate
evidence before any Chipnet claim.
