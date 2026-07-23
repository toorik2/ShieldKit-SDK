# Fresh witness inputs

`generateFreshWitnessInputs` loads and verifies a complete local
`development-only` verifier-profile bundle, takes caller-supplied exact SCCT
digests, and produces a sequential deposit → transfer → withdrawal relation
chain. Each result includes a canonical 752-byte action packet, its two
SHA-256 public limbs, and the exact JSON input accepted by the G1 low128 WASM.

The input must contain exactly `bundleDirectory`, `expectedProfile`,
`witnessSeed`, `withdrawalScriptHash`, and the three
`transactionContextDigests`. `expectedProfile` is the full
`{network, profileId, instanceId}` binding from the already authenticated
genesis manifest; the loader rejects a bundle that does not match it. The seed
is private witness material; no profile, setup, proof, BCH transaction, or
network activity is created here.

The returned `actions[kind]` contains:

- `action`: canonical reference-transition material;
- `actionPacket` and `actionPacketHex`: exactly 752 bytes;
- `publicInputs`: two 32-byte Fr encodings of the action-packet SHA-256 halves;
- `circuitInput`: the matching low128 Circom JSON object; and
- `actionDigest`: the action-packet SHA-256.

For the profile-build handoff, load the finalized bundle directory only after
the profile builder has written its canonical manifest. Feed the complete
assembler's exact SCCT digest for each action into
`transactionContextDigests`; do not reuse a bootstrap digest. The returned
`profile` echoes the authenticated profile ID, instance ID, state-NFT category,
and reserve cap for the assembler to cross-check.

Active records are constructed through the public recipient-address path in
`@shield.cash/recovery`: a sender has only `{ak,recoveryPublicKey}` and never
needs a recipient spend secret. They are 192-byte
X25519/HKDF-SHA256/ChaCha20-Poly1305 records, cryptographically constructed and
byte-bound by G1, but G1 does not prove AEAD correctness. Wallet recovery must
decrypt and recompute the note before accepting it. This module is
development-only witness tooling, not a G2/Chipnet qualification claim.

To exercise the real relation witness generator when an authenticated local
bundle and its matching WASM are available:

```sh
SHIELD_FRESH_WITNESS_TEST_BUNDLE=/path/to/bundle \
SHIELD_FRESH_WITNESS_TEST_WASM=/path/to/g1_relation.wasm \
SHIELD_FRESH_WITNESS_TEST_GENERATOR=/pinned/path/to/generate_witness.js \
npm test --prefix packages/fresh-witness-inputs
```

The test fail-closes unless the supplied WASM is exactly 9,977,099 bytes and
its SHA-256 equals the authenticated bundle's `witness-generator` artifact; it
also requires an explicit pinned generator path, then verifies all three
19,301,356-byte witness outputs.
