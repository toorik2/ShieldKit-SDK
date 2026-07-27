# External Phase-2 contribution transcript

ShieldKit’s built-in sequential runner is a
`local-contribution-simulation`. It is useful for development and loader
tests, but one coordinator sees every contribution and it cannot establish
participant independence.

The external protocol in
`packages/profile/setup/external-contribution.mjs` separates participant work
from coordinator work:

1. The coordinator creates a request binding `ceremonyId`, numeric sequence,
   R1CS SHA-256, Phase-1 SHA-256, and the exact previous zkey SHA-256.
2. An independently operated participant receives that request and the pinned
   input files, runs `snarkjs zkey contribute` in its own environment, and
   returns the new zkey.
3. The participant signs an Ed25519 receipt binding the request, output zkey
   SHA-256, entropy commitment, participant ID, and public key. Entropy itself
   is never sent to the coordinator API.
4. The coordinator verifies every signature, strict sequence, previous/output
   hash link, and uniqueness of both participant IDs and signing keys.
5. The resulting canonical transcript binds the full chain and receives its
   own SHA-256.

The transcript proves integrity of the declared contribution chain. It does
not prove that participants were independent, destroyed entropy, secured their
machines, or followed an acceptable governance process. Those claims require
out-of-band identity, operational, and audit evidence. Accordingly, this SDK
labels the result `external-contribution-transcript` and never promotes it to
`production-qualified`.

Any production deployment must additionally:

- publish the request/receipt transcript and all artifact hashes;
- document contributor selection, communication boundaries, and incident
  handling;
- independently verify the final zkey against the R1CS and Phase-1 file;
- obtain a circuit, covenant, implementation, and operational audit; and
- create a new profile and genesis after qualification.
