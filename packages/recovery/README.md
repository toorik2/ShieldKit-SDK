# `@shield.cash/recovery`

Portable V1 recipient-address and chain-recovery primitives for SDK bindings.
The default entrypoint is browser-safe ESM: it imports neither `node:crypto` nor
`Buffer`, retains secrets locally, performs no network or persistence I/O, and
works with `Uint8Array` only.

```js
import {
  constructRecipientOutput, deriveRecipientAddress, recoverRecipientOutput,
} from '@shield.cash/recovery';

const address = await deriveRecipientAddress({ seed, profileId, instanceId });
const sent = await constructRecipientOutput({ address, kind: 'transfer', slot: 0 });
const note = await recoverRecipientOutput({
  seed, profileId, instanceId, kind: 'transfer', slot: 0,
  outputCommitment: sent.output.cm, record: sent.record,
});
```

`seed` and `record` are exact-length `Uint8Array`s. Identifiers and field
encodings are lowercase 32-byte hex strings. Errors are `RecoveryError` with a
stable `code`; authentication failures deliberately do not expose plaintext.
The record remains exactly 192 bytes: `version | slot | X25519 ephemeral public
key | nonce | ChaCha20-Poly1305 ciphertext-and-tag | two zero bytes`.

## Packet-only history recovery

`recoverAuthenticatedChainHistory` accepts an explicit V1 `accountSeed`,
profile/instance IDs, and caller-authenticated contiguous action-packet bytes
anchored by exact initial and terminal serialized states. It reconstructs owned
notes, derives their nullifiers, and returns spent/unspent status. The companion
`serializeChainHistoryActions` is the strict exact-field-to-packet codec.

It performs no node, indexer, service, storage, or network access. The caller
remains responsible for BCH provenance, ordering, and state-anchor
authentication. A terminal anchor detects a truncated prefix; continuity and
packet fingerprints detect reordered and duplicate packets. This is not a
raw-node sync, reorg, 10,000-history, archive-availability, or independent
implementation claim.

The seed is a V1 account seed, not a root-seed hierarchy. V1 retains exactly
one recipient address for `(accountSeed, profileId, instanceId)`; applications
with a master seed must supply their own versioned account derivation and scan
each account seed separately.

## Cryptographic and portability boundary

V1 derivation, domains, record layout, X25519, HKDF-SHA256,
ChaCha20-Poly1305, and Poseidon commitment semantics are unchanged. The default
backend is pure-JS Noble (`@noble/curves` 2.2.0, `@noble/hashes` 2.2.0,
`@noble/ciphers` 2.1.1); exact V1 Poseidon arities use `poseidon-lite` 0.3.0.
All are lockfile-pinned. `./node` exposes a native `node:crypto` backend only
for integration/conformance checks; it is never imported by the portable entry.

Construction obtains randomness only through WebCrypto `getRandomValues` (or an
explicit `rng.bytes(length)` source) and fails closed if it is unavailable or
malformed. An explicit `cryptoBackend` must implement X25519 public/shared
secret, HKDF-SHA256, and authenticated seal/open; the SDK validates that shape
at runtime. The included Node backend and default Noble backend are both real
implementations, not mocks.

`npm test` pins a deterministic V1 vector and proves byte identity between
Noble and native Node crypto. It also bundles the public entrypoint and runs an
actual Chromium module worker using WebCrypto randomness. This is portability
evidence for the recovery core, not a browser proving benchmark or an Android
qualification claim.

Android remains a binding boundary: a current Android app must provide a
standards-compliant JavaScript runtime with `Uint8Array`, `BigInt`, ES modules,
and WebCrypto `getRandomValues`, then run this ESM package or bind the same
typed backend. No Android device execution or performance claim is made here.
