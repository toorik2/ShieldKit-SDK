# `@shield.cash/sdk`

The SDK is an offline, wallet-facing facade over the authenticated profile,
portable recovery, witness/planning, preparation, settlement, and genesis
primitives. It is not a service client: it opens no RPC connection, discovers
no chain data, stores no secret, calls no hosted prover, and broadcasts nothing.

The safe order is:

1. Desktop: load a hash-authenticated profile with exact `network`, `profileId`,
   and `instanceId` coordinates.
2. Derive a recipient address from a caller-held seed; scan serialized BCH
   outputs supplied by the application and recover matching 192-byte records.
   For a contiguous caller-authenticated packet segment, call
   `recoverAuthenticatedHistory` with a V1 account seed and exact initial and
   terminal state anchors; it locally reconstructs owned notes and their
   spent/unspent state without a service client.
3. Require an explicit `local-only` prover capability, make witness-bound plans,
   and supply only profile-bound real PF7 unlocking material to settlement.
4. Plan a complete preparation transaction, pass the emitted signing request to
   the integrator's signer, then return only the 64-byte Schnorr signature to
   `finalizeCompletePreparation`.
5. Serialize the complete ten-input settlement only after the application has
   locally generated its real proof/PF7 unlocks. Read exact sizes and fees from
   `measurements`; the protocol rate is exactly one satoshi per serialized byte.

The facade never receives a private key. A `local-only` prover capability is a
typed integration assertion, not evidence that a proof is valid; proof validity
is established by the profile-bound PF7 and complete BCH VM execution gates.

`./browser` bundles only portable recovery and profile-coordinate validation;
it contains no Node built-ins. It has no browser proving claim. `./android`
offers two deliberately distinct paths:

- `createAndroidWalletSdk` accepts a typed embedding-runtime contract for
  bridges that already perform their own checks.
- `createDetectedAndroidWalletSdk` first runs `probeAndroidRuntime()` against
  the active Android JavaScript engine. It exercises BigInt arithmetic,
  Uint8Array allocation, and WebCrypto `getRandomValues`, and refuses a host
  whose user agent is not Android. Successful import is the ESM check.

The probe is an executable prerequisite check. Its result becomes
portable-runtime evidence only when captured on an actual Android runtime; it
is never a device model, Android app-RSS, proving-performance, p95, or G4
qualification claim. A physical-device proof run remains the fail-closed
`packages/android-prover-harness` workflow; it uses caller-pinned local files,
USB `adb`, and no network service. This checkout currently has no `adb`
executable, so no physical Android evidence is claimed here.

```js
import { createDesktopWalletSdk } from '@shield.cash/sdk';

const sdk = await createDesktopWalletSdk({
  bundleDirectory: '/trusted/local/profile',
  expectedProfile: { network: 'chipnet', profileId, instanceId },
});
const address = await sdk.deriveRecipientAddress(seed);
const plan = await sdk.planCompletePreparation(funding);
const signing = await sdk.preparationSigningRequest(funding);
// Sign `signing.digest` in the host wallet; do not give this SDK the key.
const prepared = await sdk.finalizeCompletePreparation(funding, signatureHex);
```

Development-only bundles remain development-only. Replacing setup material
means a new profile and new genesis; the SDK will reject a bundle whose exact
coordinates differ from the requested profile.

The portable history helper does not obtain BCH history or authenticate a
provider. The integrator supplies authenticated, ordered packets plus both
state anchors; the helper detects malformed, duplicate, reordered, and
truncated supplied history. It makes no raw-node synchronization, reorg,
10,000-transition, archival-availability, or independent-implementation
claim. Its `accountSeed` is the V1 seed defining one address for this profile
and instance, not an SDK-defined master/root hierarchy.
