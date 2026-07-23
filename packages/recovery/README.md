# `@shield.cash/recovery`

Portable V2 recipient-address and chain-recovery primitives for SDK bindings.
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
The record remains exactly 192 bytes: `version=2 | slot=0 | compressed
BabyJubJub recipient point | compressed ephemeral point | c_rho | c_r |
Poseidon authentication field | 30 zero bytes`. `c_rho` and `c_r` are field
additive masks derived from BabyJubJub ECDH and a domain-separated Poseidon
KDF. The recipient point is committed into `ak`; recovery therefore rejects a
record that is not addressed to the authority in the output commitment.

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

## Deterministic scale conformance

`scale-history-conformance.mjs` writes public deterministic test vectors outside
the repository and compares the Node/circomlibjs transition reference against
portable packet recovery:

```sh
node scale-history-conformance.mjs /absolute/artifact/output 10000
```

It covers at least 384 valid deposit/transfer/withdrawal transitions and runs
the requested 10,000-transition recovery workload. It does not claim Groth16,
BCH VM, BCHN, relay, miner, raw-block-provenance, or production qualification.

The seed is a V1 account seed, not a root-seed hierarchy. V1 retains exactly
one recipient address for `(accountSeed, profileId, instanceId)`; applications
with a master seed must supply their own versioned account derivation and scan
each account seed separately.

## Raw settlement extraction (Node-only subpath)

`@shield.cash/recovery/raw-settlement-history` consumes caller-supplied raw BCH
genesis and settlement transaction bytes. It computes each transaction ID,
requires ten settlement inputs, extracts only input 7's exact
`PUSHDATA2(752)` packet, validates input 8's direct vout-0 state ancestry,
state lock/hash, mutable zero-amount NFT category and commitment, and packet
profile/instance/state continuity. Its result is exact anchors plus packets for
`recoverAuthenticatedChainHistory`.

`createRawSettlementJournal` is an offline append/rollback/replay container for
caller-supplied branches. Its synthetic structural scale test exercises journal
memory and deterministic rollback mechanics only; it is not raw-node, BCH VM,
Chipnet, reorg, provider-authentication, or 10,000-transition recovery
evidence. The caller must authenticate raw BCH provenance and confirmation
order, and an independent implementation remains a G5 requirement.

## Raw BCH structural parsing and self-hosted BCHN consistency (Node-only)

`@shield.cash/recovery/raw-chain-recovery` contains two deliberately distinct
surfaces. `parseRawBchBlock`, `verifyRawChainSegment`, and the in-memory journal
are **untrusted structural parsers**: they check raw transaction boundaries,
merkle roots, header linkage, structural proof of work, and arithmetic chainwork
against caller-supplied anchors. They do not establish BCH consensus, canonical
chain selection, coinbase validity, difficulty rules, UTXO validity, BCH VM
validity, or G5 recovery. Never use an arbitrary structural segment as a wallet
chain source.

`fetchBchnRawChainSegment` is the bounded self-hosted BCHN subpath. Its caller
pins an authenticated checkpoint, while the node supplies the current canonical
tip and every block hash by height. It requires `chain == "chipnet"`, an
available non-IBD/non-pruned node with equal block/header counts, and a stable
`getblockchaininfo` snapshot. For every height it cross-checks
`getblockhash`, raw and verbose `getblockheader`, raw `getblock`, parent hash,
height, confirmations, merkle/header bytes, and cumulative chainwork. It rejects
tip changes during fetch, stale nodes, wrong networks, malformed responses, and
equivocation. It first proves the checkpoint is canonical at its declared
height, including the checkpoint chainwork, so a zero-block suffix is not an
unchecked success. One request is bounded to 10,000 blocks; a wallet must retain
an authenticated checkpoint and resume in bounded suffixes for longer history.
The RPC adapter takes only `(method, params)` and never stores or logs
credentials.

This remains a single-BCHN, bounded consistency layer rather than a consensus
engine or independent implementation. It is useful only after its raw suffix is
also passed through profile-bound settlement validation; it does not close G5,
which still requires long-history, VM, archival, adversarial, and independent
implementation evidence.

## Cryptographic and portability boundary

V2 intentionally replaces the unprovable X25519/HKDF/ChaCha record with the
same native-field BabyJubJub and Poseidon operations used by the Circom
relation. The portable implementation checks compressed-point canonicality,
curve membership, nonidentity, and prime subgroup membership before ECDH. It
does not claim constant-time JavaScript execution. `poseidon-lite` 0.3.0 is
lockfile-pinned; no Node crypto, network, persistence, prover, or backend
service is imported by the portable entrypoint.

Construction obtains randomness only through WebCrypto `getRandomValues` (or an
explicit `rng.bytes(length)` source) and fails closed if it is unavailable or
malformed. The one-output G1 relation fixes `slot=0`; callers cannot silently
construct an unprovable multi-output record.

`npm test` exercises deterministic V2 record construction, mutation rejection,
and an actual Chromium module worker using WebCrypto randomness. This is
portability evidence for the recovery core, not a browser proving benchmark,
an Android qualification, a ceremony, or a proof/verifier qualification.

Android remains a binding boundary: a current Android app must provide a
standards-compliant JavaScript runtime with `Uint8Array`, `BigInt`, ES modules,
and WebCrypto `getRandomValues`, then run this ESM package or bind the same
typed backend. No Android device execution or performance claim is made here.
