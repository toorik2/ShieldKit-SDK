# ShieldKit V2 native recovery scanner

This crate performs offline, deterministic V2 Direct recovery from
caller-authenticated raw BCH transactions. It does not query a node and does
not treat a snapshot hash or signature as evidence of BCH consensus.

Build and validate with the pinned toolchain:

```sh
cargo +1.97.1 build --locked
cargo +1.97.1 test --locked
cargo +1.97.1 clippy --all-targets --all-features --locked -- -D warnings
```

The binary accepts exactly one JSON value on stdin:

```sh
shieldkit-v2-recovery scan < scan-request.json
shieldkit-v2-recovery scan-stream < framed-scan.bin > framed-material.bin
shieldkit-v2-recovery authenticate-snapshot < anchored-snapshot-request.json
shieldkit-v2-recovery authenticate-snapshot-stream \
  < framed-snapshot.bin > framed-material.bin
shieldkit-v2-recovery verify-snapshot < verify-request.json
```

`scan` requires:

- `schema: "shieldkit-v2-recovery-scan-v1"`;
- profile/network/instance/denomination/carrier-count bindings;
- a txid-, height-, and block-hash-anchored raw genesis transaction;
- the exact genesis output-0 outpoint and 128-byte initial `SKS2` state;
- ordered, anchored raw action transactions;
- an explicit txid-pinned raw source transaction for every funding prevout;
- an exact expected output-0 tip with txid, height, and block hash.

The scanner computes every txid, parses canonical CompactSize and CashToken
prefixes, preserves the state category in token-prefix wire order, follows the
exact output-0 lineage, and rejects forks or unrelated higher-sequence states.
It accepts the binding input only as
`PUSHDATA2(552) || SDA2 packet || MINIMAL_PUSH(binding redeem script)`, with
exactly one redeem push and no additional bytes. It requires the source binding
output to be canonical P2SH32 (`aa20<hash256(redeem)>87`) and authenticates the
revealed redeem script against that exact source lock. It rebuilds every
`SDC2` transaction-context hash from the actual txid-verified source outputs
and incrementally reconstructs both depth-32 trees with the frozen V2 Poseidon
domains.

`scan` returns `shieldkit-v2-recovery-scan-result-v1`. Its `snapshot` binds
the profile, instance, network, exact genesis and tip, height, block hash,
terminal state, ordered packets, and reconstructed roots. Its `material`
contains the complete authenticated node prefixes, active note frontier,
ordered note records, indexed-nullifier successor leaves, and canonical tip
needed by the SQLite store. Raw replay retains these nodes while applying each
action, so producing the material performs no second Poseidon pass.

`authenticate-snapshot` is the normal snapshot-import path. Its request
supplies the independently authenticated profile, exact genesis point, and
exact canonical tip point. It reconstructs both terminal roots bottom-up once,
checks every packet's encoding, identity, counter/value delta, pre/post-state
chain, and ordered note/nullifier contribution, and requires exact equality
with those external anchors. It does not replay every historical Merkle update.
It returns `shieldkit-v2-recovery-authenticated-material-v1`, with the same
store material shape as `scan.material`. Hashes and records remain strict
lowercase hexadecimal strings on this JSON wire; the Node adapter validates
and converts them to fixed-width byte arrays before atomic store installation.

`verify-snapshot` is the explicit slow audit fallback. It authenticates the
snapshot and then independently repeats the complete raw-genesis scan,
including every fixed-depth historical tree update, before requiring exact
snapshot equality. Normal CLI recovery does not run this second replay after a
successful raw scan.

## Bounded framed recovery

`scan-stream` is the long-history transport. It does not accept a monolithic
JSON history and does not emit a monolithic JSON result. The wire is:

```text
"SKR2F001"
repeated:
  payloadLength u32be
  payload UTF-8 JSON[payloadLength]
```

Every payload is independently limited to 524,288 bytes. A zero-length or
larger frame fails closed before JSON decoding. Input uses the exact schema
`shieldkit-v2-recovery-stream-input-v1` and this order:

1. One `header` frame. It declares canonical-decimal `actionCount` and contains
   the scan request fields other than `schema`, `actions`, and
   `fundingPrevouts`.
2. Exactly `actionCount` `action` frames. Indexes are canonical decimal,
   contiguous from zero, and each frame pairs one anchored action with the
   exact txid-pinned raw transaction containing that action's funding prevout.
   This pairing lets the scanner validate and discard raw transactions one
   action at a time rather than retaining a history-sized input array.
3. One `end` frame containing the same action count, the exact number of
   preceding frames, and a SHA-256 transcript digest.
4. Immediate EOF. Truncation and every trailing byte fail closed.

The input digest is:

```text
SHA256(
  "ShieldKit V2 recovery stream input v1\0" ||
  every pre-end (payloadLength || payload), in exact wire order
)
```

The output uses `shieldkit-v2-recovery-stream-output-v1`. It begins with a
counted `header`, then a compact `snapshot`/material header, and then exactly
indexed records in this fixed order:

```text
action
note-node
note-frontier
note-leaf
nullifier-node
nullifier-leaf
```

The terminal `end` frame repeats every count and binds every preceding output
frame with:

```text
SHA256(
  "ShieldKit V2 recovery stream output v1\0" ||
  every pre-end (payloadLength || payload), in exact wire order
)
```

Consumers must stage all rows and commit only after receiving and validating
the `end` frame and a clean scanner exit. A missing, duplicated, reordered,
oversized, malformed, digest-mismatched, or trailing frame is not a partial
snapshot. It is a failed recovery attempt.

The framing bounds transient transport memory to one frame; it does not claim
that the authenticated tree working set is constant-size. The scanner still
retains the terminal depth-32 tree state and recovery records required to
produce the checkpoint. Those structures scale with pool history and remain
subject to the separate recovery-RSS/store-size qualification gates.

The existing `scan` JSON command remains available for small histories and
compatibility. Its stdin remains capped at 256 MiB. It is not the long-history
interface.

### Bounded authenticated snapshots

`authenticate-snapshot-stream` is distinct from `scan-stream`; frames from one
schema are never accepted by the other. Its exact input schema is
`shieldkit-v2-recovery-authenticate-snapshot-stream-input-v1`:

1. One `header` frame declares `actionCount`. Its request contains the
   independently authenticated network, profile, instance, denomination,
   carrier count, exact genesis point, exact canonical tip point, and a compact
   snapshot. The compact snapshot contains every normal snapshot field except
   `actions`; `noteTree` contains only `depth`, `count`, and `root`;
   `nullifierTree` contains only `depth`, `count`, and `root`.
2. Exactly `actionCount` contiguous `action` frames carry the normal snapshot
   action records in canonical chain order. They do not carry raw BCH
   transactions, note-leaf arrays, or nullifier-key arrays.
3. One counted/digested `end` frame followed immediately by EOF.

Its input transcript is:

```text
SHA256(
  "ShieldKit V2 recovery authenticate snapshot stream input v1\0" ||
  every pre-end (payloadLength || payload), in exact wire order
)
```

The scanner strictly decodes each ordered 552-byte packet and validates its
action-specific state delta before deriving an ordered note leaf and/or
nullifier key. After validating the complete frame transcript, it reconstructs
both terminal trees bottom-up exactly once through the normal authenticated
snapshot path. It then validates the snapshot content hash, history hash,
packet chain, terminal roots/counts/state, and exact independently supplied
profile/genesis/tip bindings. Its output schema and record order are exactly
the same as `scan-stream`.

Node callers use the separate
`authenticateNativeRecoverySnapshotStream({ binaryPath, binarySha256,
requestHeader, actionCount, actions, timeoutMs })` API. `actions` may be an
iterable or async iterable of normal snapshot action records. This API never
silently dispatches the raw-scan schema.

## Authentication boundary

The caller must authenticate the profile artifact and establish that every
asserted block is on the active best chain at the required confirmation depth.
Raw transaction parsing cannot prove block inclusion, chain work, confirmation
status, or absence of a later reorganization. Snapshot content hashes detect
mutation; they are not signatures or consensus proofs. The scanner enforces
the 100,000-byte transaction and 10,000-byte input-unlock policy ceilings, but
does not execute the BCH VM or measure VM resource usage.

Node callers should use
`packages/pool/v2/recovery-native.mjs`. It opens a regular non-symlink binary
with `O_NOFOLLOW`, verifies the caller-supplied SHA-256 pin, and executes that
same open file through an inherited Linux `/proc/self/fd` descriptor with
`shell: false`. `scanNativeRecoveryStream` accepts an iterable or async
iterable of `{ action, fundingPrevout }` pairs, writes one bounded frame at a
time, validates the output framing/order/counts/digests incrementally, and
yields converted rows. The yielded rows are provisional until its final
`{ type: "end" }` value. Abandoning iteration kills the scanner; callers must
roll back their staging transaction.
