# Operator source registry and fanout

This is qualification infrastructure, not an end-user ShieldKit command. It
remains explicitly unqualified beta software and never waits for a block
confirmation: exact zero-conf raw-transaction and output readback through the
pinned public Chipnet Fulcrum providers is the only acceptance boundary.

One owner has one canonical private registry at
`<operator-root>/source-registry-v1/shieldkit-v2-beta-operator-source-registry.sqlite`.
The root, registry directory, and every claimed data-home directory must already
exist as current-user canonical `0700` directories with no symlinked ancestry;
the database, wallets, inventories, ledgers, and journals must be private `0600`
unlinked regular files with canonical, non-symlinked ancestry. A run never accepts a list of
previous ledgers or scans a wallet to decide whether an outpoint is reusable.
The database is the sole reuse authority. It assigns immutable roles: exactly
the twenty reconciled fanout recipients are `fanout-performance` sources, and
a separately authenticated source is `semantic`. A source cannot be registered
under the other role, and no claimed source may share a pool data-home with any
other claimed source.

First provision 21 independent private identities: `wallet-01` through
`wallet-20` are the only fanout performance recipients; `wallet-21` is
reserved for the separate semantic pool and is never a fanout output.

```sh
npm run qualification:v2:beta:operator-fanout -- provision \
  --operator-root /private/shieldkit-v2-operator
```

The operator funds one separately held P2PKH source wallet, writes a canonical
private inventory containing at least two source outpoints, then prepares the
fanout locally. The prepared transaction consumes all authenticated inputs,
pays exactly 20 distinct P2PKH outputs of at least `53,006,565` sats, preserves
a dust-safe fresh change output, is signed locally, and is evaluated under
`BCH_2026_STANDARD` for its exact serialized bytes and every input.

The private inventory is RFC 8785 canonical JSON, mode `0600`, has no symlinked
parent, and contains
only explicit already-owned outpoints (no address scan or selection):

```json
{"schema":"shieldkit-v2-beta-operator-fanout-inventory-v1","sourceOutpoints":["<txid-a>:0","<txid-b>:1"]}
```

```sh
npm run qualification:v2:beta:operator-fanout -- prepare \
  --operator-root /private/shieldkit-v2-operator --run-id fanout-r1 \
  --source-wallet /private/source-wallet.json \
  --inventory /private/fanout-inventory.json
```

`prepare` records exact bytes in an immutable private journal and creates a
canonical SQLite `prepared` operation. It does not send. The explicit send is
the only network mutation and uses the mandatory coordinator boundary:

```sh
npm run qualification:v2:beta:operator-fanout -- broadcast --execute-live \
  --operator-root /private/shieldkit-v2-operator --run-id fanout-r1
```

There is no automatic rebroadcast. A pre-send rejection leaves the operation
`prepared`; a disconnect after the durable send boundary or an exact-readback
failure leaves it `indeterminate`. Inspect it explicitly; recovery is read-only
and registers outputs only if the pinned public Chipnet Fulcrum providers
return the exact journal bytes and all 20 tokenless outputs with exact locks
and values. Direct BCHN is reserved solely for an explicitly injected branded
lab-attestation capability.

```sh
npm run qualification:v2:beta:operator-fanout -- recover \
  --operator-root /private/shieldkit-v2-operator --run-id fanout-r1
```

The operator workflows use the same three pinned, TLS-verified public Chipnet
providers as the product: one sender and two read-only witnesses. They accept
no RPC URL, RPC credentials, or SSH option. A direct BCHN handle exists only as
an explicit branded lab/test injection seam.

Each output progresses through the canonical state machine:
`available`, `semantic-claimed`, `performance-reserved`, `send-attempted`,
`indeterminate`, `spent`, `reconciled`, or `explicitly-released`. Every CAS
transition records outpoint provenance, wallet lock, value, release, data
home, installation receipt, lease/run, evidence digest, timestamp, and prior
state. Fanout inputs are atomically registered with their prepared operation
before the journal is written; an existing registry source or a previously
reserved fanout input cannot be used to construct another fanout. A source that
was once sent or indeterminate is never silently returned to the available set.

Before spending the separate semantic source, authenticate it against the
pinned public Chipnet providers with exact raw-transaction and live-UTXO
readback, then claim it explicitly. Its `--data-home` must already exist as a
canonical private `0700` directory, so aliases and nonexistent paths cannot
bypass the global custody-home uniqueness rule.
The command refuses an already-spent source; it is not a retrospective chain
attestation tool. This source can never be among the twenty performance
recipients:

```sh
npm run qualification:v2:beta:operator-source-claim -- \
  --operator-root /private/shieldkit-v2-operator --run-id semantic-r1 \
  --outpoint <txid:vout> --wallet-locking-bytecode <p2pkh-hex> \
  --value-sats <decimal-sats> --data-home /private/semantic-pool \
  --installation-receipt-sha256 <sha256> --release-id <release-id> \
  --release-manifest-sha256 <sha256> --semantic-evidence-sha256 <sha256>
```

Then the performance reservation command creates a durable private reservation
intent/ledger and atomically transitions exactly 20 registry `available`
records to one lease. A crashed reservation must be resumed against those exact
bindings, never recreated with a new lease. The SQLite registry pins the exact
v2 DDL facts and runs `foreign_key_check` on every open. Fanout operations bind
the canonical input-set digest and exact input count; every state CAS requires
exactly that reservation set. Expiry release compares the ledger
against every immutable registry binding (role, release, home, receipt, lock,
value, lease/run, and evidence digest) before releasing anything. The performance runner verifies that lease before its first command
and transitions each source `performance-reserved → send-attempted → spent →
reconciled` only after exact pool-create inspection. No paths, raw outpoints,
keys, raw transactions, witnesses, or circuit inputs belong in public evidence.
