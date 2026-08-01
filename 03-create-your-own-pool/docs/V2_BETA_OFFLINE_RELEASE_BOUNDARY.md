# V2 beta offline release boundary

`pack-v2-beta-offline-bundle.mjs` copies three already-private custody trees
into a new private local bundle and emits an exact-JCS allowlist of runtime,
ceremony, and native files. The manifest is published last as the bundle commit
marker. `install-v2-beta-offline-bundle.mjs` accepts only the exact release ID
and manifest SHA-256 committed by the repository-tracked
`pins/v2-beta-product-offline-r3.pin.json`; the bundle cannot authenticate a
replacement manifest using hashes it supplied itself. Neither command performs
a network request or makes a production or release-qualified claim.

Installation holds a synchronous SQLite exclusive transaction for the whole
operation. The kernel releases that lease after normal exit or SIGKILL, so
there is no partially-written PID lock to repair. Copied files and directory
entries are fsynced before publication. The final step always invokes the
product artifact installer, which verifies the reusable independently pinned
runtime, historic-ceremony, native-prover, and cross-binding artifacts once at
installation time. An idempotent restart rechecks the installed receipt against
both the journal and pinned bundle before loading it. Installation does not
create a pool-specific runtime: it establishes the reusable pinned-artifact and
receipt boundary that later commands may load from.

Remote publication remains intentionally unimplemented. The tracked hash is
the trust root for this one local beta bundle only. A future remote publication
layer must add an audited signature/threshold and key-rotation policy plus an
immutable transport identity before any URL or remote retrieval is accepted.

## Blank-machine procedure and command boundary

This is a deliberately unqualified beta procedure. It is not a release or
production installation procedure, does not establish confirmation or mining,
and does not complete any deployment, action, acceptance, or release-gate row.
Keep every such row explicitly incomplete until its own independent gate is
met.

The repository requires Node `>=22.5.0`. The local product test boundary uses
exact Node `v22.23.1`; this is not a live-runner, release, or performance
approval.

On a blank machine, keep the stages separate:

1. Install only the repository dependencies.

   ```sh
   npm ci
   ```

2. In the separate private custody/preparation environment, create a new local
   bundle from already prepared beta material. The release ID must be the one
   pinned by `pins/v2-beta-product-offline-r3.pin.json`.

   ```sh
   npm run beta:offline:pack -- \
     <private-runtime-dir> \
     <private-historical-ceremony-dir> \
     <private-native-prover-dir> \
     <new-private-bundle-dir> \
     <pinned-release-id>
   ```

3. On the blank machine, perform the explicit one-time pinned installation
   before any public pool command. Record the JSON receipt and elapsed time in
   a separate installation report. Its time and result are not action evidence
   and must not be folded into a pool-create, deposit, withdrawal, or live-run
   acceptance record.

   ```sh
   install -d -m 700 <private-product-data-dir>
   npm run beta:offline:install -- \
     <private-offline-bundle-dir> \
     <private-product-data-dir>
   ```

4. Only after that successful pinned installation, invoke the literal public
   CLI. After the hash-pinned bootstrap has produced the pool `instanceId`, a fresh
   pool create performs exactly one measured deterministic fixed-width instance
   specialization and then exactly one receipt-bound linked-cache load. Its
   required event order is `instance-specialization`, then
   `linked-runtime-cache-load`; cold runtime build, compiler child spawn, and
   full runtime verification are forbidden. A cache-hit or restart create has
   exactly one `linked-runtime-cache-load` and zero specializations. Neither
   path may rebuild, regenerate, or replace any artifact.

   ```sh
   ./node_modules/.bin/shieldkit pool create \
     --data-home <private-product-data-dir> \
     --funding-wallet <absolute-canonical-private-wallet-path> \
     --funding-utxo <64-lowercase-hex-txid:vout>
   ```

   This is the only new-pool funding route described here. It requires an
   already user-owned Chipnet UTXO, never a sponsor or faucet. The wallet path
   must name an owner-private canonical 0600 wallet JSON file; its private key
   is never accepted on argv. The exact outpoint is authenticated as unspent,
   tokenless, and locked to that wallet before use. The product copies the
   wallet into its private recovery store before signing, while public results
   and evidence exclude the path and private material. `--funding-txid` is not
   a new-create workflow and is retained only for existing local recovery
   compatibility.

   A returned `accepted-zero-conf-beta-unqualified` result means BCHN
   zero-conf admission, exact readback, and local commit completed. It does
   not mean confirmed, mined, production-qualified, release-qualified, or
   performance-qualified.

   The subsequent public action commands use the same already-installed data
   home. Each deposit and withdraw has exactly one receipt-bound
   `linked-runtime-cache-load`, with zero instance specializations,
   compiler/build work, or full runtime verification. A failed or missing
   installation is a blocker, not permission to rebuild, regenerate, or
   silently prepare material while handling an action.

   If a process loses the RPC response after attempting a send, ordinary
   restart/reconciliation remains read-only. Inspect the secret-free durable
   status to obtain the current one-use attempt token:

   ```sh
   ./node_modules/.bin/shieldkit recovery inspect \
     --data-home <private-product-data-dir> \
     --operation-id <operation-id>
   ```

   Only an operator who has inspected that status may request one exact-byte
   rebroadcast. It requires both the current token and an explicit
   acknowledgement; stale tokens, changed bytes, and already-visible
   transactions fail without a send:

   ```sh
   ./node_modules/.bin/shieldkit recovery rebroadcast \
     --data-home <private-product-data-dir> \
     --operation-id <operation-id> \
     --attempt-token <current-token> \
     --acknowledge-exact-rebroadcast
   ```

## Runtime-work boundary and evidence status

| Requirement | Implemented / local-test boundary | Still unproven and not qualified |
| --- | --- | --- |
| Installation | Reusable pinned artifacts are verified once and a restart-checkable receipt is persisted. | Clean-machine installation transcript and any release qualification. |
| Fresh pool create | After bootstrap has an `instanceId`, exactly one deterministic fixed-width specialization precedes exactly one linked-cache load; compiler/build/full-verification events are rejected. | Clean-clone acceptance and independent runtime-work evidence. No timing claim is made. |
| Cache-hit or restart create | Exactly one linked-cache load and zero specializations. | Clean-clone restart evidence. No timing claim is made. |
| Deposit and withdraw | Exactly one linked-cache load and zero compiler/build/full-verification/specialization events. | Clean-clone acceptance evidence. No timing claim is made. |

The npm entrypoints preserve literal arguments after `--`:

```sh
npm run beta:offline:pack -- <runtime-dir> <ceremony-dir> <native-dir> <new-bundle-dir> <pinned-release-id>
npm run beta:offline:install -- <bundle-dir> <product-data-dir>
```

This document specifies no live or performance runner invocation. Any future
live evidence remains beta-only and cannot mark an acceptance row complete
without its own independently verified qualification record.
