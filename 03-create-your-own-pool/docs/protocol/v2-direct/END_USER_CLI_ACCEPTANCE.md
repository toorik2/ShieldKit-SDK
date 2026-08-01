# ShieldKit V2 End-User CLI Acceptance Contract

**Status:** implementation tracker; no row is a qualification claim until its
listed real evidence exists and independently re-verifies from a clean worktree.

## Product boundary

Deliver an explicitly unqualified V2 beta Chipnet lane with these user commands:

```text
shieldkit pool create \
  --funding-wallet <absolute-canonical-private-wallet-path> \
  --funding-utxo <64-lowercase-hex-txid:vout>
shieldkit deposit
shieldkit withdraw
shieldkit recovery inspect --operation-id <operation-id>
shieldkit recovery rebroadcast --operation-id <operation-id> \
  --attempt-token <current-token> --acknowledge-exact-rebroadcast
```

`pool create` is one user invocation, not a sponsor, faucet, or external-funder
workflow. The supplied wallet path names a normalized absolute canonical private
wallet JSON file; its wallet data must be owner-private (0600) and its parent
private. The supplied outpoint is authenticated exactly with BCHN raw-transaction
and `gettxout` observations: it must currently be unspent, tokenless, and locked
to that wallet's Chipnet P2PKH key. Private keys/WIFs are never CLI arguments.
The wallet is copied into the product's private recovery custody before bootstrap
signing; neither source path nor private material appears in results or evidence.

Pool create locally builds and verifies the source/genesis package, then uses the
bounded BCHN admission/readback and atomic local commit path. Deposit and
withdraw additionally perform local witness/proof construction and verification.
BCHN zero-conf acceptance is the only completion state; commands never wait for
a block confirmation or call a result confirmed or mined. All resulting claims
remain explicitly beta and unqualified.

Installation verifies reusable pinned artifacts once; it does not create a
pool-specific runtime. After bootstrap has produced the fresh pool `instanceId`,
`pool create` performs exactly one measured deterministic fixed-width instance
specialization, followed by exactly one linked-cache load. A cache-hit or restart
create performs only that one linked-cache load. Every `deposit` and `withdraw`
performs exactly one linked-cache load and zero compiler/build/full-runtime-
verification/instance-specialization work. These are implemented runtime-work
contracts and local-test targets, not evidence of a live action, clean-clone
acceptance, or performance qualification.

The existing confirmed V2 lane remains separate. Nothing in this work may weaken
its authenticated-history or confirmation-depth rules, promote beta artifacts, or
claim ceremony, audit, production, or release qualification.

## Non-negotiable acceptance matrix

`Implemented / local-tested` identifies a current code boundary or local test
target only. It is not a live, clean-clone, performance, or qualification pass;
no row below is qualified.

| ID | Requirement | Implemented / local-tested | Evidence still missing |
|---|---|---|---|
| P-01 | Exact commands and recoverable local UX | Literal one-invocation user-funded create parsing/dispatch, stable JSON/human result validation, secret-free recovery inspection, and acknowledgement-plus-current-token exact rebroadcast have local tests. Legacy `--funding-txid` is not a new-create route. | Clean-machine transcripts for create, deposit, withdraw, inspect, and rebroadcast using real state. |
| P-02 | No performance qualification | No public latency, throughput, p50, p95, or live-performance claim is made by this beta contract. | Any future benchmark must be separately specified, independently reproduced, and must not relabel this beta as qualified. |
| P-03 | No action-time runtime rebuild | Runtime-work observers and local tests require fresh create to specialize once then load once, cache-hit create to load once, and deposit/withdraw to load once; forbidden compiler/build/full-verification work is rejected. | Instrumented live commands, process/file/network tracing, and cache-hit proof for all three commands. |
| P-04 | Verify artifacts once, then load a durable verified cache | The installer verifies reusable pinned artifacts once; receipt-bound linked-cache loading and local tamper/restart boundaries exist. | Install transcript, signed/hash-pinned manifest, cache receipt, tamper rejection, crash recovery, and warm identity checks from a clean environment. |
| P-05 | Pinned native multicore prover | The pinned installer, receipt-bound worker, and strict local consumers require exact host-core use plus fail-closed CPU/RSS/cgroup telemetry. | Reproducible clean-host build receipt, binary hash, proving-key/circuit binding, proof equivalence, and actual all-core telemetry from every real action. |
| P-06 | Private local-only witnesses and secrets | Private product stores and the contained native worker locally enforce trusted paths, private modes, cleanup, and secret-free public evidence. | Clean-host trace proving no remote prover/witness transport or secret-bearing file, process argument, log, or evidence across success and injected crashes. |
| P-07 | Persistent incremental trees | The beta product lifecycle uses the persistent note/indexed-nullifier engine and locally tests transactional updates, restart, and root/path differentials without full-history reconstruction. | Real deposit/withdraw evidence binding the persisted paths, counts, roots, and database/WAL growth. |
| P-08 | Fresh recoverable change wallets | The product lifecycle stages fresh private change material durably before signing and retains attached/orphan-recoverable watch state in local tests. | Real-action crash injection proving funds remain recoverable at every boundary. |
| P-09 | Crash-safe exactly-once delivery | The beta SQLite delivery journal uses a durable send attempt, token-bound CAS, read-only reconciliation, no automatic resend, and explicit acknowledged exact-byte recovery; the generic coordinator has the same fail-closed boundary. | Real node ambiguity/restart and concurrent-process evidence; no live exactly-once claim is made. |
| P-10 | Single-pass node admission | The product lifecycle uses one mandatory gate that locally enforces one `testmempoolaccept` and at most one `sendrawtransaction` attempt for immutable bytes. | RPC-counted live evidence showing no retry loop or duplicate local/node VM execution. |
| P-11 | Exact zero-conf readback | Product create/deposit/withdraw paths locally require exact raw bytes plus output-0 state-NFT category/capability/commitment/value before success. | Real BCHN readback evidence for every qualified action. |
| P-12 | Full local transaction verification | The product path requires exact all-input execution under the pinned BCH VM profile before admission and binds the resulting transaction/source outputs into evidence. | Real-action all-input verdicts and resource measurements under the unchanged 10,000-byte unlock and 100,000-byte transaction caps. |
| P-13 | Explicit beta isolation | Public product dispatch and all locally validated results require `confirmed:false`, `mined:false`, `productionQualified:false`; beta state remains separate from the confirmed store. | Clean-machine transcript and state inspection proving no beta-to-confirmed-state crossover. |
| P-14 | Capacity 100,000 instance | No product qualification run is claimed. | Fresh Chipnet genesis commits immutable `maximumLiveNotes=100000`; exact genesis tx/readback and descriptor/runtime bindings recorded. |
| P-15 | Real 5-by-5 story | No product CLI qualification run is claimed. | Five real deposits followed by five real withdrawals, all zero-conf, with fresh private material and no skipped gate or synthetic result. |
| P-16 | Clean install and immutable dependency graph | No clean-install result is claimed. | Fresh isolated checkout, tracked lockfile, `npm ci`, pinned native toolchain/artifacts, and no network fetch during warm actions. |
| P-17 | Recovery and adversarial coverage | Local product tests cover interrupted install, cache/runtime/readback/state/transaction tampering, stale attempts, explicit recovery, crash boundaries, and concurrent send claims. | Clean-clone corpus execution plus real node ambiguity/restart evidence. |
| P-18 | Mandatory CI | The tracked workflow includes mandatory source/audit, portable, beta-product security, type, campaign, Rust, covenant, verifier-lane, and formal jobs under pinned Node 22.23.1 where Node 22 is required. | A clean committed candidate and mandatory remote-green run; CI is not claimed green before that evidence exists. |

## Timing and evidence schema

Every real command emits a secret-free record bound to the operation ID, exact
artifact hashes, and transaction ID. It records:

- cold/warm classification and cache receipt hash;
- authenticated state/funding read, tree path construction, witness calculation,
  proof generation, proof verification, transaction construction/signing, Libauth
  VM evaluation, BCHN admission, raw/state readback, SQLite commit, and total time;
- transaction bytes, each unlocking-bytecode size, fee satoshis and satoshis/byte;
- proof-system identity, worker/thread count, CPU utilization, peak RSS, exact
  cgroup memory/swap limits and OOM counters;
- exact BCHN RPC method count and terminal backend identity;
- proof verification result, each input VM verdict and resource measurements;
- exact raw-transaction SHA-256, state outpoint, category, capability, commitment,
  and value returned by BCHN;
- store/overlay database and WAL sizes plus materialized note/nullifier counts.

Evidence contains no note secrets, spend/view keys, private membership paths,
funding private keys, change private keys, raw circuit inputs, witnesses, or private
action records.

## Qualification sequence

1. Independently verify all source, lockfile, manifest, ceremony-beta, circuit,
   proving-key, verification-key, covenant, and native-prover pins.
2. Install once and create the durable verified cache; prove cache tampering and
   interrupted installation fail closed and recover cleanly.
3. From a clean checkout and empty data directory, create a fresh explicitly
   unqualified 100,000-note Chipnet beta pool and accept/read it back zero-conf.
4. Run five real deposits and five real withdrawals with no confirmation polling,
   recording the complete evidence above.
5. Re-verify the evidence bundle independently, replay canonical history, run all
   recovery/adversarial tests, and run mandatory CI from a clean worktree.
6. Pass only if every applicable row is green. Otherwise ship
   the measurements and blockers without weakening the contract.
