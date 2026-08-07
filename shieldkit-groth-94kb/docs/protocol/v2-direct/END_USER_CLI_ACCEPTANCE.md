# ShieldKit V2 End-User CLI Acceptance Contract

**Status:** implementation tracker; no row is a qualification claim until its
listed real evidence exists and independently re-verifies from a clean worktree.

## Product boundary

Deliver an explicitly unqualified V2 beta Chipnet lane with these user commands:

```text
shieldkit pool create \
  --funding-wallet <absolute-canonical-private-wallet-path> \
  --funding-utxo <64-lowercase-hex-txid:vout>
shieldkit pool create --resume
shieldkit deposit
shieldkit withdraw --to <bchtest-p2pkh-external-not-fee-wallet>
shieldkit recovery inspect --operation-id <operation-id>
shieldkit recovery rebroadcast --operation-id <operation-id> \
  --attempt-token <current-token> --acknowledge-exact-rebroadcast
```

`pool create` is one user invocation, not a sponsor, faucet, or external-funder
workflow. The supplied wallet path names a normalized absolute canonical private
wallet JSON file; its wallet data must be owner-private (0600) and its parent
private. The supplied outpoint is authenticated from exact raw transaction bytes
and public zero-conf UTXO observations: it must currently be unspent, tokenless, and locked
to that wallet's Chipnet P2PKH key. Private keys/WIFs are never CLI arguments.
The wallet is copied into the product's private recovery custody before bootstrap
signing; neither source path nor private material appears in results or evidence.
`pool create --resume` is accepted only when that data home already contains the
exact durable create operation; it accepts no new wallet or outpoint and never
turns into a second send or a fresh pool.

Pool create locally builds and verifies the source/genesis package, then uses two
pinned public Chipnet Fulcrum/Electrum TLS providers: the primary broadcasts once,
and the distinct attestation provider reads exact raw bytes and the successor UTXO.
The product accepts no RPC URL, provider override, username, password, API key,
or SSH option. Users need only their local funding wallet; network access is
anonymous public Chipnet access (the public providers can still observe the
client IP address and requested transactions/outpoints).
Deposit and withdraw additionally perform local witness/proof construction and verification.
Public-provider zero-conf readback is the only completion state; commands never wait for
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
| P-01 | Exact commands and recoverable local UX | Literal one-invocation user-funded create parsing/dispatch, stable JSON/human result validation, secret-free recovery inspection, and acknowledgement-plus-current-token exact rebroadcast have local tests. Legacy `--funding-txid` input is rejected by the end-user CLI. | Clean-machine transcripts for create, deposit, withdraw, inspect, and rebroadcast using real state. |
| P-02 | Warm end-to-end performance gates | The live benchmark and independent bundle verifier require both command-total and action-total `p50 <= 5000 ms` and `p95 <= 10000 ms` over at least twenty real warm samples per action kind. The separate fresh pool-create campaign applies the same percentile limits to literal CLI duration. Cold install/runtime construction is measured separately and is never hidden inside a warm sample. | Clean committed real-Chipnet evidence must meet every threshold; no latency claim is made until that bundle independently re-verifies. Passing these gates does not promote the explicitly unqualified beta. |
| P-03 | No action-time runtime rebuild | Runtime-work observers and local tests require fresh create to specialize once then load once, cache-hit create to load once, and deposit/withdraw to load once; forbidden compiler/build/full-verification work is rejected. | Instrumented live commands, process/file/network tracing, and cache-hit proof for all three commands. |
| P-04 | Verify artifacts once, then load a durable verified cache | The installer verifies reusable pinned artifacts once; receipt-bound linked-cache loading and local tamper/restart boundaries exist. | Install transcript, signed/hash-pinned manifest, cache receipt, tamper rejection, crash recovery, and warm identity checks from a clean environment. |
| P-05 | Pinned native multicore prover | The pinned installer, receipt-bound worker, and strict local consumers require exact host-core use plus fail-closed CPU/RSS/cgroup telemetry. | Reproducible clean-host build receipt, binary hash, proving-key/circuit binding, proof equivalence, and actual all-core telemetry from every real action. |
| P-06 | Private local-only witnesses and secrets | Private product stores and the contained native worker locally enforce trusted paths, private modes, cleanup, and secret-free public evidence. | Clean-host trace proving no remote prover/witness transport or secret-bearing file, process argument, log, or evidence across success and injected crashes. |
| P-07 | Persistent incremental trees | The beta product lifecycle uses the persistent note/indexed-nullifier engine and locally tests transactional updates, restart, and root/path differentials without full-history reconstruction. | Real deposit/withdraw evidence binding the persisted paths, counts, roots, and database/WAL growth. |
| P-08 | Fresh recoverable change wallets | The product lifecycle stages fresh private change material durably before signing and retains attached/orphan-recoverable watch state in local tests. | Real-action crash injection proving funds remain recoverable at every boundary. |
| P-09 | Crash-safe exactly-once delivery | The beta SQLite delivery journal uses a durable send attempt, token-bound CAS, read-only reconciliation, no automatic resend, and explicit acknowledged exact-byte recovery; the generic coordinator has the same fail-closed boundary. | Real node ambiguity/restart and concurrent-process evidence; no live exactly-once claim is made. |
| P-10 | Route-labelled public-provider admission | The action lifecycle durably claims immutable bytes and uses zero action-path `testmempoolaccept` calls. Fresh success is exactly one primary `blockchain.transaction.broadcast`, one independent `blockchain.transaction.get`, and one independent `blockchain.utxo.get_info` read. Indeterminate/restart/rebroadcast paths publish one of six exact logical routes; evidence separately records literal provider method names and counts. Local all-input VM execution remains mandatory. | TLS/genesis, route-counted live evidence including zero preflight and no automatic resend. Public-provider visibility is not a BCHN-internal instruction or direct-node claim. |
| P-11 | Exact independent zero-conf readback | Product create/deposit/withdraw paths locally require exact raw bytes plus output-0 state-NFT category/capability/commitment/value before success. The primary broadcast endpoint and attestation endpoint are distinct; provider token metadata is cross-checked but raw bytes are authoritative. Lab-only direct BCHN qualification, if run, is separately labelled and outside the end-user transport claim. | Real independent public-provider raw/UTXO readback evidence for every qualified beta action. |
| P-12 | Full local transaction verification | The product path requires exact all-input execution under the pinned BCH VM profile before admission and binds the resulting transaction/source outputs into evidence. | Real-action all-input verdicts and resource measurements under the unchanged 10,000-byte unlock and 100,000-byte transaction caps. |
| P-13 | Explicit beta isolation | Public product dispatch and all locally validated results require `confirmed:false`, `mined:false`, `productionQualified:false`; beta state remains separate from the confirmed store. | Clean-machine transcript and state inspection proving no beta-to-confirmed-state crossover. |
| P-14 | Capacity 100,000 instance | A clean-checkout exploratory run created immutable capacity 100,000 instance `66e2089a069f339a2fbaa8572016c7abb6084370285aebd96bf8d63b311e03c3`; exact source/genesis IDs, runtime pins, and dual-provider readback are recorded in `V2_BETA_LIVE_5X5_2026-08-02.md`. | Re-run from one final committed candidate and pass the independent evidence-bundle verifier; the exploratory run is not qualification. |
| P-15 | Real 5-by-5 story | The same exploratory Chipnet instance completed five real deposits and five real withdrawals with final counters `noteCount=5`, `nullifierCount=5`, `liveCount=0`; every delivery journal record has `attemptCount=1`. | Re-run through the final semantic-evidence harness from one final committed candidate. The public-provider latency exceeded P-02, so no product qualification is claimed. |
| P-16 | Clean install and immutable dependency graph | No clean-install result is claimed. | Fresh isolated checkout, tracked lockfile, `npm ci`, pinned native toolchain/artifacts, and no network fetch during warm actions. |
| P-17 | Recovery and adversarial coverage | Local product tests cover interrupted install, cache/runtime/readback/state/transaction tampering, stale attempts, explicit recovery, crash boundaries, and concurrent send claims. | Clean-clone corpus execution plus real node ambiguity/restart evidence. |
| P-18 | Mandatory CI | The tracked workflow includes mandatory source/audit, portable, beta-product security, type, campaign, Rust, covenant, verifier-lane, and formal jobs under pinned Node 22.23.1 where Node 22 is required. | A clean committed candidate and mandatory remote-green run; CI is not claimed green before that evidence exists. |

## Timing and evidence schema

Every real command emits a secret-free record bound to the operation ID, exact
artifact hashes, and transaction ID. It records:

- cold/warm classification and cache receipt hash;
- authenticated state/funding read, tree path construction, witness calculation,
  proof generation, proof verification, transaction construction/signing, Libauth
  VM evaluation, public-provider admission, raw/state readback, SQLite commit, and total time;
- transaction bytes, each unlocking-bytecode size, fee satoshis and satoshis/byte;
- proof-system identity, worker/thread count, CPU utilization, peak RSS, exact
  cgroup memory/swap limits and OOM counters;
- exact literal public-provider method counts, logical route counts, and terminal backend identity;
- proof verification result, each input VM verdict and resource measurements;
- exact raw-transaction SHA-256, state outpoint, category, capability, commitment,
  and value derived from exact raw bytes and checked against provider UTXO visibility;
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
