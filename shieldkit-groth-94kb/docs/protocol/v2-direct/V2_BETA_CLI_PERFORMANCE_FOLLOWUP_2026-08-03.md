# V2 Beta CLI Performance Follow-up

**Date:** 2026-08-03

**Code candidate:** `5c07859` (`perf(v2): send through the fastest pinned provider`)

**Verdict:** the real end-user commands work safely against public Chipnet,
but the preserved PF10 protocol is not performance-qualified. The mandatory
`p50 <= 5,000 ms` and `p95 <= 10,000 ms` gates have not been met.

**Claims:** explicitly unqualified beta, zero confirmation, not mined, not
production qualified. The existing single-contributor beta ceremony and its
pinned artifacts were reused unchanged; no ceremony was rerun.

This follow-up extends
`V2_BETA_LIVE_5X5_2026-08-02.md`. It records bounded optimization probes after
the original real 100,000-capacity, five-deposit/five-withdrawal story. The
probes span several commits and are therefore diagnostic evidence, not a
single-candidate performance qualification corpus.

## Public network route

The product uses three pinned public Chipnet TLS providers. It requires no SSH,
private RPC endpoint, or RPC credential. One provider receives exactly one
broadcast. All three are then read-only observers, and any two must return the
exact raw transaction and exact live successor state before local commit.
There is no automatic failover broadcast.

The final provider order is:

1. `chipnet.bch.ninja:50002` - sender and observer;
2. `chipnet.imaginary.cash:50002` - observer;
3. `blackie.c3-soft.com:64002` - observer.

## Funding inventory boundary

The added command

```text
shieldkit pool add-funding --funding-utxo <txid:vout>
```

authenticates one exact tokenless output by raw-transaction and live-UTXO
readback, proves that the retained local wallet owns it, and atomically adds it
to the funding inventory. It neither scans a wallet nor broadcasts a
transaction, and no private key appears on the command line.

The rolling covenant requires the action-funding transaction to be independent
of the current state transaction. Therefore, the change output created by one
action cannot fund the immediately following action: it shares that action's
transaction ID with the new state tip. It becomes eligible after another action
advances the tip. Continuous use requires at least two independent fee UTXOs
that can alternate. An attempted immediate reuse failed safely before any send;
after an independent retained output was admitted, the withdrawal succeeded.

## Optimization probe transactions

All six rows are real zero-conf Chipnet actions. Every proof verified locally,
every transaction passed all 13 Libauth BCH-2026 input evaluations, every row
used a single broadcast attempt, and each accepted result was atomically
committed after exact public readback.

| Kind | Transaction ID | Bytes | Fee sats | Proof generation ms | Admission ms | Action ms | CLI ms | Process wall ms |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| deposit | `3d1c90d1ee03377c0aa2a365d6e27bf195b5de653fb488a8d713a9926afc9810` | 97,852 | 97,852 | 1,556.700 | 4,242.177 | 9,720.406 | 10,083.863 | 11,313 |
| withdrawal | `ea3ac0e8177c12cf18ac3fc06ba9e4e2506c625f8c80c6396eac4a726033c401` | 97,886 | 97,886 | 1,597.900 | 4,616.154 | 10,473.059 | 10,854.250 | 12,149 |
| deposit | `79c35683cc2a4cc7f320299630bf8f9ae0828085607ed1800de55757b0f61d1b` | 97,852 | 97,852 | 1,553.300 | 4,688.080 | 10,067.149 | 10,440.821 | 11,968 |
| withdrawal | `7d8c5bceada7fb9578fcbeebe0e75bdc799a1a68048f8b202acbd4263bc0ab63` | 97,886 | 97,886 | 1,589.859 | 4,195.431 | 9,660.065 | 10,114.601 | 11,355 |
| deposit | `49c5385dc8071073e434bc5c7c30264081c255fbf2eca9f5ccccf0102cb1cf99` | 97,852 | 97,852 | 1,520.008 | 4,182.604 | 9,372.175 | 9,806.267 | 11,186 |
| withdrawal | `0a1f452921f363a603fbd5127a62ab0611bef5fe1ce578ec00af5e9566dca8b4` | 97,886 | 97,886 | 1,580.060 | 4,139.182 | 9,588.601 | 10,027.618 | 11,323 |

The last deposit and withdrawal are the exact `5c07859` candidate. Their
runtime work counters each record one linked-cache load and zero cold runtime
builds, full runtime verifications, compiler child spawns, or instance
specializations. Each native proof requested, observed, and actively used all
20 reference-machine cores.

The final withdrawal additionally records:

- proof total: 2,493.479 ms;
- witness calculation: 531.378 ms;
- witness assembly: 940.853 ms;
- state read: 1,197.987 ms;
- funding read: 1,536.151 ms;
- signing plus all-input VM: 218.694 ms;
- atomic commit: 66.387 ms;
- exact raw-transaction SHA-256:
  `b4ec53a4e0d334898976b9c2cf01c95fd47909d35ce1333b2dcb064575876450`.

State and funding reads overlap and must not be summed. Admission includes the
one send plus the exact two-provider successor quorum.

## Current durable state

The latest operation is `accepted_zero_conf`, its local wallet commit is
complete, and its delivery record is `locally_reconciled` with one attempt and
`rpc-accepted` submission. The pool now has:

- `noteCount=8`;
- `nullifierCount=8`;
- `liveCount=0`;
- `maximumLiveNotes=100000`;
- action sequence 16;
- current tip
  `0a1f452921f363a603fbd5127a62ab0611bef5fe1ce578ec00af5e9566dca8b4:0`.

No block confirmation was requested or awaited.

## Regression evidence

The exact candidate passed:

- source policy: 523 syntax-checked files and only the two designated raw-send
  modules;
- V2 TypeScript check: green;
- mandatory beta-product security suite: 29 files, 224/224 tests, zero skips;
- complete portable suite: 201 files, 1,502/1,502 tests, zero skips;
- transport-focused suite: 28/28 tests.

Both domain suites used test-runner parallelism 20. Earlier unchanged gates for
the same line remain recorded in the base report and implementation evidence;
this follow-up does not relabel those results as a fresh release qualification.

## Why the performance gate remains red

The final provider reorder and two-of-three observation reduced admission to
about 4.14-4.18 seconds, but it did not change the dominant structure: a nearly
98 kB PF10 transaction must still be validated and propagated, after the local
proof, witness assembly, signing, and all-input VM work. The final observed
action totals were 9.37 and 9.59 seconds, while process wall times were 11.19
and 11.32 seconds.

Running the mandatory 20-deposit and 20-withdrawal campaign cannot turn these
observations into the required 5-second median; it would only spend more
Chipnet outputs to establish a percentile for a candidate already far from the
target. The current candidate therefore remains a functional, security-tested,
explicitly unqualified beta. Meeting the original latency requirement requires
a materially smaller/faster verifier and settlement topology, or a changed
acceptance contract. Neither change is allowed by the objective's requirement
to preserve the exact circuit and covenant, so no production or performance
qualification claim is made.
