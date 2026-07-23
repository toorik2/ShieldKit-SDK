# G1 BCHN v29 public-connection runtime observation

Observation time: 2026-07-23T14:37:55Z. Status: **G1 OPEN**.

This is a defensive, read/sync-only Chipnet runtime observation. It does not
construct, test for acceptance, submit, relay, broadcast, mine, or fund a
transaction. It is not a G1 PASS claim.

## What was built and run

The disposable source tree was a depth-one checkout of BCHN `v29.0.0` at
`89a591f7c5b1fd110c0819377ad8f2647d656800` (tree
`b5defaae9825a25a30b723df8101d06ef9607b2d`). Its worktree was clean and
`git fsck --no-dangling` succeeded. A no-wallet/no-UI/no-ZMQ build produced:

| Binary | SHA-256 |
| --- | --- |
| `bitcoind` | `97b5d3a0f0af68dba06de6d13f5ac9ae3896b0384b2e7923a0644c6ed7b5064e` |
| `bitcoin-cli` | `55bc8e3f59cb8354141041940f4f1443bb863c25c1db449e295d45fa5f262f56` |

Both reported `v29.0.0-89a591f`. Two processes used separate disposable
datadirs, cookie authentication, separate loopback RPC ports, outbound-only
IPv4 P2P, `-blocksonly=1`, `-persistmempool=0`, and no wallet binary. Exact
arguments contain no credentials in [raw/runtime-arguments.txt](raw/runtime-arguments.txt).

## Read-only public P2P result

Both local nodes completed outbound public Chipnet handshakes and each reported
eight connections. Their upstream sets were not identical: node A included
`95.216.205.87:48333` and `136.49.112.63:48333`; node B included
`96.126.111.144:48333` and `23.92.24.29:48333`. They also shared several
upstreams. `getpeerinfo` observed remote subversions including BCHN `29.0.0`,
`29.0.1`, and `28.0.2`; a P2P user-agent is not independent operator or
release provenance proof.

Every peer advertised `startingheight`/`synced_headers` 315,794. At capture,
node A had only 101,413 validated blocks and node B 107,523, both with
`initialblockdownload: true`; their best-block hashes and MTPs consequently
differed. Therefore 315,794 is an observed peer-advertised/header-chain height,
not a locally validated current Chipnet tip claim. The raw RPC responses retain
the exact values.

## Policy surface relevant to the 10-input, 54,949-B baseline

The current local runtime reported `minrelaytxfee` and `mempoolminfee` of
0.00001000 BCH/kB (1 sat/B), 20 MB `maxmempool`, and 223-byte data-carrier
policy. These nodes were in IBD, so those RPC values do not establish current
peer admission for any transaction.

The pinned source record in [../REPORT.md](../REPORT.md) remains the applicable
source-level surface: 100,000-byte standard transaction size, 10,000-byte
post-Upgrade-12 unlocking bytecode, 201-byte P2S locking bytecode, and the
per-input op-cost formula `(unlocking bytes + 41) * 800`. The 54,949-byte
verifier baseline is below the source transaction ceiling, but this observation
does not execute a complete 10-input transaction or prove relay/standardness.

## Gate result

| Requirement | Result | Reason |
| --- | --- | --- |
| Source-identified BCHN v29 runtime | observed | Fresh v29.0.0 no-wallet binaries built and started. |
| Separate datadirs and distinct public upstream paths | observed | Separate local processes completed outbound handshakes with partly distinct peers. |
| Current locally validated Chipnet tip/activation | **OPEN** | Both nodes remained in IBD and below the observed header height. |
| Two independent current BCHN v29 peer reproductions | **OPEN** | Both observed local processes are one operator/host; remote P2P user agents are not controlled independent reproductions. |
| 10-input 54KB transaction policy/consensus/relay result | **NOT RUN** | No transaction construction, acceptance RPC, submission, relay, funding, or mining was authorized. |

The daemons were stopped after capture. The next gate-closing evidence requires
two independently operated synchronized BCHN v29 nodes and exact complete
transaction acceptance/relay evidence. This record deliberately does not
substitute local outbound connections, peer user-agent strings, or source
limits for that requirement.
