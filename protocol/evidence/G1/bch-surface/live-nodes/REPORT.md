# G1 local BCHN v29 Chipnet runtime probe

Observation window: 2026-07-23T13:30:00Z--2026-07-23T13:32:17Z. This is a disposable, source-built, loopback-only runtime probe. It is not a live Chipnet observation, a peer reproduction, a transaction-acceptance test, or G1 PASS evidence.

## Provenance and build

The source was cloned directly from the already-recorded official BCHN repository and release tag. `git ls-remote --tags https://github.com/bitcoin-cash-node/bitcoin-cash-node.git refs/tags/v29.0.0` returned `89a591f7c5b1fd110c0819377ad8f2647d656800`. A depth-one checkout of that tag had the same `HEAD`, tree `b5defaae9825a25a30b723df8101d06ef9607b2d`, a clean worktree, and passed `git fsck --no-dangling`.

The tag is a lightweight tag, so `git verify-tag v29.0.0` cannot provide a signed-tag result (`cannot verify a non-tag object of type commit`). This records source identity, not a signed release-binary provenance claim.

On the observed host, CMake 4.4.0, Ninja 1.13.2, GNU Make 4.4.1, g++ 16.1.1, Python 3.14.6, OpenSSL 3.6.3, libevent 2.1.13, GMP 6.3, and Boost 1.91 were available. The following no-wallet, no-UI build completed:

```
cmake -S <source> -B <build> -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_BITCOIN_WALLET=OFF -DBUILD_BITCOIN_QT=OFF \
  -DBUILD_BITCOIN_ZMQ=OFF -DBUILD_BITCOIN_SEEDER=OFF \
  -DBUILD_LIBBITCOINCONSENSUS=OFF -DENABLE_TEST=OFF -DENABLE_MAN=OFF \
  -DENABLE_QRCODE=OFF -DENABLE_NATPMP=OFF -DENABLE_UPNP=OFF \
  -DSTART_WITH_NATPMP=OFF -DSTART_WITH_UPNP=OFF
ninja -C <build> -j4 bitcoind bitcoin-cli
```

`bitcoind --version` and `bitcoin-cli --version` both reported v29.0.0-89a591f. The resulting binary digests are in [raw/binary-sha256.txt](raw/binary-sha256.txt). No downloaded executable was run.

## Isolation and safety boundary

Two processes used separate temporary datadirs, cookie authentication, distinct loopback RPC and P2P ports, no wallet binary, and no `rpcuser`/`rpcpassword`. Automatic discovery and DNS seeding were disabled; onion, NAT-PMP, and UPnP were disabled; `-blocksonly=1` made `localrelay=false`; `-persistmempool=0` avoided persistence. The sole configured peer address was a loopback address. No wallet was created, no block was mined, no private key was supplied, and no transaction was constructed, tested for acceptance, relayed, or broadcast.

The first configuration attempt safely failed before either daemon started because BCHN v29 rejects `-fixedseeds` as an invalid parameter. A second attempt demonstrated that `-bind` also reserves the default Chipnet onion port unless an explicit onion bind is supplied; node B could not bind that port. The final runs used explicit, distinct normal and onion loopback binds. Exact arguments and failure text are in [raw/startup-and-attempts.txt](raw/startup-and-attempts.txt).

## Observed runtime state

Both source-built processes started and shut down cleanly. Their RPC data show BCHN v29.0.0, chain `chip`, zero local blocks and headers, Chipnet genesis as best block, MTP `1597811185`, initial block download, and the configured May 2026 Chipnet upgrade still not mempool-activated at this empty local tip. The empty mempools reported 1 sat/B relay/minimum fees, 20 MB maximum mempool, and 223-byte data-carrier policy. Raw RPC snapshots are in [raw/](raw/).

This confirms only this locally initialized node's startup configuration. Because no chain data was imported and no external peer was contacted, its genesis-only MTP cannot establish contemporary Chipnet activation or policy.

## Peer-topology falsifier

The two processes are **not independent operators** and cannot satisfy G1.2. More narrowly, the configured loopback peer did not complete a BCH P2P version handshake. On the first attempt both nodes made outbound `-connect` attempts; on the corrected attempt node A used `-connect=0` and node B used `-connect=127.0.0.1:48543`. In both cases, the connecting node sent a version message and immediately disconnected; the accepting node logged `failed to find an eviction candidate - connection dropped (full)`. The corrected run observed zero connections and zero peer records after retries. The detailed, redacted log excerpts are [raw/peer-topology-falsifier.txt](raw/peer-topology-falsifier.txt).

No cause is inferred beyond that recorded daemon output. This is a negative topology result, not evidence of an interoperable peer or a BCH consensus/policy defect.

## Gate verdict

| Requirement | Result | Evidence boundary |
| --- | --- | --- |
| G1.1 live-node portion | **OPEN** | Local v29 startup and RPC surface were observed, but the node has only genesis and no current Chipnet chain/peer result. |
| G1.2 two independent current BCHN v29 peers | **OPEN / not attempted as a substitute** | Two processes on one host are not independent; their loopback P2P handshake also failed. |
| Transaction acceptance, relay, mining inclusion | **NOT RUN** | No transaction, UTXO, wallet, funds, or broadcast was authorized or used. |

The next admissible evidence remains two independently operated, current, synchronized BCHN v29 peers and complete exact-transaction acceptance/relay records. This probe neither changes the prior source-recorded limits nor supports a G1 pass claim.
