# G1 BCH execution surface observation

Observation: 2026-07-23T16:16:37+03:00. Scope: source, release, and host-inventory evidence only; no transaction was constructed, broadcast, relayed, or sent to mainnet or Chipnet. Status: G1 remains **OPEN**. This record is not G1 PASS evidence.

## Provenance tier

| Fact class | Evidence | Result |
| --- | --- | --- |
| Current BCHN release | GitHub release API: [v29.0.0](https://github.com/bitcoin-cash-node/bitcoin-cash-node/releases/tag/v29.0.0), published 2026-01-09; tag resolves to commit [89a591f7c5b1fd110c0819377ad8f2647d656800](https://github.com/bitcoin-cash-node/bitcoin-cash-node/commit/89a591f7c5b1fd110c0819377ad8f2647d656800) | documented release/source |
| Consensus and default policy | BCHN v29.0.0 source at that immutable tag | documented/source configuration |
| Locally installed node, configuration, MTP, mempool, or peer verdict | bitcoind, bitcoin-cli, bchn, bchn-cli, and Docker absent; no BCH process | no local runtime evidence |
| Independent peer reproduction | no accessible, pre-existing BCHN v29 peer | missing; no projection made |

Raw responses, commands, and SHA-256s are in [raw/](raw/). raw/SHA256SUMS indexes every fetched source response; no fetched executable was run.

## Source-recorded execution surface

The release states that v29.0.0 implements the May 15 2026 upgrade, including P2S. The independent P2S specification pin fetched at [2bcfa82b8aeb1f158398ae5532a94c8c5dcf870a](https://github.com/bitjson/bch-p2s/commit/2bcfa82b8aeb1f158398ae5532a94c8c5dcf870a) matches the BCHN implementation.

| Surface | v29.0.0 source-recorded value | Basis and qualification |
| --- | ---: | --- |
| Standard transaction serialized size | 100,000 B maximum | [policy.h:47-49](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/policy/policy.h#L47-L49); IsStandardTx rejects greater values. Node-local policy can still be configured differently. |
| Consensus transaction size | 1,000,000 B maximum | [consensus.h:12-15](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/consensus/consensus.h#L12-L15). |
| Standard unlocking bytecode after Upgrade 12 | 10,000 B maximum | [policy.cpp:82-92](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/policy/policy.cpp#L82-L92) selects MAX_SCRIPT_SIZE; the P2S specification explicitly describes standard/consensus unification. |
| P2S locking bytecode | 201 B maximum for a standard bare P2S output | [standard.h:65-83](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/standard.h#L65-L83) and [P2S spec](https://github.com/bitjson/bch-p2s/blob/2bcfa82b8aeb1f158398ae5532a94c8c5dcf870a/readme.md#locking-bytecode-length). |
| CashToken NFT commitment | 128 B consensus maximum after Upgrade 12 (40 B before) | [token.h:69-73](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/primitives/token.h#L69-L73) and [tokens.cpp:72-80](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/consensus/tokens.cpp#L72-L80). This is a consensus limit, not peer acceptance evidence. |
| Stack and element ceilings | combined stack + altstack + function table: 1,000 items; element: 10,000 B | [vm_limits.h:18-22](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/vm_limits.h#L18-L22), [vm_limits.h:29-42](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/vm_limits.h#L29-L42). Conditional/control depth is 100. |
| Operation and hash density | per input op-cost ceiling (unlockingBytes + 41) x 800; standard hash-iteration ceiling floor((unlockingBytes + 41) / 2) | [vm_limits.h:46-76](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/vm_limits.h#L46-L76). Composite cost uses base cost + 192 x hashIterations under standard flags + 26,000 x sigchecks ([script_metrics.h:36-45](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/script_metrics.h#L36-L45)). |
| Sigchecks | 3,000 per transaction consensus maximum; standard input sigcheck density is separately enforced | [consensus.h:36-42](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/consensus/consensus.h#L36-L42), [interpreter.cpp:2814-2821](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/script/interpreter.cpp#L2814-L2821). |
| Default relay floor | 1,000 sat/kB = 1 sat/B | [validation.h:67-70](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/validation.h#L67-L70), applied to serialized size in [validation.cpp:687-696](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/validation.cpp#L687-L696). minrelaytxfee, mempool pressure, and miner policy can raise effective requirements. |

At the project G2 ceilings, the source-derived margins are: 95,000/100,000 B transaction = 5%; 9,500/10,000 B unlocking bytecode = 5%; 190/201 B P2S = 5.47%; and 120/128 B commitment = 6.25%. For a 9,500 B unlocking bytecode, the per-input op-cost allowance is 7,632,800 and the standard hash-iteration allowance is 4,770. These are arithmetic consequences of pinned source, not executed measurements. The 54,739-B baseline transaction would require at least 54,739 sat at the default source fee floor; its historical 5,000-sat fee cannot establish default-fee relay.

## Activation and network configuration

The activation predicate is previous-block median-time-past (MTP) >= configured upgrade12ActivationTime, not merely wall-clock date ([activation.cpp:160-169](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/consensus/activation.cpp#L160-L169)). The v29 source configures mainnet for 2026-05-15 12:00:00 UTC (1778846400) and Chipnet for 2025-11-15 12:00:00 UTC (1763208000) ([chainparams.cpp:147-159](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/chainparams.cpp#L147-L159), [chainparams.cpp:979-992](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/89a591f7c5b1fd110c0819377ad8f2647d656800/src/chainparams.cpp#L979-L992)). Both mainnet and Chipnet set fRequireStandard = true in this source configuration. No local node supplied MTP, tip height/hash, version, startup arguments, or mempool policy, so activation and standardness were not live-confirmed.

## G1 requirements 1–2 verdict

| Requirement | Result | Exact reason |
| --- | --- | --- |
| G1.1: record current rules from primary specs and live nodes | **OPEN / not passed** | Primary release/spec/source facts are pinned, but no local node or live-node result exists. |
| G1.2: two independent current BCHN v29 peers reproduce behavior | **OPEN / not passed** | Zero accessible pre-existing peers; no substitute, simulator, downloaded binary, or public-RPC claim was used. |

### Unblocking evidence

Run two independently operated, unmodified BCHN v29 peers (one mainnet and one Chipnet evidence set as applicable) and archive: getnetworkinfo, getblockchaininfo including MTP/upgrade status, getmempoolinfo, startup arguments, testmempoolaccept / submission verdicts for the exact complete transactions, and the raw transactions/UTXOs. Verify the same P2S, token, unlocking-bytecode, transaction-size, op-cost, and fee cases on both. That work is required before this source record can contribute to a G1 pass claim.

## Follow-up: disposable local runtime probe

The initial inventory statement above remains an accurate snapshot of the host before this work. A subsequent source-identified, no-wallet BCHN v29 build started two isolated, loopback-only Chipnet processes and captured genesis-only RPC state. The processes were not independent operators, did not reach a current Chipnet tip, and did not complete their configured loopback P2P handshake. No transaction, wallet, funding, mining, external peer, or broadcast was used. The complete follow-up record is [live-nodes/](live-nodes/), and it leaves G1 **OPEN**.
