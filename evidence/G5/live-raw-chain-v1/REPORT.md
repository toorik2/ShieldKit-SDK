# Live canonical-chain recovery probe

Status: **PASS for the bounded single-node transport and CTOR-independent
historical state-chain extractor; not G5, V2, or release evidence.**

At `2026-07-24T01:21:19.794Z`, the read-only adapter queried the
project-controlled, synchronized, non-pruned BCHN v29 Chipnet node. It pinned
block `315828`
(`000000003b666ee97a9937306969092d6e9ef7884a79d7e7610b5f36393613a0`)
and authenticated a stable 31-block canonical snapshot through height
`315859`
(`000000001ce4637c753dac6efa0132148189b0b7cb4f0706035cad9743188195`).

The concatenated raw-block SHA-256 is
`31f3be88173f000de087619c0248add44db19e6fa35b935705a1c309cd70cb5e`.
Outpoint-graph reconstruction, independent of BCH canonical transaction order,
recovered the historical V1 state chain:

1. deposit
   `56563c2c3a81857216853b53293c0cedc8f4baaa15b2430553be57a0d57a6cf1`
2. transfer
   `ffa7fe6cb706546368a4f2dd14243a5c73a7d0dcc90d570f1238592387baa38b`
3. withdrawal
   `14f6363290f73fdd7e723491110c458de8efa8e90b7e7dfa6675381e1175c2e0`

The immutable public-result file is
`/home/toorik/Projects/ZK-Proofs/.codex-artifacts/chipnet-live-flow-019f8ed4/raw-chain-live-probe-v1.json`
(16,720 bytes, SHA-256
`e53f0cc4488f177b4604a3f328afbe44c5b33b0bb7a6e61254c6be9dec93b9fe`).

This probe uses one self-hosted node and validates a stable canonical RPC
snapshot, raw headers/blocks, chainwork, merkle roots, and profile-bound state
ancestry. It does not independently implement BCH consensus or difficulty
rules, execute settlement scripts, compare two independent nodes, exercise a
live reorg, or qualify seed recovery. The V1 recovery relation is invalidated;
all recovery and live-chain evidence must be regenerated for the corrected V2
profile.
