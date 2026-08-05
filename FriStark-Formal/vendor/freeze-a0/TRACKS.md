# Parallel implementation tracks (product repo only)

Integration branch: `feat/v2-stark-product`  
Interface contracts: `docs/protocol/v2-stark/contracts/`  
Write scope is exclusive per track; contract changes require A0 revision.

**Testing / qualification is not a track here.** All claim→evidence packs, campaigns, forge matrices, clean-host/Chipnet qualification, and terminal closure live in:

https://github.com/toorik2/ShieldKit-Assurance

| Track | Branch suggestion | Write paths |
|-------|-------------------|-------------|
| T1 pin/params | `feat/v2-stark/t1-pin` | `vendor/bch-fri-stark/`, `packages/prove/v2-stark/fri-params*` |
| T2 codecs | `feat/v2-stark/t2-codecs` | `packages/action/v2-stark/`, `crates/shieldkit-v2-stark-codec/` |
| T3 trees | `feat/v2-stark/t3-trees` | `packages/pool/v2-stark/`, action tree modules |
| T4 AIR | `feat/v2-stark/t4-air` | `packages/prove/v2-stark/air/`, vendor AIR extensions |
| T5 prove runtime | `feat/v2-stark/t5-prove` | `packages/prove/v2-stark/` workers/install |
| T6 packer | `feat/v2-stark/t6-packer` | `packages/unlock-builder/v2-stark/packer*` |
| T7 bind/state | `feat/v2-stark/t7-covenants` | `packages/unlock-builder/v2-stark/{binding,state}*` |
| T8 genesis/settle | `feat/v2-stark/t8-settle` | `packages/profile/v2-stark/`, settlement assemble |
| T9 CLI | `feat/v2-stark/t9-cli` | `packages/kit/v2-stark/`, shieldkit wiring |
| T10 recover | `feat/v2-stark/t10-recover` | `packages/recover/v2-stark/` |

Do **not** add T11–T13 (evidence harnesses, forge campaigns, soak runners) in this repository.

Merge rule: track → integration when product contracts and product behavior hold; formal qualification is Assurance’s job against a pinned commit.
