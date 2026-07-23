# PF7 action-digest seam corpus

Status: measured development-only verifier-role evidence experiment

Observed: 2026-07-23T17:32:42Z

Implementation commits:

- `e3db60a1c159824cab4b9c46556903569e0b3018`
- `aa7583cfde2278242fe81d57bafae96018e57976`

## Scope and verdict

The exact seven-verifier `bn254-onetx-pf7-sub62-r1` topology now has a
reproducible three-action entrypoint for the selected runtime action-digest
seam. Deposit, transfer, and withdrawal each rebuilt twice, accepted in the
normal and standard BCH-2026 VMs for verifier roles 0 through 6, stayed below
the 59,000-byte verifier-context target and 10,000-byte per-input limit, and
passed the raw-terminal and cross-action mutation batteries.

This result is **not G2**. The transaction context has ten inputs, but inputs 7
(`packet`), 8 (`state`), and 9 (`fee`) remain explicitly unevaluated structural
roles. The measured wire transactions are verifier contexts, not complete
deposit, transfer, or withdrawal settlements.

## Retained source boundary

- Base verifier.cash commit:
  `26468ae29004d2401619032de2a6ec8de269a4d6`.
- Historical seam-off reference terminal:
  `17c6b9552c48b0fc5271be626a1578fb0065df09`, tree
  `d9673df5a3f5358df6aaff9c4042a029bc26a521`.
- Action-seam terminal:
  `1d543756602edfd92081a0b58dba62d33d0aea34`, tree
  `1c1efb23e95bf51a715f8ab29f3cf698a359303d`.
- Retained patch 0008 SHA-256:
  `c40db1abc1cb54fca82c5754f985d6ede22d236f8bf1404771ae105ab438bd83`.
- Historical reference-manifest SHA-256:
  `974353ff5bfa514aa2f43d32d05a77eda3c05afb7702f87f4b11f21e3deefda0`.
- Distinct seam-manifest SHA-256:
  `10fe8728e4414db7a8b262b60a23b58d3dc2782187ab6465560a262e62dfd8c3`.
- Replaying retained patches 0001 through 0008 onto the base produced tree
  `1c1efb23e95bf51a715f8ab29f3cf698a359303d`, exactly matching the seam
  terminal tree.
- Running the unchanged seam-off entrypoint after this integration reproduced
  historical verifier-set SHA-256
  `b4d0aabcc71a1fec03026ab98e233d41f90cc4b161e313dbf62176bf9fb74ce4`.

The provenance manifest preserves the reference and seam terminals as separate
identities. Historical G1 records remain reference-terminal evidence and were
not relabeled.

## Exact ingress

| Action | Adapter SHA-256 | SCAR packet SHA-256 |
| --- | --- | --- |
| deposit | `d895e004e163ed8c07f08b0ed98d339d9e0ac22a56f6c76d00b81436bca64637` | `3b3f83ecabc740a380a2a2b7ca6ee6cd08b01ccea4dd983e069ec37006fdafda` |
| transfer | `7bcfe5b5f0d2a0c6edc72871f30fd2bcdb2dfc6a3aa5734a9a4c7e0aa2673687` | `db6eb2e27eb60f95ddf4d74414b6598e5562e9870489f9ced0794325e8e384ad` |
| withdrawal | `7adc81d6365bfffdb98c2ae82f144a998e78b2fba215b84f784262ef31a9eb0c` | `3c13e43dfeea20e18a81bef417fb90be56030686fe39e914f420631b00937887` |

Each packet is the canonical 752-byte `SCAR` encoding. Its single SHA-256 is
split into exact unsigned BE-u128 public limbs and must equal the two adapter
public inputs before any build begins.

The on-chain ABI under test is:

- input 7: exactly `PUSHDATA2(752) || SCAR[752]`, with no suffix;
- genesis first push: exactly
  `PUSHDATA2(480) || projectionContext[448] || SHA256(SCAR)[32]`;
- terminal: single-SHA256 of the exact input-7 payload and raw comparison to
  the genesis digest bytes.

## Measurements

| Action | Context wire | All-bytes score | Maximum unlock | Normal VM | Standard VM | Raw terminal | Seam red team |
| --- | ---: | ---: | ---: | --- | --- | --- | --- |
| deposit | 55,311 B | 55,631 B | 9,277 B | 7/7 | 7/7 | 18/18 reject | 17/17 reject |
| transfer | 55,376 B | 55,696 B | 9,277 B | 7/7 | 7/7 | 18/18 reject | 17/17 reject |
| withdrawal | 55,247 B | 55,567 B | 9,213 B | 7/7 | 7/7 | 18/18 reject | 17/17 reject |

All ten source locking bytecodes were byte-identical across the three actions.
The complete source-set SHA-256 is
`16e57f25f98afd2ecd2e16720970e17a96ca2c4c57e0006c1eea0e1e5b3d0f01`.

The 17-case seam battery contains 13 local packet/carrier/public-input/role
mutations plus two packet substitutions and two genesis substitutions from the
other action builds. Every battery ran with all ten inputs in transaction
context while evaluating only the seven verifier roles.

## Reproducibility

Command:

```text
node packages/pf7-verifier-generator/seam-cli.mjs ABSOLUTE_CONFIG.json
```

The strict configuration requires three action-ordered SHA-pinned adapters,
three action-ordered SHA-pinned packets, exact clean verifier/CashC/LeanBCH
checkouts, a nonexistent output destination, and a direct short scratch
directory. Each action is rebuilt twice. `result.json`, `inputs_dump.json`,
`c7_candidate_srcouts.hex`, `c7_candidate_tx.hex`, and `standardness.json`
must be byte-identical between the two builds.

Three complete invocations, including one after splitting historical and seam
provenance, produced byte-identical copies of all eight published files. The
canonical corpus SHA-256 was
`9222ae981216b53b601268a86bb3200503522780207a38051a973baf2ee833c5`.

Published file hashes:

| File | SHA-256 |
| --- | --- |
| `manifest.json` | `aece30e2b34763607f3c1e129fe6ca6fc50b89450efaaeb6110e351b3af34ce0` |
| `deposit-raw-terminal-attacks.json` | `feed49ae00eaf34ac6fbdcef9b1a4d596a0f7177d9bec8e543287a4f2d23bfb0` |
| `deposit-seam-redteam.json` | `f4d7b11cda262fac3d65e7db23e1beda9df1c453711e0c949480a59fe444c1c3` |
| `transfer-raw-terminal-attacks.json` | `3b337a937e45da52e26847817a2a931347e272c2c397cab5b2bbd7ed7c89d6d4` |
| `transfer-seam-redteam.json` | `ec16fac03d0cde08437fe3c21cdd8dc5f6d3b683ef069b1fda28204385be75ea` |
| `withdrawal-raw-terminal-attacks.json` | `1899f0678bf209e229dfcb04749308ab219f4faeedee2647ea35a21b12481fd2` |
| `withdrawal-seam-redteam.json` | `84bd7f0f992ca184e0b685e7268f52a20cc7f44f68e241322ed3e1e5d9401d3b` |

## Limitations

- Inputs 7 through 9 are not settlement covenants and are not evaluated.
- The measured context has placeholder structural roles and is not a complete
  value-, token-, state-, fee-, output-, or signature-bound transaction.
- No P2S binding/state covenant, BCHN standardness, peer relay, miner
  inclusion, Chipnet flow, LeanBCH cross-check of the new seam, ceremony, or
  release claim is established.
- Installed dependency roots are lock-bound and version-checked but their full
  installed closure is not byte-authenticated.
- The generated corpus files remain external reproducibility outputs. This
  repository retains the source generator, exact patch chain, hashes,
  measurements, and limitations; it does not promote those outputs into a G2
  artifact.
