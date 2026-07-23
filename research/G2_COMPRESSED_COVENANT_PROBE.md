# G2 compressed covenant and state-trampoline probe

Status: measured BCH-2026 feasibility result; **not G2 evidence or a complete
settlement candidate**

Candidate context: SCCT v1, ten ordered inputs, current development-only PF7
packet seam at verifier.cash commit
`1d543756602edfd92081a0b58dba62d33d0aea34`.

## Result

BCH-2026 loops and functions reduce direct SCCT reconstruction substantially,
but the strongest standalone bare-P2S form is still 201 bytes: 11 bytes above
the project's 190-byte gate. A two-lock direct decomposition can place a
189-byte reconstruction core beside a 181-byte state-continuity lock, but that
core does not have room to pin the PF7 set, profile/instance, and complete
settlement policy. It is therefore not a sound G2 binding candidate.

The viable measured architecture is instead a small state P2S trampoline:

1. input 7 remains exactly one `PUSHDATA2(752) || SCAR[752]` packet;
2. input 8 contains exactly one canonical push of a static settlement helper;
3. the 88-byte state P2S lock hashes the complete input-8 unlock, pins the exact
   input-7 lock, self-preserves at output 0, defines the authenticated helper,
   and invokes it; and
4. the helper performs SCCT reconstruction and the larger static/settlement
   checks without being subject to the 190-byte locking-bytecode limit.

There is no lock-hash cycle:

```
PF7/profile/category -> packet-only input-7 lock -> helper
    -> state trampoline lock -> state UTXO and successor output
```

The helper does not embed the state lock. The state lock hashes the canonical
helper unlock and compares output 0 with `OP_ACTIVEBYTECODE`.

## Exact measurements

Pinned runtime: `@bitauth/libauth@3.1.0-next.8`,
`createVirtualMachineBch2026(false|true)`.

| Form | Lock bytes | Unlock bytes | Standard VM | Status |
| --- | ---: | ---: | --- | --- |
| Prior literal unrolled SCCT probe | 842 | 755 | pass | executable upper bound |
| Loop SCCT, explicit token branches | 244 | 755 | pass | over 190 |
| Loop plus shared token function, standalone | 201 | 755 | pass | 11 over project gate |
| Coupled reconstruction core | 189 | 755 | pass | incomplete policy pinning |
| Coupled direct state-continuity lock | 181 | 0 | pass | conditional on incomplete core |
| Packet-only input-7 lock | 20 | 755 | pass | selected trampoline component |
| State trampoline lock | 88 | 1,069 | pass | selected trampoline component |
| Authenticated state/settlement helper | n/a | 1,066 helper bytes plus 3-byte PUSHDATA2 | pass | selected trampoline component |
| Transparent fee P2PKH | 25 | 100 | structure checked; signature execution outside this slice | selected topology |

The packet-only lock plus state trampoline plus transparent-fee lock/unlocks
have this exact 2,057-byte input-side lock/unlock subtotal:

```
20 + 755 + 88 + 1069 + 25 + 100 = 2057
```

The maximum unlocking bytecode among these three roles is 1,069 bytes, far
below 10,000. The helper unlock includes every byte: a 3-byte
`PUSHDATA2(1066)` header followed by all 1,066 helper bytes.

Standard-VM operation costs:

| Action | packet-only input 7 | state trampoline plus helper |
| --- | ---: | ---: |
| deposit | 4,628 | 258,085 |
| transfer | 4,628 | 258,037 |
| withdrawal | 4,628 | 273,283 |

The package also serializes an isolated ten-input fixture at 2,594, 2,594, and
2,604 bytes respectively. Those fixtures deliberately omit the large PF7
unlocking programs and are not complete-transaction measurements.

### Corrected 59 KB recalculation

The previous common helper cap of 3,317 bytes assumed a 57-byte state wrapper.
The measured wrapper is 88 bytes, so the common cap tightens by exactly 31
bytes to 3,286.

Using the same fixed-envelope calculation and the measured PF7 seam wires:

| Action | PF7 structural wire | Corrected helper-unlock cap | Recalculated wire with 1,069-byte helper unlock | Remaining to 59,000 |
| --- | ---: | ---: | ---: | ---: |
| deposit | 55,311 | 3,351 | 56,718 | 2,282 |
| transfer | 55,376 | 3,286 | 56,783 | 2,217 |
| withdrawal | 55,247 | 3,415 | 56,654 | 2,346 |

The fixed non-helper offset is recalculated from 307 to 338 bytes. These are
exact arithmetic against the measured structural wires and the previously
specified fixed-envelope offset. They are **not** encoded, executed,
complete-settlement measurements and cannot pass G2.

## What the helper executes

The helper:

- reconstructs SCCT v1 byte-for-byte for all ten inputs and the exact
  two/three-output action layouts;
- uses non-palindromic outpoints to prove that
  `OP_OUTPOINTTXHASH` is committed in serialized wire order;
- requires version 2, locktime 0, ten inputs, sequence 0 at every input, and
  action-dependent output count;
- authenticates exact packet encoding and the SCCT digest at packet bytes
  720 through 751;
- pins all seven current PF7 P2SH32 source locks by exact SHA-256;
- pins packet profile and instance identities;
- pins the state category independently of capability and requires a mutable,
  zero-amount, 80-byte state NFT at input 8 and output 0;
- requires category, commitment, and amount introspection to be empty on every
  other input and output;
- binds pre/post NFT commitments to packet state, preserves the fixed
  denomination reserve delta, and checks boundary/withdrawal values and the
  withdrawal script hash;
- requires input 7 and input 9 to spend the same preparation parent at exact
  vouts 0 and 1;
- requires input 9 to have an exact 100-byte Schnorr/P2PKH unlock with sighash
  byte `0x41`;
- derives the input-9 P2PKH lock from its exact 33-byte pubkey and requires the
  canonical change output to use the same P2PKH lock; and
- fixes input-7 value to `B + D` for deposit and `B` otherwise.

The refreshed-context adversarial cases change the actual transaction and then
recompute SCCT, so rejection cannot be attributed merely to a stale context
digest. They reject:

- substituted PF7 source lock;
- wrong preparation parent or vouts;
- wrong fee sighash, fee lock, or change key;
- altered state commitment or state value;
- the state category inserted into another input as fungible-only, immutable
  NFT, or minting NFT; and
- the state category inserted into another output as a mutable NFT.

The last four token cases compare/enforce category independently; they do not
mistake `category || capability` for category identity.

## Delegation boundary

The selected split has only these intended delegations:

- The trampoline delegates helper semantics only after hashing the entire
  canonical helper unlock and requiring exactly one initial stack item.
- The helper relies on the exact PF7 terminal/public-input seam to prove the
  relation over the authenticated SCAR. This package does not execute the PF7
  proof inputs.
- Schnorr validity remains enforced by executing input 9's exact P2PKH source
  lock. This slice checks its structure, sighash byte, pubkey-derived source
  lock, and same-key change but does not produce a valid signature.
- Authentic genesis establishes the unique category/outpoint. The helper
  prevents that category from appearing anywhere else in a transition and the
  trampoline preserves the exact successor lock.

There is no delegation to an indexer, relayer, hosted prover, artifact server,
administrator, pause key, or post-genesis authority.

## Remaining falsifiers before integration

This probe does not yet:

- splice the helper and fee signature into the real PF7 deposit, transfer, and
  withdrawal transactions;
- execute all ten real inputs together;
- measure encoded complete wire/all-bytes score for those transactions;
- execute the fee signature;
- prove BCHN standard relay or Chipnet inclusion;
- run the full substitution corpus against real proofs; or
- cross-check the helper in LeanBCH.

The current exact fixture locks are development-only probe inputs with their
source result/input hashes recorded in
`bch/g2-compressed-covenants/pf7-seam-v0-locks.json`. They are not a verifier
bundle or profile authority.

The trampoline result is a GO for integration and a NO-GO for any G2,
59-kilobyte complete-transaction, relay, or Chipnet claim until those remaining
tests pass.
