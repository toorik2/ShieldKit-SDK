# G2 settlement enforcement split candidate

Status: executable candidate; not frozen and not deployment material

## Exact roles

The settlement transaction has ten ordered inputs:

| Index | Role |
| ---: | --- |
| 0–4 | PF7 executor roles |
| 5 | PF7 genesis role |
| 6 | PF7 terminal role |
| 7 | action-packet binding and preparation carrier |
| 8 | unique mutable state NFT, reserve, and authenticated helper |
| 9 | transparent P2PKH fee authorization |

The PF7 roles retain the measured two-public-input verifier and exact
`PUSHDATA2(752) || SCAR` packet seam. Input 7 carries the same packet. No role
accepts caller-supplied public scalars or a second packet.

## State trampoline and helper

Input 8's bare-P2S lock is an instance-specific trampoline no larger than 190
bytes. It:

1. accepts exactly one minimally encoded helper push;
2. checks the helper's exact length and SHA-256 against its constructor
   constant;
3. requires output 0 locking bytecode to equal `OP_ACTIVEBYTECODE`; and
4. executes the authenticated helper with `OP_DEFINE` and `OP_INVOKE`.

The action-invariant helper is part of the profile's authenticated verifier set.
With the current measured 88-byte trampoline, the conservative common
input-8-unlock cap is 3,286 bytes while the complete transaction remains at
most 59,000 bytes. This cap must be recomputed from the integrated transaction
if the trampoline or any other serialized field changes. The 65,000-byte
contingency is not an allocation.

The helper contains the profile ID, instance ID, state category, reserve cap,
state and binding carrier values, exact input-7 lock, and the complete
settlement logic. It validates:

- transaction version 2, locktime 0, ten inputs, zero sequences, and exact
  action-dependent output count;
- one canonical 752-byte packet at input 7 with no suffix;
- the exact profile, instance, action, and immutable state fields;
- source and successor state values `S + pre.reserve` and
  `S + post.reserve`;
- exact 80-byte `SHST` commitments, mutable capability, zero fungible amount,
  and unchanged state category;
- deposit, transfer, and withdrawal reserve/value/output equations;
- every non-state input and output is tokenless;
- no other input or output uses the state category, comparing the 32-byte
  category independently of capability and fungible amount;
- exact state-lock continuity and exact input-7 binding lock;
- one complete canonical `SCCT` v1 reconstruction from transaction
  introspection; and
- `SHA256(SCCT)` equals packet bytes 720–751.

The helper must reject any field mutation even if another valid proof is
supplied. Splitting unrelated context fields across independent scripts is not
equivalent to one monolithic context commitment.

## Binding and dependency direction

Input 7's bare-P2S lock is no larger than 190 bytes. It authenticates the exact
input-8/output-0 state NFT handoff and the preparation pair below. The state
helper pins the exact input-7 lock. Input 7 never embeds or hashes the state
lock, avoiding a script-hash fixed point.

Construction order is:

```
circuit and PF7 verifier locks
  -> profile ID
  -> instance and state category
  -> input-7 binding lock
  -> state helper
  -> input-8 trampoline
  -> genesis
```

No post-genesis key, pause, rescue, sequencer, upgrade, or service authority is
introduced.

## Permissionless preparation authorization

The preparation transaction creates:

- output 0: the exact input-7 binding carrier, including the 0.1 BCH
  contribution only for deposit; and
- output 1: a canonical P2PKH fee UTXO controlled by the preparing wallet.

Settlement inputs 7 and 9 must spend those sibling outputs from the same parent
transaction at vouts 0 and 1. Input 9 must contain an exact 100-byte canonical
compressed-pubkey Schnorr P2PKH unlock whose sighash byte is `0x41`
(`ALL|FORKID`). The canonical change output preserves the exact fee-input
P2PKH lock. Input 9's own P2PKH execution verifies the signature.

The signature protects a prepared carrier from theft; it never substitutes for
the proof-to-packet-to-`SCCT` transaction binding.

## Candidate falsifiers

This split is rejected or redesigned if any of these occurs:

- trampoline lock above 190 bytes;
- input-8 helper unlock above the current 3,286-byte derived cap;
- any unlock above 10,000 bytes;
- any complete action above 59,000 serialized bytes;
- honest standard BCH-2026 VM rejection or operation-limit failure;
- accepted helper mutation, non-minimal helper push, state-lock substitution,
  packet suffix, role substitution, or context mutation;
- accepted duplicate state category in any token form;
- spend of a prepared binding carrier without the sibling fee key;
- accepted wrong preparation parent/vout, fee lock, sighash, or change key; or
- action-specific PF7 source locks or a construction hash cycle.

The measured 57-byte trampoline mechanism and earlier 842-byte context and
833-byte state formulations are feasibility inputs only. They are not an
integrated G2 result or a lower-bound proof.
