# G2 bare-P2S state covenant feasibility: FAIL

This is a bounded, pre-G2 measurement. It is not a proof verifier, binding
covenant, complete settlement transaction, relay result, Chipnet result, or G2
PASS claim.

## Frozen semantics measured

`ShieldStateV1.cash` implements the requested static state lock:

- v2, locktime 0, exactly ten inputs, active input 8;
- exact self lock on input 8 and successor output 0;
- exact constructor-pinned input-7 binding source lock;
- one mutable state NFT of the constructor-pinned category, zero fungible
  amount, and no duplicate state-category token in the other nine inputs or
  non-state outputs;
- exact canonical input-7 unlock: `4d f0 02 || SCAR[752]`;
- SCAR magic/version/Chipnet/profile/instance checks for pre and post state;
- exact `SHST` pre/post NFT commitments from SCAR state commitments and raw
  action sequences;
- exact output cardinality, reserve deltas, denomination, and withdrawal
  script hash for deposit, transfer, and withdrawal; and
- a static profile carrier base `S=1,000` satoshis, so input state value is
  `S + preReserve` and successor value is `S + postReserve`.

The base is required to avoid a zero-satoshi state UTXO at empty genesis and
after a withdrawal. It is a profile/instance constant. The existing SCCT v1
encoder already commits each input source and output value, so no SCCT format
change is needed; its exact action contexts must use these two equations.

The 76-byte input-8 argument is a fixed, non-action density pad and is
consumed by the function. It contains no packet, digest, proof, outpoint, or
secret. Its only effect is to give the highly introspective lock enough
operation-density budget for the VM test.

## Exact measurement

Pinned compiler: cashc `0.14.0-next.1`, `optimizeFor: size`.

| Item | Bytes |
| --- | ---: |
| Executable contract body | 729 |
| Instantiated bare-P2S lock, with a one-byte binding lock test fixture | 833 |
| BCH P2S maximum | 190 |
| Excess, executable body | 539 |
| Excess, instantiated test lock | 643 |

The instantiated size includes 104 bytes of canonical constructor-argument
pushes for the test fixture: a one-byte binding lock, three 32-byte
identifiers, and `S=1,000`. A real binding source lock can only increase it.

`npm run compile` emits byte-exact executable hex and CashScript's deterministic
disassembly. `npm test` executes the instantiated full semantics against
real-reference deposit, transfer, and withdrawal SCAR packets in both normal
and standard libauth BCH-2026 VMs. The adversarial test rejects packet,
unlocking, category, capability, commitment, value, output-lock, binding-lock,
and active-index substitutions.

## Verdict and boundary

The full frozen semantics are **not viable as one <=190-byte bare-P2S state
lock in this measured CashScript formulation**. This is a feasibility failure,
not permission to omit checks or to call a subset a G2 candidate.

No protocol check was moved outside the measured source. The only deliberately
outside scope is validation of input 7's binding semantics and input 6's real
proof verification: those are separate inputs whose whole-transaction success
is required by BCH, and neither is available in this isolated state-covenant
slice. Their absence makes this a pre-G2 falsifier, not a settlement claim.

This result does not prove a hand-optimized BCH assembly lower bound. Any
alternative must retain every frozen check above, provide byte-exact source and
disassembly, and rerun the same normal/standard/adversarial VM matrix before it
can replace this failure record.
