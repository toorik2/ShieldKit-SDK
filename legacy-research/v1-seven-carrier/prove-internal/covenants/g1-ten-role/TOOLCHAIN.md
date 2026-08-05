# G1 ten-role BCH-2026 toolchain evidence

Status: **surface prerequisite passed; settlement candidate not yet emitted.**

This package pins `@bitauth/libauth@3.1.0-next.8` and executes its
`createVirtualMachineBch2026(true)` VM. The executable test constructs a
35-byte P2SH32 lock and a 9,499-byte push-only unlocking bytecode, then proves
that the standard BCH-2026 VM accepts it. The probe's redeem script consumes
the witness and checks its exact 9,488-byte size; it contains neither
`OP_TRUE` nor verifier/covenant substitution.

The CashScript compiler required for the source template is the verifier.cash
rescheduled CashC closure: `cashc@0.14.0-next.1`, source revision
`156163853ab6a80a26993047d1b55c9ea1886cae`. It must be loaded through the
same `CASHC_ROOT=.../vendor/cashc-resched/packages/cashc` adapter pattern as
verifier.cash. Run the full compiler evidence with:
`CASHC_ROOT=/absolute/path/to/verifier.cash/vendor/cashc-resched/packages/cashc npm test`.
No registry `cashscript` package is accepted as a substitute.

The prior commit's `cashscript@0.13.2` plus `@bitauth/libauth@3.0.0` result is
recorded only as a rejected stale-toolchain candidate: it models BCH-2022
policy and cannot establish any BCH-2026 feasibility or protocol conclusion.
`13-input-context-falsifier.mjs` evaluates the actual measured ten-role verifier
locks after appending three standard P2SH32 structural inputs. It is a durable
negative result: the current locks reject the 13-input context, so they cannot
be relabelled as a settlement envelope. Run it with
`VERIFIER_CASH_ROOT=/absolute/path/to/verifier.cash npm run falsify:13input`.
This branch contains no state or binding covenant candidate.
