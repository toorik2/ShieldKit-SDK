# Direct SCCT reconstruction result

Status: measured feasibility probe; not a covenant candidate and not a G2
result.

The executable probe constructs the complete 1,352-byte deposit/transfer SCCT
v1 preimage with BCH-2026 introspection, applies one SHA-256, and compares the
result with the final 32 bytes of the exactly canonical input-7 unlocking
bytecode `4d f0 02 || SCAR[752]`. Its source locks for inputs 0 through 6 are
the exact PF7 v0 locks from the frozen replay artifact. It runs in libauth
`createVirtualMachineBch2026(true)`.

| Measurement | Result |
| --- | ---: |
| locking bytecode | 842 bytes |
| project P2S gate | 190 bytes |
| excess over gate | 652 bytes |
| input-7 unlocking bytecode | 755 bytes |
| SCCT preimage | 1,352 bytes |
| VM operation cost | 120,844 |
| lock plus input-7 unlock | 1,597 bytes |

The test first returns the constructed preimage and byte-compares it with an
independent JavaScript SCCT encoder. It then executes the hash comparison and
rejects mutations of an outpoint hash/index, sequence, source value, PF7 and
binding source locks, state category/commitment, non-state token, output
value/lock/token, non-canonical packet push, and packet context suffix.

The 842-byte result is an **executable unrolled upper bound**, not a proof that
all loop/function-compressed direct reconstructions exceed 190 bytes. Therefore
this result does not support a claim that the 190-byte target is impossible.
It does establish that a literal, independently auditable reconstruction with
all ten source entries and two output entries is 4.43 times the project limit
before adding action-invariant profile/instance and verifier-set authentication,
packet field parsing, proof coupling, exact state successor/reserve checks,
fee/change rules, or withdrawal handling.

The fixture deliberately pins one state category and 80-byte commitment so that
the exact CashTokens prefix hash can be audited. A real action-invariant binding
script must instead derive the state commitment from SCAR and bind the profile,
instance, verifier set, state covenant, and action-specific outputs. Those
missing requirements make this a floor for one direct strategy, not a valid
alternative implementation.

No sound smaller architecture is identified under the frozen map and
packet-only input-7 invariant. Moving executable helpers to the unlock is
forbidden by that invariant; adding a second commitment-verification input or
changing the SCCT relation/encoding changes the frozen G2 candidate. A
loop-compressed reconstruction remains an open experiment, not a permitted
assumption or a passing result.
