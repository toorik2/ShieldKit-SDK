# G2 binding P2S direct-reconstruction probe

This is a measured feasibility probe, not a settlement covenant or a G2
candidate. It uses the exact selected PF7 v0 source locking bytecodes and a
real BCH-2026 standard VM program. The program reconstructs the full 1,352
byte deposit/transfer `SCCT` preimage from transaction introspection, hashes it
once, and compares it to `SCAR[720..751]` supplied by the canonical 752-byte
input-7 push.

The probe intentionally does **not** claim to enforce the action relation,
proof verification, packet fields other than the context suffix, profile
binding, state successor, reserve, fee/change, or output topology. Those are
additional required semantics, so its measured locking-bytecode size is an
executable lower floor only for a direct in-script SCCT reconstruction strategy.

Run `npm test` in this directory. The test prints/records the exact bytecode
length, disassembly, operation cost, and rejection matrix.
