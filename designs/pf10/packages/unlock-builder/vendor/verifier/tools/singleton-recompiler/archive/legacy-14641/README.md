# Legacy 14,641-byte recompiler snapshots

Historical inputs and pre-pass source snapshots for the 14,641 -> 12,351 ->
6,361-byte singleton campaign. These files are retained as explicit provenance,
not as active tool inputs.

- `arity-14641.json`, `baseline-14641.json`, `optimized-14641.hex`: archived
  14,641-byte campaign state.
- `scheduler.pre-cse.mjs`: scheduler before the constant-CSE pass.
- `optimize.pre-regalloc.mjs`, `scheduler.pre-regalloc.mjs`: state before the
  isolated register-allocation experiment.

The active recompiler remains one directory above. New ad-hoc `*.bak` files are
ignored repository-wide; durable snapshots belong in a named archive directory.
