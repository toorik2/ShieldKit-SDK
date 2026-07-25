# Browser local prover

This adapter performs one selected local Chromium `snarkjs.groth16.fullProve`
per manifest only. The manifest still carries all three canonical action inputs
and selects exactly one of `deposit`, `transfer`, or `withdrawal`; this keeps
each proof run individually measurable. Its
manifest binds Chipnet, profile, and instance atomically, then obtains the
WASM, zkey, and verification key from the authenticated verifier-profile
bundle. It pins Chromium, Playwright Core, the browser snarkjs bundle, CLI, and
each input by SHA-256; it serves them only on loopback and disables Chromium
background networking. Browser outputs are independently verified by the
pinned local snarkjs CLI. `witnessMemoryPages` is mandatory and pins the
initial witness-calculator WASM allocation (one page is 64 KiB); it prevents
snarkjs's 32,767-page default reservation from masquerading as usable browser
memory. It does not alter the relation, proving key, or verifier.

The reported RSS is a diagnostic sum of the Chromium root process plus live
descendants, not the Node harness or loopback server; it double-counts shared
pages and is not memory-budget evidence. Use cgroup-v2 `memory.current` and
`memory.peak` with `MemoryMax=2GiB` (and no swap) for an authoritative memory
result. A run is feasibility telemetry only. G4 still requires a fixed
desktop-browser fixture, 60-second p95, and 2-GiB process-memory
qualification; no Android or browser result is implied by unit tests.

The current frozen-profile result is an explicit failure, with the rationale
and artifact pointers in [BUDGET_GATE.md](BUDGET_GATE.md). It does not authorize
a budget, relation, verifier, or profile change.
