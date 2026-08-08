# Benchmarks

Model level cost and size analysis for the verifier. The scripts are read only: they compute and print, they do not
touch the verifier.

For authoritative numbers, meaning real consensus bytes and op cost measured on the actual BCH-2026 VM, use the
libauth harness described in the main README. The scripts here are the model that those measurements confirm.

## Running them

Run from the repository root, with the root and `apps/` on the Python path so the scripts find `cashvm`,
`structures_*` and the verifier modules.

Linux and macOS:

```
PYTHONPATH=".:apps" python benchmarks/cost_report_native.py
PYTHONPATH=".:apps" python benchmarks/proof_size_native.py
PYTHONPATH=".:apps" python benchmarks/standard_tx_sweep.py
```

Windows (PowerShell), note the semicolon separator:

```
$env:PYTHONPATH=".;apps"; python benchmarks\cost_report_native.py
```

They have no third party dependencies and require no network access.

## What each one measures

- `cost_report_native.py`: the full on chain op cost of the hash-STARK verifier for the native CT-AIR
  (Poseidon2 over Goldilocks, no elliptic curves), modelling what the script VM has to execute.
- `proof_size_native.py`: byte accounting for the proof, broken down by component (Merkle siblings, FRI cosets,
  openings) and checked against a size budget.
- `standard_tx_sweep.py`: sweeps the parameter space (blowup, queries, grinding, fold) and reports which
  configurations reach at least 100 bit security while still fitting a standard BCH transaction, under the real
  consensus limits (P2SH32 required, 10000 bytes per input scriptSig, 100000 bytes per transaction).

`cost_report.py`, `cost_report_full.py` and `proof_size.py` are the shared building blocks the three scripts above
import, and are not meant to be run directly.

## Model versus measurement

The model is calibrated against real measurements, but it remains a model. The verifier's test suite runs the
covenants on real libauth and reports exact bytes and op cost per input; where the two disagree, the libauth number
is authoritative. The internal `cashvm.py` op cost counter is useful as a fast differential oracle during
development, but it overcounts byte operations such as SPLIT and BIN2NUM and should not be quoted as a deploy cost.
