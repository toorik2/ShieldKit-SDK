import Recompiler

/-- Verified-recompiler spike: proofs are checked at build time (`lake build`).
    If this binary runs, every rewrite theorem in the `Recompiler` library type-checked. -/
def main : IO Unit :=
  IO.println "Recompiler stack-VM rewrite rules: all theorems checked by Lean (see lake build)."
