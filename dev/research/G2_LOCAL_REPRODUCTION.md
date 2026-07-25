# Local G2-adjacent reproduction boundary

Run the deterministic local runner from a clean worktree after installing the
pinned dependencies in each listed package:

```sh
for package in packages/settlement-context packages/settlement-transaction packages/preparation-transaction bch/g2-compressed-covenants; do
  (cd "$package" && TMPDIR=/home/toorik/Projects/ZK-Proofs/.codex-artifacts/tmp npm ci --no-audit --no-fund)
done
TMPDIR=/home/toorik/Projects/ZK-Proofs/.codex-artifacts/tmp node conformance/reproduce-local-g2.mjs
```

The JSON output records the checked commit, dirty state, Node version, and the
source hash of each package manifest. Its `tier` is deliberately narrow:

- `structural` covers canonical SCCT and complete-transaction construction plus
  fail-closed mutations.
- `libauth-bch2026-vm` covers only the local Libauth BCH-2026 VM executions
  named in the report.

It does not run LeanBCH, BCHN, network relay, mining, or Chipnet. It also does
not establish real PF7 proof execution. Therefore a passing report is neither
G1 PASS nor G2 evidence; it is a reproducible local diagnostic boundary.
