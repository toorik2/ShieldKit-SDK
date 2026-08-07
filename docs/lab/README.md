# Lab

The Lab shelf contains executable research that is not part of the supported
root PF10 surface.

| ID | Design | Evidence | Why it remains Lab |
| --- | --- | --- | --- |
| `pf6-a3-direct-v1` | Groth16 · 6 verifier roles · 9-input actions | Real Chipnet lifecycle and cross-checks | Router contains maintainer-absolute imports; frozen release is explicitly unqualified; conditional withdrawal layout risk |
| `fri-stark-96kb` | Goldilocks FRI-STARK · 17 roles · 18-input actions | Scoped release and Chipnet lifecycle evidence | Requires ignored/private build material; maintainer defaults remain; independent P7 journey was waived |

Read [PF6](./pf6.md) or [FRI-STARK](./fri.md) for the exact boundary.

## Experimental router

The source router is invoked directly:

```bash
node cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 --version
node cli/scripts/shieldkit.mjs --profile fri-stark-96kb --version
```

It is not the root package binary. This does **not** work:

```bash
npm run shieldkit -- --profile pf6-a3-direct-v1 --help
```

The router is not a portable release surface yet:

- PF6 imports PF10 and `snarkjs` through maintainer-absolute paths;
- FRI-STARK expects a private worker build, materialized local artifacts, and a
  maintainer-local wallet fallback.

Always supply explicit wallet and data-home paths in Lab work. Treat successful
local execution as scoped evidence, not a support or maturity claim. The
[router README](https://github.com/toorik2/ShieldKit-SDK/blob/main/cli/README.md)
is a code-adjacent Lab reference.
