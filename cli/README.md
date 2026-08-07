# Profile router (Lab)

`cli/` is an experimental router for comparing pool designs. It is not the
installed `shieldkit` command and it is not a unified product surface.

Run it directly from the repository root:

```bash
node cli/scripts/shieldkit.mjs --profile pf6-a3-direct-v1 --version
node cli/scripts/shieldkit.mjs --profile fri-stark-96kb --version
```

`npm run shieldkit -- --profile …` does not route these profiles.

| Profile | State |
| --- | --- |
| `pf10` | Delegates to the Product CLI; the root command is canonical |
| `pf6-a3-direct-v1` | Lab-only; depends on maintainer-local absolute paths |
| `fri-stark-96kb` | Lab-only; depends on ignored build and evidence material |

The FRI worker must exist at the exact private path expected by the router:

```bash
cd shieldkit-fri-stark-96kb
CARGO_TARGET_DIR=.private/cargo-target cargo build --release -p shieldkit-fri-worker
```

Always pass explicit `--funding-wallet` and `--data-home` paths. The current FRI
module contains a maintainer-local wallet fallback and must not be treated as a
portable interface.

The registry is [`pool-designs.json`](./pool-designs.json). Unknown profile IDs
fail closed. `node cli/test-profile.mjs` checks routing behavior only; it is not
profile qualification or a release gate.

Read the [Lab boundary](../docs/lab/README.md) before using either profile.
