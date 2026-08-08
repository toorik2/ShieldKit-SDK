# Verify claims

ShieldKit treats qualification as a chain of evidence, not a label.

```text
source tests
  → real proof and transaction bytes
  → local BCH VM acceptance
  → node policy admission and exact readback
  → adversarial mutations and independent model checks
  → reproducible artifacts and explicitly closed release gates
```

A later step does not repair a missing earlier step. A component pass is not a
whole-transaction pass, a projected metric is not a measurement, and a waived
gate is not green.

## Portable checks

```bash
npm test
npm run test:clean-source
npm run check:source
npm run check:no-pf7-release
npm run qualification:beta
```

These commands cover different scopes. Read their output and evidence paths;
do not summarize all of them as “qualified.” External node, clean-host,
ceremony, audit, and long-running evidence remains separate.
`test:clean-source` intentionally requires an exact clean committed checkout;
the ordinary portable suite remains runnable while developing changes.

## Benchmarks

The primary action benchmark measures a real semantic action through exact BCHN
mempool observation. It is first-try only and retains failures:

```bash
npm run bench:action -- --help
npm run bench:action -- --design pf10 --action deposit \
  --data-home /absolute/path/to/pf10-data-home
```

Component proof/scaling work remains separate:

```bash
npm run bench:component
```

Never present a component scorecard as end-to-end preparation time. Reports must
identify the exact profile, commit, prover, host, transaction, span DAG,
acceptance observation, and cache mode. See the
[action benchmark contract](../../bench/pipeline/README.md).

## Current evidence boundaries

- PF10 is the unified CLI's only money-moving beta backend, but remains unaudited and
  `productionQualified: false`.
- PF6 has real Chipnet lifecycle, BCHN, Libauth, and LeanBCH evidence, but its
  preserved release manifest is explicitly unqualified and the Lab router is
  not portable.
- FRI-STARK has a scoped release verdict and live Chipnet evidence, but the
  independent P7 journey was waived rather than executed and its permitted
  claim remains experimental beta only.

Deep evidence is indexed under [Record](../record/README.md). Preserve exact
artifact hashes, commands, network, transaction structure, verdicts, missing
gates, and accepted risks when citing it.
