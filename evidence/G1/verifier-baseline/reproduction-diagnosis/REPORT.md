# Reproduction diagnosis: pinned bootstrap succeeds

This is a verifier-build reproducibility result, not a G1 decision. The
candidate remains research-only with fixed verifier/deployment binding; this
does not support ceremony, production, relay, release, or G1 PASS claims.

## Result

Two independent disposable rebuilds of verifier.cash commit
`26468ae29004d2401619032de2a6ec8de269a4d6` completed the unmodified candidate
command and full runner corpus:

| Runtime | Run | `gateOk` | Score/wire | Primary result / tx hashes |
| --- | --- | --- | --- | --- |
| Node v25.9.0 | `g1-diag-current-pinnedlean-deps` | true | 54,949 / 54,739 | `98436d…affca` / `6b19b2…0570a` |
| Node v20.20.2 (available LTS) | `g1-diag-node20-pinneddeps` | true | 54,949 / 54,739 | `98436d…affca` / `6b19b2…0570a` |

Both also reproduced source-output, boundary-parts, op-margin, off-subgroup,
and deterministic red-team-vector hashes listed in `hashes.txt`. The red-team
summary has 6/6 honest accepts, 18/18 extra-valid accepts, 6/6 worst-case
accepts, and 6/6 rejects for each off-curve mutation family.

## Exact failure and cause

The earlier incomplete bootstrap had root `npm ci` and harness dependencies,
but omitted the declared `build/` dependency closure. Its unmodified candidate
command failed before a result with:

```text
Error: ProjectivePoint expected
  at aprjpoint (.../@noble/curves/src/abstract/weierstrass.ts:602:42)
  at Point.add (.../weierstrass.ts:805:7)
  at rowFunction (build/chunked/pairing/gen_vkx_ecip.mjs:128:53)
  at ecipData (lanes/bn254-onetx/src/c7/build.ts:1119:14)
  at buildGenesisMerged (lanes/bn254-onetx/src/c7/build.ts:1829:14)
```

`c7/build.ts` resolves Noble through `createRequire(build/package.json)`, while
the ECIP module resolves it from `build/chunked/pairing`. With the build closure
installed, both resolve exactly the same PNPM instance:

```text
build/node_modules/.pnpm/@noble+curves@2.2.0/node_modules/@noble/curves/bn254.js
```

The root npm closure is separately `@noble/curves@1.9.7`. The failure is an
installation-closure/class-identity mismatch, not a BCH VM, scorer, candidate,
or proof-verification failure. Installing `build/` from its committed
`pnpm-lock.yaml` is the smallest repair; no source patch is required.

Two additional bootstrap prerequisites were independently exposed:

- the committed vendor CashC tree omits `packages/cashc/dist`; build its
  `1c707c1dbf87396b30ba5e0704b1db44475ce893` source with Yarn classic and its
  committed `yarn.lock` in an isolated vendor staging tree;
- set `LEANBCH_ROOT` to a disposable archive of the candidate-pinned
  `51201015fdaef4562debf2a2b1cab4013a45e8b4`, then run
  `npm ci --no-audit --no-fund` in its `optimizer/` directory.

The early missing artifacts and the Noble mismatch are bootstrap provenance
gaps. They should be pinned/documented before treating this candidate as a
reproducible baseline, even though the complete pinned environment above
rebuilds it exactly.

## Minimal successful environment

Use Node v20.20.2 or v25.9.0; both were measured. Install root with its
`package-lock.json`, then both `harness/` and `build/` with their committed
PNPM locks. Use the candidate-pinned LeanBCH archive, not a dirty live checkout.
Build the vendored CashC package before invoking the documented command. Full
commands and resulting hashes are in the sibling files.
