# Gate evidence

Evidence records conform to `policy/evidence.schema.json` and live under a
directory named for their gate and candidate. Raw artifacts remain immutable;
new observations create new records rather than overwriting prior results.

G1 now contains source, reproduction, toolchain, and arithmetic records. Each
verdict applies only to its stated claim: a passing verifier reproduction or
registry observation is not a G1 pass. Run:

```sh
npm --prefix packages/conformance test
```

to validate every machine-readable evidence record and the bytes and SHA-256 of
its repository-local artifacts.
