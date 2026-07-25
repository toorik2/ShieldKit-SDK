# Commands

All paths below are local, read-only or pre-genesis qualification paths.

```bash
# Strict v1 adapter conversion, then real K=9 PF7 transaction and attacks.
node packages/snarkjs-adapter/snarkjs-groth16-adapter.mjs <v1-adapter-input.json> <input-sha256>
LEANBCH_ROOT=/tmp/shield-leanbch-51201015 C7_SHIELD_ADAPTER_FILE=<v1-adapter.json> C7_SHIELD_ADAPTER_SHA256=ece0c4f3406c8395fde96f22dc0c1b534d17eda71d793626f00b9dcf1aed4f8e DP=1 STRIPED=1 STRIPE_BOUNDARY=1 DIRECT_FINALIZE_STATE=1 STRICT_DEPLOYMENT=1 PUBLIC_BENCH_CONTEXT=1 KWIN=9 STRIPED_FRAGS=7 SW=32 CDNW=1 CDWIDTH=34 UNW=16 WDWIDTH=32 NITS=1 RESCHEDULE=on SZ_ALLAFF=1 L17SEL=1 SEAMNARROW=1 KSPEC=1 SIBLING_READ=1 FIXED_WDAT=1 DYN_PACK=1 DERIVE_MODE=1 DRIVER_PACK_DERIVED=1 DRIVER_WINDOW_DERIVED=1 harness/node_modules/.bin/tsx lanes/bn254-onetx/src/c7/build.ts
harness/node_modules/.bin/tsx lanes/bn254-onetx/src/c7/measure-terminal-raw-attacks.ts <run/tmp> <run/tmp/raw-attacks-v1.json>

# Repeat the full build with transfer and withdrawal adapters, then compare every
# lockingBytecode in each inputs_dump.json (not unlocks or candidate transactions).
node <lock-comparison-script> <deposit/tmp/inputs_dump.json> <transfer/tmp/inputs_dump.json> <withdrawal/tmp/inputs_dump.json>

# Immutable external development-only bundles and read-only replacement check.
node packages/setup-profile-bridge/cli.mjs --input /tmp/shield-g1-v1-replacement-019f8ed4/bridge-v0.json
node packages/setup-profile-bridge/cli.mjs --input /tmp/shield-g1-v1-replacement-019f8ed4/bridge-v1.json
node packages/core/compare-development-profiles.mjs --left <v0-bundle> --right <v1-bundle>
```

The K=13 composed attempt separately failed at cashc compilation with
`UnusedVariableError: Unused variable ec0`; it is recorded as a failed closure,
not used as v1 evidence.
