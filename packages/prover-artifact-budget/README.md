# Prover artifact budget packager

This read-only-input packager measures the two artifacts required by the current
local prover interface: full `final.zkey` and witness-generator `.wasm`. It
requires caller path, version, and SHA-256 pins for zstd and SHA-256 pins for
both direct regular-file inputs. Compression uses deterministic single-thread
zstd settings (`-T1 -19 --no-check`), stages private outputs transactionally,
then streams decompression to verify the original hash and size.

The compressed total is assessed against the fixed G0 512 MiB ceiling. A PASS
is only an artifact-size result. It does not initialize setup, use a full setup
in tests, establish browser/Android viability, execute BCH, or qualify G1.

For a pinned JSON manifest, run `node cli.mjs --input manifest.json`. The CLI
accepts no identity or budget overrides, rejects duplicate JSON object names,
resolves permitted relative paths against the manifest, and writes canonical
JSON only after successful packaging.
