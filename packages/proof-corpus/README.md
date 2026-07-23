# Local proof corpus runner

`proof-corpus.mjs` is a fail-closed local executor for a caller-supplied
Groth16 corpus. It accepts exactly one deposit, transfer, and withdrawal input,
each paired with the two expected packet-digest limbs. It requires hashes for
the R1CS, WASM, zkey, verification key, and each input; rejects symlinks and
path changes; refuses to overwrite output; generates witnesses; checks R1CS;
proves; verifies locally; and hashes all outputs.

It never performs setup, downloads artifacts, executes a BCH transaction, or
assigns a gate verdict. The packet digest is a supplied immutable corpus value;
this runner checks the proof's exactly-two public signals against it but does
not reconstruct the BCH context or packet itself.

On Linux, each direct `snarkjs` child is sampled from `/proc/<pid>/status` at
25 ms intervals. Results record `VmHWM` when available (otherwise sampled
`VmRSS`), method, scope, and sample count. Other platforms or unavailable
procfs record a null peak rather than a substituted process-wide value.

The package test uses the pinned dependency's tiny real Groth16 fixture only to
exercise fail-closed public-arity handling. It is not full-relation, setup,
proof-corpus qualification, or G1 evidence.

The manifest is strict (all paths resolve from the runner's working directory):

```json
{
  "schema": "shield.cash/proof-corpus/v1",
  "snarkjs": {"path": "/immutable/snarkjs-cli.cjs", "sha256": "...", "version": "0.7.6"},
  "artifacts": {
    "r1cs": {"path": "/immutable/relation.r1cs", "sha256": "..."},
    "wasm": {"path": "/immutable/relation.wasm", "sha256": "..."},
    "zkey": {"path": "/immutable/relation.zkey", "sha256": "..."},
    "verificationKey": {"path": "/immutable/verification_key.json", "sha256": "..."}
  },
  "actions": [
    {"kind": "deposit", "input": {"path": "/immutable/deposit.json", "sha256": "..."}, "packetDigest": ["hi", "lo"]},
    {"kind": "transfer", "input": {"path": "/immutable/transfer.json", "sha256": "..."}, "packetDigest": ["hi", "lo"]},
    {"kind": "withdrawal", "input": {"path": "/immutable/withdrawal.json", "sha256": "..."}, "packetDigest": ["hi", "lo"]}
  ],
  "outputDirectory": "/new/empty/corpus-output"
}
```
