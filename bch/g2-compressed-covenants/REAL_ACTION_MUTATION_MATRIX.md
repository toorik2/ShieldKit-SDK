# Real complete-action mutation matrix

Run the fixture-bound full ten-input Libauth BCH-2026 standard-VM matrix:

```sh
node real-action-mutation-matrix.mjs /absolute/artifact/output
```

It executes all ten inputs for each real Chipnet deposit, transfer, and
withdrawal fixture. Negative families cover unlocks, source roles, serialized
outpoints, all SCAR packet field ranges, successor outputs, state NFT fields,
fee fields, and input ordering. The resulting JSON records every evaluated
input and rejects a report with a false accept or unexecuted mutation.

This is local VM evidence. It does not assert BCHN relay, miner inclusion, a
new Groth16 proof for each mutation, or a 256-proof corpus.
