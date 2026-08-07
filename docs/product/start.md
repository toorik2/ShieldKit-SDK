# Start

PF10 is the only backend allowed to move funds through the unified CLI. It is an
unaudited, Chipnet-only beta and is not production-qualified.

## Inspect

Use Node.js 22.23.1, the version pinned in CI. The package accepts Node.js 22.5.0
or newer.

```bash
npm ci
npm run shieldkit -- --version
npm run shieldkit -- design list
npm run shieldkit -- --design pf10 design doctor
```

These commands do not broadcast. `design doctor` checks local wiring; it is not
an instance or chain-health report.

## Use an existing PF10 instance

The old PF10 product stores private state under a `--data-home`. The unified CLI
uses a separate immutable home that binds the exact profile, instance, network,
and accepted genesis descriptor. Import is read-only and leaves the old data
home untouched:

```bash
npm run shieldkit -- pool import \
  --from-data-home /absolute/path/legacy-pf10-data-home \
  --home /absolute/path/shieldkit-home \
  --design pf10
```

Import succeeds only for a committed, zero-conf-accepted PF10 deployment that
the product APIs can validate. A session file or evidence directory is not
migration authority.

## Create a new PF10 instance

Creation still uses the PF10 product data-home during the compatibility window.
You need an owner-private funding wallet and an owned, unspent, tokenless
Chipnet P2PKH UTXO.

The following command broadcasts Chipnet transactions:

```bash
npm run shieldkit -- --design pf10 pool create \
  --data-home /absolute/path/new-pf10-data-home \
  --funding-wallet /absolute/path/funding-wallet.json \
  --funding-utxo <64-lowercase-hex-txid>:<vout>
```

After the command reports the exact accepted-zero-conf contract, import that
data home into a new unified home using the previous command. A new `--home` is
never silently reinterpreted as the legacy data-home. `pool create`, including
`--resume`, is refused whenever a bound home is present; creation and resume
must name the exact legacy `--data-home` explicitly.

## Operate

Actions require the validated home. Direct `--data-home` actions are rejected by
the unified grammar.

```bash
npm run shieldkit -- --home /absolute/path/shieldkit-home action deposit
npm run shieldkit -- --home /absolute/path/shieldkit-home action transfer --note <owned-note-id>
npm run shieldkit -- --home /absolute/path/shieldkit-home action withdraw \
  --note <owned-note-id> \
  --to <fresh-bchtest-p2pkh-address>
```

The PF10 backend owns proof generation, whole-transaction VM validation,
durability, one-send admission, exact readback, and local commit. The unified
wrapper re-derives the imported deployment authority before every delegation
and reports success only when the backend returns its complete beta acceptance,
route-count, Chipnet-genesis, and state-readback contract.

## Recover ambiguous delivery

Inspection is read-only. Rebroadcast requires the exact recorded operation, the
current compare-and-swap token, and explicit acknowledgement:

```bash
npm run shieldkit -- --home /absolute/path/shieldkit-home operation inspect \
  --operation-id <operation-id>

npm run shieldkit -- --home /absolute/path/shieldkit-home operation rebroadcast \
  --operation-id <operation-id> \
  --cas-token <current-attempt-token> \
  --acknowledge-rebroadcast
```

There is no automatic rebroadcast. After any ambiguous send, inspect before
acting.

## Know what is not implemented

`pool status` and `pool sync` do not yet have a qualified canonical-lineage
implementation. They fail closed. `pool doctor` is a local check, not a synonym
for status. PF6 and FRI mutations also fail closed even with `--allow-lab`.

During the compatibility window ending **2026-11-07**, the old PF10 CLI remains
available as `npm run shieldkit:legacy-pf10 -- …`. It is a migration bridge, not
a second product grammar.

Keep wallets, homes, and data homes private and backed up. Read
[Security](../../SECURITY.md) before funding anything.
