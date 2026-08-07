# Start with PF10

PF10 is the only profile wired to the root `shieldkit` command. It is an
unaudited, Chipnet-only beta and is not production-qualified.

## Install and inspect

Use Node.js 22.23.1, the version pinned in CI. The package accepts Node.js
22.5.0 or newer.

```bash
npm ci
npm run shieldkit -- --version
npm run shieldkit -- pool --help
```

These checks do not broadcast. Source installation alone does not guarantee
that the authenticated PF10 runtime bundle is installed. A funded action must
use runtime material whose receipt, profile identity, artifact hashes, and
source commit verify locally; missing or mismatched material fails closed.

## Prepare

You need:

- an absolute path to a retained, owner-private Chipnet funding wallet;
- an owned, unspent, tokenless Chipnet P2PKH UTXO;
- a new absolute data-home path outside this checkout;
- a separate fresh Chipnet P2PKH address for withdrawals.

ShieldKit does not provide a faucet, sponsor, mining service, or hosted wallet.
Keep wallet and data-home files private and backed up. Read
[Security](../../SECURITY.md) before continuing.

## Create a pool

The following command broadcasts Chipnet transactions:

```bash
npm run shieldkit -- pool create \
  --funding-wallet /absolute/path/funding-wallet.json \
  --funding-utxo <64-lowercase-hex-txid>:<vout> \
  --data-home /absolute/path/shieldkit-pool \
  --human
```

Do not substitute a different wallet or UTXO when resuming an existing create
operation. Inspect the exact recovery contract first:

```bash
npm run shieldkit -- pool create --help
npm run shieldkit -- pool recover --help
```

## Operate

The state-changing lifecycle is create, deposit, transfer, and withdraw. Use
the command's help as the option authority:

```bash
npm run shieldkit -- pool deposit --help
npm run shieldkit -- pool transfer --help
npm run shieldkit -- pool withdraw --help
npm run shieldkit -- pool recover --help
npm run shieldkit -- pool doctor --help
```

Continuous operation requires independent fee UTXOs managed by the data home.
Withdraw only to a fresh external address, not the funding or change wallet.

An action completes at accepted zero-confirmation admission and exact readback.
ShieldKit does not wait for mining. Preserve the result and operation ID until
the next local health check succeeds. The root `pool recover` command only
inspects ambiguous delivery and performs explicit exact-byte rebroadcast; it is
not wallet restoration.

PF6 and FRI-STARK use a separate experimental router and are not drop-in PF10
profiles. See [Lab profiles](../lab/README.md).
