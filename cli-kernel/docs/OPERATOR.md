# Unified CLI operator guide

Entry: `node cli-kernel/bin/shieldkit.mjs` or the package `shieldkit` binary.

## Grammar

```text
shieldkit [--home <path>] [--design <alias> | --profile <64-hex-id>] <group> <command> [flags]
```

Design aliases select backend families. `--profile` is always an exact content
ID and is accepted only when a validated home or registered profile package can
bind it. There is no automatic design/profile default.

The target groups are:

| Group | Commands | Current boundary |
| --- | --- | --- |
| `design` | `list`, `show`, `doctor`, `verify` | Read-only catalog and wiring checks |
| `pool` | `create`, `import`, `status`, `sync`, `doctor` | PF10 create/import/doctor; status and sync fail closed |
| `action` | `deposit`, `transfer`, `withdraw` | PF10 only, through a bound home |
| `operation` | `inspect`, `rebroadcast` | PF10 inspect and exact acknowledged rebroadcast |
| `demo` | `list`, `status` | Explicit unavailable catalog state |

## Home and identity

A home binds `backendId`, exact `profileId`, `instanceId`, Chipnet genesis,
accepted genesis descriptor, and `homeId`. The manifest is owner-private,
single-link, immutable, and symlink-rejecting.

An existing home wins. Supplied design/profile selectors assert a match and
fail on disagreement. A legacy PF10 `--data-home` is never treated as a unified
home:

```bash
shieldkit pool import \
  --from-data-home /absolute/legacy-pf10-data-home \
  --home /absolute/new-home \
  --design pf10
```

The source is opened read-only through the PF10 product's committed deployment
authority and is left untouched. The new home stores an identity-bound private
pointer to it.

## PF10 workflow

Pool creation uses the legacy data-home only during the compatibility bridge:

```bash
shieldkit --design pf10 pool create \
  --data-home /absolute/new-pf10-data-home \
  --funding-wallet /absolute/funding-wallet.json \
  --funding-utxo <txid:vout>
```

After accepted creation, import it into a home. Then:

```bash
shieldkit --home /absolute/home action deposit
shieldkit --home /absolute/home action transfer --note <note-id>
shieldkit --home /absolute/home action withdraw --note <note-id> --to <bchtest-p2pkh>
```

Creation and `--resume` always require the exact explicit legacy `--data-home`;
both are refused through an existing bound home. Before every bound-home PF10
delegation, the adapter re-derives the product's committed deployment receipt
and requires it to match the immutable home.

Direct legacy data-home actions are not part of the unified grammar. The PF10
backend's result is translated to success only when its exact beta contract
reports verified proof, all-input VM acceptance, an allowed admission route with
exact RPC counts and canonical Chipnet genesis, zero confirmations, and complete
instance-bound readback.

## Delivery ambiguity

Exactly one automatic send is permitted per operation. After `send-attempted`,
unknown delivery is `send-indeterminate`, never an invented rejection.
Rebroadcast is explicit:

```bash
shieldkit --home /absolute/home operation rebroadcast \
  --operation-id <id> \
  --cas-token <current-token> \
  --acknowledge-rebroadcast
```

The shared SQLite coordinator enforces durable exact bytes, reservations,
whole-transaction evidence, an atomic send lease, exact readback, and idempotent
local commit. It is conformance infrastructure today; PF10 retains its existing
product lifecycle authority.

## Local defaults

Optional defaults live in `$XDG_CONFIG_HOME/shieldkit/config.json` (or
`~/.config/shieldkit/config.json`) and may contain only `home`, `design`, and
`profile`. The file must be owned by the current user, private against writes,
single-link, and free of symlink path components.

Supplying either CLI selector suppresses both config selectors. CLI `--home`
overrides config home. Defaults never override an existing home's identity.

## Lab, demo, and benchmark

PF6 and FRI have no frozen profile in the closed catalog. Their mutations stay
blocked even with `--allow-lab`.

The demo catalog is deliberately unavailable until a real descriptor is signed
by a pinned Ed25519 key. No public hash is presented as a signature and no
shared mutable funded pool is implied.

There is no stub `shieldkit dev bench`. The separate real campaign is
`npm run bench:action`; any eventual CLI integration must observe
the same action path rather than create another sender.

Compatibility shims end **2026-11-07**.
