# Model

The important objects are deliberately separate:

| Object | Meaning |
| --- | --- |
| **Design** | Friendly backend family such as `pf10`, `pf6`, or `fri`; not a protocol identity |
| **Profile** | Immutable content identity covering relation, topology, parameters, ABI, artifacts, and network policy |
| **Instance** | One on-chain pool genesis and lineage using one exact profile |
| **Home** | Private local workspace immutably bound to one profile and instance |
| **Operation** | One create, deposit, transfer, withdrawal, or recovery attempt |
| **Tip** | Mutable chain observation; never an identity |

PF10 also has a legacy **data home** containing the existing beta wallet,
journal, runtime, and recovery authority. Explicit import creates a unified home
that points back to that validated authority without copying or relabelling it.

## Resolution

An existing home wins. `--design` and `--profile` become assertions against its
binding; a mismatch fails before backend code runs. Design aliases select
families only. They never manufacture profile IDs.

Without a home, selectors resolve in this order:

1. Explicit command-line selector pair.
2. Owner-private XDG configuration.
3. Explicit environment design/home compatibility settings.
4. No default.

Supplying either CLI selector suppresses both config selectors, preventing an
explicit profile from being combined with an ambient design default.

## Operation boundary

```text
intent
  -> prove and assemble exact bytes
  -> whole-transaction validation
  -> durable bytes + reservations
  -> record send-attempted
  -> exactly one automatic send
  -> mempool observation + exact readback
  -> atomic local commit
```

The shared kernel names these states:

```text
preparing -> prepared-durable -> send-attempted
  -> accepted-zero-conf -> local-commit-pending -> committed
  -> rejected
  -> send-indeterminate
```

A preflight rejection is a safe pre-send failure. Once `send-attempted` is
durable, absence of evidence is never treated as rejection and automatic retry
is forbidden.

PF10 currently delegates this responsibility to its existing product lifecycle.
The shared SQLite coordinator exercises the same invariants in conformance tests
but is not a parallel PF10 mutation path. PF6 and FRI are not connected to it.

## Chain truth

Zero-conf mempool admission and exact transaction readback are the operational
success boundary. Confirmation is not required for normal completion. A list of
known transaction IDs is still only an observation set; it does not prove the
canonical pool lineage. That is why unified `pool sync` remains blocked.

## Repository shelves

- **Product** documents the current unified CLI and PF10 beta path.
- **Lab** documents designs that remain blocked from the unified mutation path.
- **Record** preserves specifications, evidence, decisions, and dated results.
- **Vendor** documentation belongs to upstream sources.
- **Archive** is historical and never a current setup path.
