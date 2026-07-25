# Playground & your pool

**One-line product story**

> ShieldKit creates shielded pools; the Chipnet playground is our pool, and your pool is the same thing with your genesis.

## Audiences (names)

| Name | Intent | Entry |
|------|--------|--------|
| **App builders** | Build against a live pool (ours or yours) | [`examples/chipnet-playground`](../examples/chipnet-playground/) |
| **Pool creators** | Birth a new pool | [`examples/create-your-pool`](../examples/create-your-pool/) |

Avoid “tinkerer.” Both use the **same** SDK; only the **instance** differs.

## Instance model

```text
loadInstance(ref) → createKit(instanceToKitConfig(instance))
         │
    chipnet-playground     ./my-pool/
    (official Chipnet)     (your genesis)
```

An instance is coordinates + authenticated profile bundle + **chain tip you discover**.

## Honesty

- Playground: **Chipnet**, **development-only**, **Unaudited — Work In Progress**
- Not production privacy
- Proving key ~455 MB: pin + external/local path, not git
