# artifacts/ — the per-track artifact registry (the durable process)

**Purpose:** every crown/submission build's artifacts live HERE, with full provenance — source
repo + commit, compiler repo + pinned commit, measured bytes, A1 certificate evidence (or the
track-appropriate gate for non-running size-leader entries), and submission status. This registry
exists because builds have already been lost to ephemeral scratch dirs and stale board numbers
(the 4,651 board value that matches no artifact; the true 6,054 that survived only by accident —
see `bn254-size-leader/4329/PROVENANCE-singleton-artifact-README.md`).

## THE RULE

> **A result is not HELD until its artifacts + provenance are committed here and pushed to the
> mirror (`github.com/toorik2/verifier-intel`).**

Not "measured once in a scratch dir", not "on the board", not "in a chat log". Committed + pushed,
or it doesn't count as held. Update `registry.json` and `../LEADERBOARD.md` in the same commit
("same turn" — see `../RUNBOOK.md` step 8).

## Layout

- `registry.json` — the machine-readable index. One entry per build; schema in its `_meta`.
- `<track>/<bytes>/` — one directory per registered artifact set: the hex/tx files themselves plus
  a `MANIFEST.md` (sha256 per file, source repo+commit, compiler pin, verification evidence).

Tracks: `bn254-native-standard` · `bn254-native-nonstandard` · `bn254-one-tx-standard` · `bn254-size-leader` ·
`bls-native-standard` · `bls-native-nonstandard` · `bls-size-leader`.

Statuses: `built` → `measured` → `a1-certified` → `submitted` (→ `superseded`). A1 certification
is MANDATORY before any native-track submission (1 forgery = score 0); size-leader entries never
run on-chain, so their certificate is the gate.mjs class (round-trip + differential + E2E) instead.

## Honesty discipline

- Never fabricate an artifact file. If a registered result's files are not on disk, the registry
  entry says so (`notes: artifacts-pending-rebuild`) and the entry cannot advance past its
  evidence.
- Backfilled entries record exactly what was found vs missing at backfill time.
- Byte-exact copies only: verify sha256 against the source at copy time and record both the
  hashes and the source commit in the MANIFEST.
