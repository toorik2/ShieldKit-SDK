# tools/health — codebase-health map + redundancy detector

A build-**light** source parser for LeanBCH. It reads `LeanBCH/**/*.lean` (plus the root
`LeanBCH.lean`) as **text** — it does **not** run `lake build`, load Lean, or import mathlib —
and emits two GENERATED, committed artifacts:

| artifact | audience | what it is |
| --- | --- | --- |
| [`REPORT.md`](./REPORT.md) | humans | rendered summary + tables |
| [`index.json`](./index.json) | AI agents / scripts | the machine-queryable surface |

The point: an **always-true** "what exists / what is dead / what is duplicated" map, so an agent
queries it **before** defining or proving something (instead of relying on memory and re-inventing a
lemma that already exists), and so drift in the **un-kernel-checked layer** — dead files, duplicated
declarations, escape hatches, and prose over-claims — is visible in a diff instead of rotting.

## Regenerate

```bash
node tools/health/map.mjs      # rewrites REPORT.md + index.json (no deps, no lake build)
```

The output is **deterministic** (sorted, no timestamps), so a regeneration produces a minimal,
meaningful `git diff`. **Never hand-edit `REPORT.md` or `index.json`** — they are generated. Edit
`map.mjs` and regenerate.

## What it computes

1. **Module DAG + orphans.** Parses `import LeanBCH.…` into an import graph. Roots are `LeanBCH`
   (`LeanBCH.lean`) and `LeanBCH.Opt` (`LeanBCH/Opt.lean`). Any `.lean` file **not** transitively
   reachable from a root is an **ORPHAN** (dead file). Maps module ↔ path
   (`LeanBCH.Opt.Adapter` ↔ `LeanBCH/Opt/Adapter.lean`).
2. **Declaration index.** Every top-level `theorem`/`lemma`/`def`/`abbrev`/`structure`/`inductive`
   with simple name, kind, enclosing `namespace` (tracked via `namespace`/`section`/`mutual`/`end`),
   and `file:line`. Signatures are **best-effort** (first source line only — multi-line signatures
   are truncated).
3. **Duplication suspects.** (a) simple names defined in ≥2 files; (b) files sharing a basename in
   different dirs. **Suspects for human review — some are legitimate** (same name in different
   namespaces, e.g. `run`/`step`/`State`).
4. **Escape-hatch scan.** Real proof-term uses of `sorry`/`admit`/`native_decide`/`partial def`/
   `unsafe`/top-level `axiom`, plus a per-file `decide` count. Comments, doc-prose, strings, and
   backtick-quoted tokens are excluded, so prose like "no `native_decide`" is **not** counted. The
   project headline should be **0** `sorry`/`admit`/`native_decide`/`partial`.
5. **Claim scan.** Comment/doc lines containing strong claim words (`proven`, `sound`, `verified`,
   `0 sorry`, `byte-for-byte`, `floor`, `keystone`, …) — a **worklist** for an adversarial reviewer
   to check claims against reality. Surfaced, **not verified**.

## How an AI agent should QUERY it before building

Before defining a lemma/def or starting a proof, **query `index.json` first** (cheap, no build):

```bash
NAME=step_foo   # the thing you're about to define

# 1. Does this simple name already exist? Where?
node -e 'const j=require("./tools/health/index.json");
  console.log(j.declarations.filter(d=>d.name==="'"$NAME"'"||d.fullName.includes("'"$NAME"'"))
    .map(d=>d.kind+" "+d.fullName+"  ("+d.file+":"+d.line+")").join("\n")||"— not found —")'

# 2. Is it already flagged as a duplication suspect (defined in several files)?
node -e 'const j=require("./tools/health/index.json");
  const d=j.duplication.names.find(x=>x.name==="'"$NAME"'");
  console.log(d?JSON.stringify(d,null,2):"— not a duplicate name —")'
```

Or just `grep -n '"name": "step_foo"' tools/health/index.json`. If the name (or a near-synonym) is
already there, **reuse or extend it — do not re-derive it.**

### The deeper query: `exact?` / `apply?`

`index.json` answers *"does a declaration with this NAME exist?"*. It does **not** answer *"does some
lemma already PROVE this goal?"* — names differ, statements match. For that, use **Lean's own**
`exact?` / `apply?` (and `rw?` / `simp?`) inside the proof: they search the environment by TYPE and
will find a differently-named lemma that closes the goal. Workflow: query this map to avoid
duplicating a *name*/*concept*; use `exact?`/`apply?` to avoid re-proving a *statement*.

## CI wiring

`tools/opt-ci/verify.sh` runs `node tools/health/map.mjs` as step **[5/5]**, **report-only** — it
never fails the build in this draft. The comment there lists the natural FAIL gates to promote later:
(a) any real escape hatch, (b) any new orphan file, (c) artifact drift
(`git diff --exit-code tools/health/` after regenerating). This tool covers the un-gateable /
un-kernel-checked layer that `lake build` + `#print axioms` cannot see.

## Not committed

`index.json` and `REPORT.md` are GENERATED, not committed (they would go stale on every new declaration and bloat the repo — the very drift this tool fights). Run `node tools/health/map.mjs` to (re)generate them locally; `tools/opt-ci/verify.sh` regenerates them fresh on each CI run. The committed source of truth is `map.mjs`.
