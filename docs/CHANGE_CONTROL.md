# Frozen-direction change control

Document version: 1.1

Status: binding under `g0-v3`

## Rule

Files and decisions hashed by `policy/g0-lock.json` are frozen. Editing prose is
not a harmless cleanup when it changes a locked meaning.

No locked change is valid unless the history contains:

1. one reopening commit containing a numbered RFC under `docs/rfcs/`, the old
   and proposed decisions, the reason for the change, every invalidated gate and
   artifact, and `policy/gates.json` reopening G0 and affected downstream gates;
2. one freeze commit containing the revised normative documents, gate states,
   and new lock manifest after the revised G0 requirements pass; and
3. a new annotated freeze tag pointing to that freeze commit.

The RFC must use a new charter version. Existing profiles and instances are
never mutated; a semantic change creates a new profile.

## Mechanical enforcement

`npm test` runs `scripts/check-policy.mjs`. It verifies:

- the SHA-256 of every frozen document;
- the required locked decision identifiers;
- the fee and verifier baselines;
- agreement between the human and machine gate states; and
- once the freeze tag exists, byte identity of the lock manifest with the
  tagged manifest while G0 remains `PASS`.

CI runs the same command. An agent must not bypass, weaken, skip, or patch this
check to make unrelated work pass.

Before creating a new freeze tag, run
`SHIELD_FREEZE_CANDIDATE=<freeze-id> npm test` on the intended freeze commit.
This permits only the not-yet-created matching tag to be absent; every document
hash, decision, invariant, and human/machine gate state must already pass.
After creating the annotated tag, plain `npm test` must pass.

## What may change without reopening G0

- evidence produced under an existing gate;
- implementation that conforms to the frozen direction;
- measured candidate choices explicitly owned by G1 or later;
- typo-only edits outside frozen documents; and
- additive documentation that does not alter a locked requirement.

When uncertain, treat a change as semantic and open an RFC.

## Break-glass truth

Repository owners can technically rewrite Git history. The guard makes ordinary
or accidental drift fail closed and makes intentional direction changes
explicit and reviewable. The annotated freeze tag is the durable comparison
point; silently moving or deleting it is a governance breach.

## 2026-07-25 — Product repository layout

Layout migration for GitHub product surface (not a protocol semantics change):

- `policy/` → `dev/protocol/policy/`; `AGENTS.md` → `dev/protocol/AGENTS.md`
- `circuits/`, `spec/`, `evidence/` → `dev/protocol/`
- Lab scripts/docs → `dev/research/`
- Product packages remain `packages/{kit,profile,action,prove,recover}`

G0 freeze document *paths* updated in `dev/protocol/policy/g0-lock.json`. Decision IDs D-001–D-016 unchanged. Re-tag freeze when cutting a new PASS candidate.

## 2026-07-25c — Remove GitHub Actions

CI workflow `.github/workflows/policy.yml` removed. Protocol freeze checks run
locally via `npm test` (`scripts/check-policy.mjs`). No hosted Actions dependency.
