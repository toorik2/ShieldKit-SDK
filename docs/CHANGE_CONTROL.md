# Frozen-direction change control

Document version: 1.0

Status: binding under `g0-v1`

## Rule

Files and decisions hashed by `policy/g0-lock.json` are frozen. Editing prose is
not a harmless cleanup when it changes a locked meaning.

No locked change is valid unless one commit contains all of:

1. a numbered RFC under `docs/rfcs/`;
2. the old and proposed decisions;
3. the reason current evidence cannot answer the need without a change;
4. every invalidated gate and artifact;
5. `policy/gates.json` reopening G0 and all affected downstream gates;
6. updated normative documents and a new lock manifest; and
7. a new annotated freeze tag after the revised G0 passes.

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
