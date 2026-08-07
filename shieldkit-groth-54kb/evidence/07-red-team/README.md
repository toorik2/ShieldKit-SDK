# WP-7 Red Team — ShieldKit-54KB pf6

Attack matrix executed (evidence/attack-matrix.json) with dual-VM agreement
(libauth, BCHN consensus, LeanBCH) on every tested class:

- FORGERY / STATE CONFUSION / CARRIER SUBSTITUTION / DIGEST MISMATCH /
  OFF-SUBGROUP / DUST / BQ-READ / GENESIS EDGE / TERMINAL ABUSE — all rejected.
- BQ-filler (densDrop) accepts — characterized unauthenticated padding (AR-01).
- RT-2026-0807-01 — deposit-after-withdrawal (novel action) rejected by the
  state covenant's packet checks (instance-dependent digest-index byte);
  dual-VM confirmed; no impact on the pinned lifecycle.

The 4 audit scopes (protocol, implementation, formal/TCB, ops/release) are in
audit-scopes.json; closure is blocker-complete (no open blockers at the time
of writing — RT-2026-0807-01 is a documented accepted-risk/limitation).
