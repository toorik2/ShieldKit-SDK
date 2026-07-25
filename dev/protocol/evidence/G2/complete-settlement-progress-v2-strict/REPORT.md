# Complete settlement progress (updated)

Observed: 2026-07-24T04:31:40Z

## Closed

- Relation freeze, setup, desktop prove, PF7-sub62 (roles 0–6), structural 7–9, recovery 29/29
- SCCT binding works when unlock lengths match plan
- Size gates hold (~55–57 kB / ≤9.3 kB unlocks)

## Open (blocks 10/10 + Chipnet)

**PF7 unlock-length fixed point:** genesis/terminal unlock sizes oscillate under prove→PF7→replan (observed terminal 9212↔9277). Without stable lengths, SCCT change amount and terminal proof diverge.

Next engineering options:
1. Pad terminal/genesis unlocks to a fixed max length inside PF7 packing
2. Fix PF7 dens/pad selection to be packet-invariant for length
3. Multi-start search for a self-consistent length tuple

**Do not fund Chipnet** until 10/10 libauth accept for deposit/transfer/withdrawal with mutation matrix.
