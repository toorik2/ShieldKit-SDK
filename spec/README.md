# shield.cash specifications

This directory contains protocol inputs that implementations must agree on. A
document's status is explicit:

- **G1 candidate**: sufficiently exact to build and falsify, but not a compatible
  profile;
- **G2 frozen**: byte-exact candidate used by all downstream evidence; or
- **released profile**: the mutually hash-consistent set defined by the charter.

The current documents are G1 feasibility candidates. They must not be used to
identify a deployed profile or to claim protocol compatibility.

The standard is deliberately narrow: fixed 0.1 BCH notes, deposit, one-note
private transfer, withdrawal, local proving, one transparent fee input, one
canonical change output, and immutable profile-bound verifier material.

