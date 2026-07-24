# shield.cash specifications

This directory contains protocol inputs that implementations must agree on. A
document's status is explicit:

- **G1 candidate**: sufficiently exact to build and falsify, but not a compatible
  profile;
- **G2 frozen**: byte-exact candidate used by all downstream evidence; or
- **released profile**: the mutually hash-consistent set defined by the charter.

The current documents are G1 feasibility candidates. They must not be used to
identify a deployed profile or to claim protocol compatibility.

The current G2 enforcement experiment is
[kernel/G2_SETTLEMENT_SPLIT_CANDIDATE.md](kernel/G2_SETTLEMENT_SPLIT_CANDIDATE.md).
It is executable research, not a frozen G2 profile.

The standard is deliberately narrow: fixed 0.1 BCH notes, deposit, one-note
private transfer, withdrawal, local proving, one transparent fee input, one
canonical change output, and immutable profile-bound verifier material.

The candidate verifier-bundle boundary is specified in
[verifier-profile/manifest-v1.md](verifier-profile/manifest-v1.md); its
non-upgrade lifecycle and future ceremony-adapter contract are in
[verifier-profile/lifecycle-v1.md](verifier-profile/lifecycle-v1.md).

The current candidate public-recipient-address and fixed recovery-record
construction is specified in [recovery-record-v2.md](recovery-record-v2.md).
It is local wallet recovery logic, not a G2 freeze or a privacy claim. The
former [recovery-record-v1.md](recovery-record-v1.md) is explicitly
invalidated historical evidence, not a compatible construction.
