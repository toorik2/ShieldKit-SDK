# PF6 Lab profile

This directory contains the `pf6-a3-direct-v1` implementation and its pinned
campaign evidence. It is not part of the root `shieldkit` product command.

PF6 uses six verifier roles and nine inputs per action. Its reference verifier
reports 54,671 script bytes. The evidence includes real Chipnet lifecycle,
Libauth, BCHN, LeanBCH, formal, and adversarial results, but the release record
explicitly sets `productionQualified: false` and `releaseQualified: false`.

Known boundaries:

- the Lab router contains maintainer-absolute dependencies;
- the setup reuses a single-contributor ceremony;
- withdrawal through the router has a conditional witness-layout risk;
- there is no mainnet, audit, or production claim.

Read the repository [PF6 Lab page](../docs/lab/pf6.md). Treat `profile.json`,
`design/FREEZE.json`, `evidence/`, and `pins/` as records tied to their exact
hashes and declared scopes.
