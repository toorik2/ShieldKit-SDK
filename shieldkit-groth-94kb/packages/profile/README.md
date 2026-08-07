# `@shieldkit/profile`

Strict profile and instance loading, content-derived identities, bundle construction, and Groth16 setup provenance.

## Public API

`@shieldkit/profile` is the only supported entrypoint.

- Load and identify: `loadProfile`, `loadVerifierProfileBundle`, `BundleValidationError`, `canonicalJson`, `parseStrictJson`, `deriveProfileId`, `deriveInstanceId`
- Instances: `loadInstance`, `instanceToKitConfig`, `playgroundInstancePath`, `playgroundBundleSearchPaths`, `CHIPNET_PLAYGROUND_ID`, `InstanceError`
- Build and setup: `buildVerifierProfileBundle`, `ProfileBuildError`, `initializeDevelopmentGroth16`, `LocalSetupError`, `initializeCeremonyGroth16`, `initializeLocalContributionSimulationGroth16`, `assertCeremonyMetadata`, `assertLocalContributionSimulationMetadata`, `CeremonyError`, `SNARKJS_VERSION`, `getPinnedSnarkjsInfo`
- External contributions: `BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE`, `createBetaSingleContributorContributionRequest`, `createExternalContributionRequest`, `signBetaSingleContributorContributionReceipt`, `signExternalContributionReceipt`, `V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_PROFILE_SCHEMA`, `V2_BETA_SINGLE_CONTRIBUTOR_CEREMONY_TRANSCRIPT_SCHEMA`, `V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_REQUEST_SCHEMA`, `V2_BETA_SINGLE_CONTRIBUTOR_CONTRIBUTION_RECEIPT_SCHEMA`, `verifyBetaSingleContributorExternalReceiptChain`, `verifyExternalContributionChain`, `digestContributionFile`, `ExternalContributionError`
- Entropy policy: `BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY`, `BETA_SINGLE_CONTRIBUTOR_ENTROPY_POLICY_SHA256`, `BETA_SINGLE_CONTRIBUTOR_ENTROPY_SCHEMA`, `BETA_SINGLE_CONTRIBUTOR_MIN_DICE_ROLLS`, `BETA_SINGLE_CONTRIBUTOR_MAX_DICE_ROLLS`, `deriveBetaSingleContributorEntropy`, `BetaSingleContributorEntropyError`
- Fail-closed compatibility: `init`, `ProfileInitError`, `V1_LEGACY_PROTOCOL_ID`, `V1_LEGACY_RELATION_ID`, `V1_LEGACY_PUBLIC_INPUT_ABI_ID`, `LEGACY_PROFILE_CREATION_QUARANTINED_CODE`, `LegacyProfileCreationQuarantinedError`, `isV1LegacyProfileIdentity`

## Boundary

`init` is a quarantine guard and always refuses historical profile creation. Development, simulated, and single-contributor setup records do not imply ceremony, release, or production qualification. Source files below this package, including `v2/`, are not public subpath exports.

Private workspace API. ShieldKit-Groth remains an unaudited, Chipnet-only beta. See the [repository overview](../../../README.md) and [product model](../../../docs/product/model.md).
