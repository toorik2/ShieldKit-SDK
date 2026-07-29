export const V1_LEGACY_PROTOCOL_ID = 'v1-legacy';
export const V1_LEGACY_RELATION_ID = 'shielded-action-v2';
export const V1_LEGACY_PUBLIC_INPUT_ABI_ID =
  'shielded-action-public-input-v1';
export const LEGACY_PROFILE_CREATION_QUARANTINED_CODE =
  'LEGACY_PROFILE_CREATION_QUARANTINED';

export class LegacyProfileCreationQuarantinedError extends Error {
  constructor(surface = 'legacy profile creation') {
    super(
      `${surface} is quarantined because it creates the V1 legacy `
      + `${V1_LEGACY_RELATION_ID} relation; it cannot create, label, convert, `
      + 'or migrate a ShieldKit V2 Direct profile. Use the attested V2 Direct '
      + 'setup and development-profile pipeline.',
    );
    this.name = 'LegacyProfileCreationQuarantinedError';
    this.code = LEGACY_PROFILE_CREATION_QUARANTINED_CODE;
  }
}

export function refuseLegacyProfileCreation(surface) {
  throw new LegacyProfileCreationQuarantinedError(surface);
}

export function isV1LegacyProfileIdentity({
  relationId,
  publicInputAbiId,
}) {
  return relationId === V1_LEGACY_RELATION_ID
    && publicInputAbiId === V1_LEGACY_PUBLIC_INPUT_ABI_ID;
}
