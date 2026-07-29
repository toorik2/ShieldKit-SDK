import {
  LegacyProfileCreationQuarantinedError,
  refuseLegacyProfileCreation,
} from './legacy.mjs';

/**
 * The historical generic init composed V1 profile packaging with setup.
 *
 * It is intentionally unavailable: the development setup implementation is
 * now attested to the exact V2 Direct relation, while the former bundle bridge
 * hard-pinned the unrelated V1 legacy relation. Keeping that composition would
 * permit protocol-identity laundering.
 */
export async function init() {
  refuseLegacyProfileCreation('the historical generic profile init');
}

export {
  LegacyProfileCreationQuarantinedError as ProfileInitError,
};
export {
  SNARKJS_VERSION,
  getPinnedSnarkjsInfo,
} from './setup/development.mjs';
