/**
 * Demo catalog boundary.
 *
 * There is deliberately no built-in demo until the project publishes a
 * descriptor catalog signed by a pinned Ed25519 key. A hash made with public
 * constants is a checksum, not a signature, and must never imply provenance.
 */

import { NETWORKS } from '../contracts/identity.mjs';

export const DEMO_CATALOG_SCHEMA = 'shieldkit-demo-catalog/v1';

export function buildDemoCatalog() {
  return Object.freeze({
    schema: DEMO_CATALOG_SCHEMA,
    network: NETWORKS.chipnet.networkId,
    entries: Object.freeze([]),
    readOnly: true,
    availability: 'unavailable',
    reason: 'no pinned Ed25519-signed descriptor catalog is bundled',
  });
}

/** Validate only the explicit unavailable sentinel; this is not authenticity. */
export function isUnavailableDemoCatalog(catalog) {
  return Boolean(
    catalog
    && catalog.schema === DEMO_CATALOG_SCHEMA
    && catalog.readOnly === true
    && catalog.availability === 'unavailable'
    && Array.isArray(catalog.entries)
    && catalog.entries.length === 0
    && !Object.hasOwn(catalog, 'signature')
    && !Object.hasOwn(catalog, 'signatureAlg')
    && !Object.hasOwn(catalog, 'contentSha256'),
  );
}

/** No bundled descriptor means there is nothing whose authenticity can verify. */
export function verifyDemoCatalog(_catalog) {
  return false;
}
