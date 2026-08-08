/**
 * Closed validated design catalog — data only.
 * Listing designs MUST NOT execute backend modules.
 */

import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

import { NETWORKS } from '../contracts/identity.mjs';
import { buildCapabilityRecord } from '../contracts/capabilities.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SDK_ROOT = path.resolve(HERE, '../..');

/** Frozen closed registry embedded in the kernel (not ambient env roots). */
export const CLOSED_CATALOG = Object.freeze({
  schema: 'shieldkit-closed-design-catalog/v2',
  network: NETWORKS.chipnet.networkId,
  designs: Object.freeze([
    Object.freeze({
      alias: 'pf10',
      aliases: Object.freeze(['pf10', 'shieldkit-groth-94kb', 'groth-pf10']),
      id: 'pf10',
      displayName: 'ShieldKit-Groth PF10',
      backendId: 'pf10-v2-beta',
      backendApiVersion: 1,
      maturity: 'product',
      designRoot: 'shieldkit-groth-94kb',
      proofSystem: 'Groth16',
      topology: 'PF10-FusedQGenesis',
      roles: 10,
      inputsPerAction: 13,
      network: NETWORKS.chipnet.networkId,
      profileId: null,
      profileStatus: 'unselected',
      profileAuthority: 'validated PF10 profile core loaded by the product context',
    }),
    Object.freeze({
      alias: 'pf6',
      aliases: Object.freeze(['pf6', 'pf6-a3-direct-v1', 'shieldkit-groth-54kb']),
      id: 'pf6-a3-direct-v1',
      displayName: 'ShieldKit-Groth PF6 (Lab)',
      backendId: 'pf6-a3-direct-v1',
      backendApiVersion: 1,
      maturity: 'lab',
      designRoot: 'shieldkit-groth-54kb',
      proofSystem: 'Groth16',
      topology: 'pf6-a3-direct-v1',
      roles: 6,
      inputsPerAction: 9,
      network: NETWORKS.chipnet.networkId,
      profileId: null,
      profileStatus: 'unfrozen',
      profileAuthority: null,
      identityBlockers: Object.freeze([
        'No closed, validated PF6 profile package is pinned by the unified CLI',
      ]),
    }),
    Object.freeze({
      alias: 'fri',
      aliases: Object.freeze(['fri', 'fri-96k', 'fri-stark-96kb', 'shieldkit-fri-stark-96kb']),
      id: 'fri-stark-96kb',
      displayName: 'ShieldKit-FRI-STARK 96KB (Lab)',
      backendId: 'fri-stark-96kb',
      backendApiVersion: 1,
      maturity: 'lab',
      designRoot: 'shieldkit-fri-stark-96kb',
      proofSystem: 'FRI-STARK',
      topology: 'fri-sound-lean-fused-state0-v1',
      roles: 17,
      inputsPerAction: 18,
      network: NETWORKS.chipnet.networkId,
      profileId: null,
      profileStatus: 'unfrozen',
      profileAuthority: null,
      identityBlockers: Object.freeze([
        'FRI creation and settlement sources disagree on topology and parameters',
        'The FRI note/key contract is not frozen',
      ]),
    }),
  ]),
});

/**
 * Compatibility name retained for callers of the prototype catalog.
 *
 * Design summaries are not profile identities. This function deliberately
 * returns the declared identity state without hashing roles/topology labels.
 */
export function withProfileIds(catalog = CLOSED_CATALOG) {
  return Object.freeze({
    ...catalog,
    designs: Object.freeze(catalog.designs.map((d) => Object.freeze({ ...d }))),
  });
}

export function loadClosedCatalog() {
  return withProfileIds(CLOSED_CATALOG);
}

/**
 * Capability matrix — evidence-bound, profile-specific.
 * Incomplete Lab verbs stay blocked/experimental, not emulated.
 */
export function capabilitiesForDesign(design) {
  if (!design || typeof design !== 'object') throw new Error('design required');
  const profileId = design.profileId ?? null;
  const profileStatus = design.profileStatus ?? (profileId === null ? 'unfrozen' : 'frozen');
  const network = design.network || NETWORKS.chipnet.networkId;

  if (design.id === 'pf10' || design.alias === 'pf10') {
    const experimental = (blocker) => ({
      status: 'experimental',
      blockers: blocker ? [blocker] : [],
    });
    return buildCapabilityRecord({
      designId: design.id,
      profileId,
      profileStatus,
      network,
      overall: 'experimental',
      guarantees: {
        destinationBinding: experimental('must be revalidated by the exact PF10 product context'),
        wholeTransactionVm: experimental('must be revalidated by the exact PF10 product context'),
        durablePreparation: experimental('legacy PF10 lifecycle owns durability; shared kernel is not its authority'),
        singleSendAdmission: experimental('legacy PF10 lifecycle owns admission; shared kernel is not its authority'),
        exactReadback: experimental('must be observed by the configured product transport'),
        syncRecovery: {
          status: 'blocked',
          blockers: ['unified canonical pool sync is not wired to the PF10 history scanner'],
        },
        noteRecovery: experimental('delegated product recovery remains beta and home-bound'),
        createPool: experimental('delegated product beta path requires an exact runtime-derived profile'),
        deposit: experimental('delegated product beta path requires a validated existing home'),
        transfer: experimental('delegated product beta path requires a validated existing home'),
        withdraw: experimental('delegated product beta path requires a validated existing home'),
      },
      blockers: [
        'This is a design-family support record, not mutation authority',
        'PF10 is the unified CLI beta backend and explicitly not a production qualification claim',
      ],
    });
  }

  if (design.id === 'pf6-a3-direct-v1' || design.alias === 'pf6') {
    const blocked = (reason) => ({ status: 'blocked', blockers: [reason] });
    return buildCapabilityRecord({
      designId: design.id,
      profileId,
      profileStatus,
      network,
      overall: 'blocked',
      guarantees: {
        destinationBinding: blocked('current PF6 withdrawal path does not prove destination binding'),
        wholeTransactionVm: blocked('no exact frozen PF6 profile support record is pinned'),
        durablePreparation: blocked('shared durable lifecycle is not integrated with PF6'),
        singleSendAdmission: blocked('shared single-send lifecycle is not integrated with PF6'),
        exactReadback: blocked('exact readback is not integrated with PF6'),
        syncRecovery: blocked('sync recovery is not product-qualified for PF6'),
        noteRecovery: blocked('note recovery is not product-qualified for PF6'),
        createPool: blocked('PF6 create is not wired to a validated home/profile package'),
        deposit: blocked('PF6 deposit is not wired to the unified safe lifecycle'),
        transfer: blocked('PF6 transfer is not wired to the unified safe lifecycle'),
        withdraw: blocked('destination binding is absent from the current PF6 withdrawal path'),
      },
      blockers: [
        'PF6 exact profile identity is not frozen in the unified CLI',
        'Lab acknowledgement cannot override missing safety guarantees',
      ],
    });
  }

  const blocked = (reason) => ({ status: 'blocked', blockers: [reason] });
  return buildCapabilityRecord({
    designId: design.id,
    profileId,
    profileStatus,
    network,
    overall: 'blocked',
    guarantees: {
      destinationBinding: blocked('FRI note/key and withdrawal-destination contracts are not frozen'),
      wholeTransactionVm: blocked('no authoritative exact FRI relation/topology profile is frozen'),
      durablePreparation: blocked('shared durable lifecycle is not integrated with FRI'),
      singleSendAdmission: blocked('shared single-send lifecycle is not integrated with FRI'),
      exactReadback: blocked('exact readback is not integrated with FRI'),
      syncRecovery: blocked('FRI sync/recovery is not frozen as a product lifecycle'),
      noteRecovery: blocked('FRI note derivation boundary is not product-qualified'),
      createPool: blocked('FRI creation and settlement profile sources disagree'),
      deposit: blocked('FRI deposit is not a complete unified lifecycle verb'),
      transfer: blocked('FRI transfer is incomplete as a full lifecycle verb'),
      withdraw: blocked('FRI withdrawal is not a complete destination-bound lifecycle verb'),
    },
    blockers: [
      'FRI exact profile and note/key contract are not frozen',
      'Lab acknowledgement cannot override missing safety guarantees',
    ],
  });
}

export function listDesignsDataOnly() {
  const catalog = loadClosedCatalog();
  return catalog.designs.map((d) => Object.freeze({
    alias: d.alias,
    id: d.id,
    displayName: d.displayName,
    backendId: d.backendId,
    profileId: d.profileId,
    profileStatus: d.profileStatus,
    profileAuthority: d.profileAuthority,
    maturity: d.maturity,
    proofSystem: d.proofSystem,
    topology: d.topology,
    roles: d.roles,
    network: d.network,
    // Explicit: listing did not execute backend code
    backendModuleLoaded: false,
  }));
}

export function showDesign(aliasOrId) {
  const catalog = loadClosedCatalog();
  const d = catalog.designs.find((x) => {
    const keys = [x.alias, x.id, ...(x.aliases || [])].map((a) => String(a).toLowerCase());
    const requested = String(aliasOrId).toLowerCase();
    return keys.includes(requested) || (x.profileId !== null && x.profileId === requested);
  });
  if (!d) return null;
  const caps = capabilitiesForDesign(d);
  return Object.freeze({
    ...d,
    capabilities: caps,
    backendModuleLoaded: false,
    designRootAbs: path.join(SDK_ROOT, d.designRoot),
  });
}

export function catalogContentHash() {
  const catalog = loadClosedCatalog();
  return createHash('sha256').update(JSON.stringify(catalog)).digest('hex');
}
