/**
 * PF10 legacy-home migration authority.
 *
 * The old product data home is deliberately not parsed here.  `session.json`
 * is only a path/configuration record.  Identity comes from the product's
 * canonical config loader and its committed, zero-conf deployment capability.
 * That capability validates the pinned genesis transaction and state NFT
 * before exposing the profile/instance binding.
 */

import path from 'node:path';

import {
  loadV2BetaProductConfig,
} from '../../shieldkit-groth-94kb/packages/kit/v2/beta-product-config.mjs';
import {
  assertV2BetaChipnetCommittedGenesisCapability,
  loadV2BetaChipnetCommittedGenesis,
} from '../../shieldkit-groth-94kb/packages/profile/v2/beta-chipnet-deployment.mjs';

import {
  assertInstanceId,
  assertProfileId,
  NETWORKS,
} from '../contracts/identity.mjs';
import { ERROR_CODES, cliFail } from '../contracts/errors.mjs';

const HASH = /^[0-9a-f]{64}$/u;
const PF10 = Object.freeze({ id: 'pf10', backendId: 'pf10-v2-beta' });

function migrationFail(message, details = null) {
  cliFail(ERROR_CODES.MIGRATION_REQUIRED, message, details === null ? undefined : { details });
}

function absoluteDataHome(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
    || path.normalize(value) !== value || value.includes('\0')) {
    migrationFail('legacy PF10 data-home must be a normalized absolute path');
  }
  return value;
}

function assertPf10Design(design) {
  if (design?.id !== PF10.id || design?.backendId !== PF10.backendId) {
    migrationFail('legacy product data can be imported only as PF10; another design may not be relabelled as PF10');
  }
}

function validateProductConfig(loaded, dataHome) {
  const config = loaded?.config;
  const expectedDataDirectory = path.join(dataHome, 'shieldkit', 'v2-beta-product');
  if (config === null || typeof config !== 'object'
    || config.dataDirectory !== expectedDataDirectory
    || typeof config.deploymentDirectory !== 'string'
    || !path.isAbsolute(config.deploymentDirectory)
    || path.normalize(config.deploymentDirectory) !== config.deploymentDirectory
    || config.deploymentDirectory !== path.join(expectedDataDirectory, 'deployment')) {
    migrationFail('validated PF10 product config does not expose the deterministic deployment authority');
  }
  return config;
}

function receiptFromAuthority({ dataHome, design, loadConfig, loadGenesis, assertGenesis = null }) {
  const sourceDataHome = absoluteDataHome(dataHome);
  assertPf10Design(design);
  let config;
  let genesis;
  try {
    config = validateProductConfig(loadConfig({ dataHome: sourceDataHome }), sourceDataHome);
    genesis = loadGenesis({ deploymentDirectory: config.deploymentDirectory });
    if (assertGenesis !== null) assertGenesis(genesis);
  } catch (error) {
    if (error?.code === ERROR_CODES.MIGRATION_REQUIRED) throw error;
    migrationFail(
      'migration blocked: PF10 product config or committed zero-conf deployment authority could not be opened read-only',
      { causeCode: typeof error?.code === 'string' ? error.code : null },
    );
  }
  try {
    const profileId = assertProfileId(genesis?.profileId, 'committed PF10 profileId');
    const instanceId = assertInstanceId(genesis?.instanceId, 'committed PF10 instanceId');
    const genesisDescriptorHash = genesis?.zeroConfEvidenceSha256;
    if (!HASH.test(genesisDescriptorHash)
      || !HASH.test(genesis?.genesisOutpoint?.txid)
      || genesis?.genesisOutpoint?.vout !== 0) {
      migrationFail('migration blocked: committed PF10 genesis capability lacks the exact descriptor/zero-conf anchor');
    }
    // `zeroConfEvidenceSha256` is the product context's descriptor binding:
    // beta-product-context requires runtime.descriptorSha256 to equal it.
    return Object.freeze({
      schema: 'shieldkit-pf10-legacy-migration-receipt/v1',
      backendId: PF10.backendId,
      designId: PF10.id,
      profileId,
      instanceId,
      network: NETWORKS.chipnet.networkId,
      genesisDescriptorHash,
      genesisOutpoint: Object.freeze({ txid: genesis.genesisOutpoint.txid, vout: 0 }),
      sourceDataHome,
      sourceDataDirectory: config.dataDirectory,
    });
  } catch (error) {
    if (error?.code === ERROR_CODES.MIGRATION_REQUIRED) throw error;
    migrationFail('migration blocked: PF10 committed deployment identity is malformed');
  }
}

/**
 * Read a PF10 legacy home through the product's authority-bearing APIs.
 * No RPC, prover, wallet, journal mutation, or filesystem mutation occurs.
 */
export function derivePf10LegacyMigrationReceipt({ dataHome, design } = {}) {
  return receiptFromAuthority({
    dataHome,
    design,
    loadConfig: loadV2BetaProductConfig,
    loadGenesis: loadV2BetaChipnetCommittedGenesis,
    assertGenesis: assertV2BetaChipnetCommittedGenesisCapability,
  });
}

/** Explicit test seam. Production callers must use the branded product APIs above. */
export function derivePf10LegacyMigrationReceiptForTest({ dataHome, design, loadConfig, loadGenesis } = {}) {
  if (typeof loadConfig !== 'function' || typeof loadGenesis !== 'function') {
    migrationFail('migration test seam requires config and committed-genesis loaders');
  }
  return receiptFromAuthority({ dataHome, design, loadConfig, loadGenesis });
}
