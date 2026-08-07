/**
 * Canonical-chain reconstruction helpers (pool sync).
 * Tip is observation only — never identity.
 */

import { createHash } from 'node:crypto';

/**
 * Reconstruct ordered history from a ChainReader + cursor.
 * @param {object} chainReader - branded ChainReader
 * @param {{ cursor?: string|null, expectedGenesis?: string|null, knownTxids?: string[] }} opts
 */
export async function reconstructChainHistory(chainReader, {
  cursor = null,
  expectedGenesis = null,
  knownTxids = [],
} = {}) {
  if (!chainReader || chainReader.kind !== 'ChainReader') {
    throw new Error('ChainReader capability required');
  }

  // Authentication is an active RPC observation (block 0 + chain label), not
  // a caller-supplied genesis string. A list of txids is only an observation
  // set; it cannot reconstruct canonical pool lineage.
  if (typeof chainReader.authenticate !== 'function') {
    throw new Error('authenticated ChainReader capability required');
  }
  await chainReader.authenticate();

  // Verify genesis when both sides declare it
  if (expectedGenesis && chainReader.genesisHash
    && expectedGenesis !== chainReader.genesisHash) {
    const err = new Error(
      `genesis mismatch: home expects ${expectedGenesis}, reader has ${chainReader.genesisHash}`,
    );
    err.code = 'GENESIS_MISMATCH';
    throw err;
  }

  const tip = await chainReader.getTip();
  if (!tip || tip.kind !== 'tip') {
    throw new Error('chain reader did not return a tip observation');
  }

  const observations = [];
  const missing = [];
  for (const txid of knownTxids) {
    try {
      const raw = await chainReader.getRawTransaction(txid, true);
      const hex = typeof raw === 'string' ? raw : raw?.hex;
      observations.push({
        txid,
        present: true,
        confirmations: typeof raw === 'object' ? (raw.confirmations ?? null) : null,
        hexPresent: typeof hex === 'string',
      });
    } catch {
      missing.push(txid);
      observations.push({ txid, present: false, confirmations: null, hexPresent: false });
    }
  }

  const deltaHash = createHash('sha256')
    .update(JSON.stringify({ tip, observations, cursor }))
    .digest('hex');

  return Object.freeze({
    schema: 'shieldkit-chain-history-delta/v1',
    tip: Object.freeze({ ...tip }), // observation, not identity
    cursor,
    genesisHash: chainReader.genesisHash ?? expectedGenesis ?? null,
    observations: Object.freeze(observations),
    missing: Object.freeze(missing),
    reconstructed: false,
    canonicalLineageVerified: false,
    lineageStatus: 'observation-only; known transaction ids do not prove canonical pool lineage',
    deltaHash,
  });
}
