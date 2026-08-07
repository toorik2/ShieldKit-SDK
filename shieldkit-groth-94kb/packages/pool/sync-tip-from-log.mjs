/**
 * Product tip sync: ordered raw genesis+settles → public tip → witness forest.
 * Secrets for *my* open notes come from residual openNoteMeta / wallet, never from strangers.
 */
import { createHash } from 'node:crypto';
import {
  rebuildPublicTipFromRawTransactions,
  publicTipToWitnessForest,
  decodeTipNftFields,
} from './tip-rebuild.mjs';
import { mergeTipForestForAct } from './product-api.mjs';

/**
 * @param {{
 *   genesisTransactionId: string,
 *   genesisTransactionHex: string,
 *   settleTransactionHexes: string[],
 *   profileId: string,
 *   instanceId: string,
 *   stateNftCategory: string,
 *   stateLockingBytecodeHex: string,
 *   stateCarrierBaseSatoshis: string,
 *   tipNftCommitmentHex?: string,
 *   myOpenNotes?: object[],
 *   secretMetaByIndex?: object,
 * }} input
 */
export async function syncTipForestFromSettlementLog(input) {
  const lock = Buffer.from(input.stateLockingBytecodeHex, 'hex');
  const stateLockSha256 = createHash('sha256').update(lock).digest('hex');
  const rawTransactions = [
    Buffer.from(input.genesisTransactionHex, 'hex'),
    ...input.settleTransactionHexes.map((h) => Buffer.from(h, 'hex')),
  ].map((b) => Uint8Array.from(b));

  let tipNft;
  if (input.tipNftCommitmentHex) {
    tipNft = decodeTipNftFields(input.tipNftCommitmentHex);
  }

  const publicTip = rebuildPublicTipFromRawTransactions({
    genesisTransactionId: input.genesisTransactionId.replace(/^sha256:/, ''),
    profileId: input.profileId.replace(/^sha256:/, ''),
    instanceId: input.instanceId.replace(/^sha256:/, ''),
    stateNftCategory: input.stateNftCategory.replace(/^sha256:/, '').toLowerCase(),
    stateLockingBytecode: Uint8Array.from(lock),
    stateLockSha256,
    stateCarrierBaseSatoshis: String(input.stateCarrierBaseSatoshis || '1080'),
    rawTransactions,
    tipNft: tipNft
      ? {
        stateCommitment: tipNft.stateCommitment,
        actionSequence: tipNft.actionSequence,
        instanceId: tipNft.instanceId,
      }
      : undefined,
  });

  const forest = await mergeTipForestForAct(
    publicTip,
    input.myOpenNotes || [],
    input.secretMetaByIndex || {},
  );
  const bareForest = await publicTipToWitnessForest(publicTip);
  return Object.freeze({
    publicTip,
    tipForest: forest,
    bareForest,
  });
}
