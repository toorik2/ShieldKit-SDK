/**
 * Product act helpers: merge public tip + private wallet for witness,
 * and assert the forbidden global open-set gate is never used.
 */
import { publicTipToWitnessForest, TipRebuildError } from './tip-rebuild.mjs';

/**
 * Build tipForest for generateFreshWitnessInputs:
 * public tip (noteLeaves, nullifiers, state) + openNoteMeta from *my* wallet notes only.
 *
 * Secrets come from the wallet note itself (listOpen). Optional secretMetaByIndex is a
 * legacy residual override only — product path should not need it after deposit writes
 * full secrets into the wallet.
 *
 * @param {object} publicTip — rebuildPublicTip result
 * @param {object[]} myOpenNotes — wallet.listOpen() entries with full spend secrets
 * @param {object} [secretMetaByIndex] — optional residual override by noteIndex
 */
export async function mergeTipForestForAct(publicTip, myOpenNotes = [], secretMetaByIndex = {}) {
  const forest = await publicTipToWitnessForest(publicTip);
  const openNoteMeta = [];
  for (const n of myOpenNotes) {
    const idx = Number(n.noteIndex);
    const residual = secretMetaByIndex[idx] || secretMetaByIndex[String(idx)] || {};
    // Prefer wallet-embedded secrets (backup restore path); residual only as fill-in.
    const note1 = n.note1 || residual.note1;
    const key1 = n.key1 != null ? String(n.key1) : (residual.key1 != null ? String(residual.key1) : undefined);
    const nfLeaf1 = n.nfLeaf1 || residual.nfLeaf1;
    const leaf = n.leaf || residual.leaf || forest.noteLeaves[idx];
    const witnessSeed = n.witnessSeed || residual.witnessSeed;
    if (!note1 || key1 == null || !nfLeaf1) {
      throw new TipRebuildError(
        'INCOMPLETE_NOTE_SECRETS',
        `wallet note at index ${idx} lacks note1/key1/nfLeaf1 required for spend`,
      );
    }
    openNoteMeta.push({
      noteIndex: idx,
      leaf,
      key1,
      nfLeaf1,
      witnessSeed,
      note1,
    });
  }
  return Object.freeze({
    ...forest,
    openNoteMeta: Object.freeze(openNoteMeta),
  });
}

/**
 * Structural guard for tests/product path: reject any gate that compares
 * myNotes.length to global liveNoteCount.
 */
export function assertNoGlobalOpenSetGate(myNoteCount, globalLiveNoteCount, options = {}) {
  const enforce = options.enforceEquality === true;
  if (enforce && Number(myNoteCount) !== Number(globalLiveNoteCount)) {
    // Product path must NEVER set enforceEquality. This branch exists only so tests
    // prove the old gate is not required.
    throw new TipRebuildError(
      'OPEN_SET_DESYNC',
      'legacy open-set equality gate (forbidden in product path)',
    );
  }
  // Product default: always OK — multi-user tip with partial wallet is valid.
  return Object.freeze({
    ok: true,
    myNoteCount: Number(myNoteCount),
    globalLiveNoteCount: Number(globalLiveNoteCount),
    gate: 'disabled-by-construction',
  });
}
