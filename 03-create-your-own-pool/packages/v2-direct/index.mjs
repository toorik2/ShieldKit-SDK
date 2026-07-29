/** @shieldkit/v2-direct public surface */
export * from './constants.mjs';
export {
  encodePoolStateV2,
  decodePoolStateV2,
  normalizePoolStateV2,
  emptyGenesisStateFields,
} from './state.mjs';
export {
  encodeActionPacketV2,
  decodeActionPacketV2,
  digestActionPacketV2,
  actionPacketPublicLimbsV2,
  actionPacketPublicLimbsHexV2,
} from './packet.mjs';
export {
  applyPublicStateDelta,
  createPoolEngineV2,
} from './transition.mjs';
export { createNoteTree, emptyNoteRoot } from './trees/note-tree.mjs';
export {
  createIndexedNullifierTree,
  emptyNullifierRoot,
} from './trees/indexed-nullifier.mjs';
export {
  createAccountKeys,
  freshOutputNote,
  shieldAddress,
  computeNullifier,
  computeNoteCommitment,
} from './crypto/note.mjs';
export {
  planRollingAction,
  selectCarrierCandidate,
  assertBundleSecurityInvariants,
  FUNDING_UTXO_REQUIRED,
} from './covenant/bundle.mjs';
export { createJournal, JOURNAL_STATES } from './wallet/journal.mjs';
export { createNoteWallet } from './wallet/notes.mjs';
export { createMempoolOverlay } from './wallet/mempool-overlay.mjs';
export {
  createDurableTreeStore,
  persistEngineTrees,
  restoreEngineTrees,
} from './trees/durable-store.mjs';
export { createNetworkGate } from './network-gate.mjs';
export {
  provePoolAction,
  resolveCircuitArtifacts,
  CIRCUIT_TREE_DEPTH,
} from './operator/prove-local.mjs';
export {
  bindPinCompatibleTransactionContext,
  measurePacketEcipPinBudget,
  loadCircuitIcAffine,
  PIN_ECIP_MAX_TRY,
} from './operator/pin-compatible-witness.mjs';
export { buildDensfuelForPacket } from './operator/densfuel-build.mjs';
export {
  loadFundingWallet,
  selectFundingUtxoFromList,
  resolveFundingWalletPath,
  generateFundingWalletMaterial,
  saveFundingWalletJson,
  mergeFundingUtxos,
} from './operator/funding-wallet.mjs';
export {
  buildPoolGenesis,
  ensureCategoryVout0,
  randomProfileId,
} from './operator/pool-create.mjs';
export { createChipnetRpc, createLiveNetworkGate } from './operator/chipnet-rpc.mjs';
export {
  recoverFromGenesisLineage,
  applyReorgUndo,
} from './recover/scanner.mjs';
export {
  proveActionV2,
  verifyActionV2,
  buildCircuitInputFromPacket,
  loadSetupPaths,
} from './prove/prove.mjs';
export { setupPoolActionV2DirectDevelopment } from './prove/setup.mjs';
export {
  loadDensfuelArtifacts,
  measureDensfuelFoundation,
  densfuelRollingPlan,
  inspectDensfuelCandidateTx,
} from './covenant/densfuel-settle.mjs';

