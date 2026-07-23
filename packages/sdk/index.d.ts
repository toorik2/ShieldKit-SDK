export * from './browser.mjs';
export interface FundingRequest {
  readonly kind: 'deposit' | 'transfer' | 'withdrawal'; readonly bindingCarrierBaseValueSatoshis: string;
  readonly bindingLockingBytecode: string; readonly fundingOutpointIndex: string;
  readonly fundingOutpointTransactionHashWire: string; readonly fundingPublicKey: string;
  readonly fundingSourceValueSatoshis: string; readonly settlementFeeFundingSatoshis: string;
}
export interface SchnorrSignatureRequest {
  readonly schema: 'shield.cash/bch-schnorr-signature-request/v1'; readonly algorithm: 'bch-schnorr-all-forkid';
  readonly signingSerialization: Uint8Array; readonly signingSerializationHex: string; readonly digest: Uint8Array; readonly digestHex: string;
}
export function createDesktopWalletSdk(value: { bundleDirectory: string; expectedProfile: import('./browser.mjs').ProfileCoordinates }): Promise<Readonly<{
  schema: 'shield.cash/desktop-wallet-sdk/v1'; profile: import('./browser.mjs').ProfileCoordinates & { readonly bundleDirectory: string; readonly setupMode: string; readonly stateNftCategory: string };
  qualification: string; deriveRecipientAddress: ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk>['deriveRecipientAddress'];
  constructRecipientOutput: ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk>['constructRecipientOutput'];
  recoverChainOutput: ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk>['recoverChainOutput'];
  recoverAuthenticatedHistory: ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk>['recoverAuthenticatedHistory'];
  serializeHistoryActions: ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk>['serializeHistoryActions'];
  requireLocalProver(value: import('./browser.mjs').LocalProverCapability): import('./browser.mjs').LocalProverCapability;
  planCompletePreparation(request: FundingRequest): Promise<unknown>;
  preparationSigningRequest(request: FundingRequest): Promise<SchnorrSignatureRequest>;
  finalizeCompletePreparation(request: FundingRequest, signatureHex: string): Promise<unknown>;
  planWitnessBoundSettlements(value: { localProver: import('./browser.mjs').LocalProverCapability; settlements: Record<string, unknown>; withdrawalScriptHash: string; witnessSeed: string }): Promise<unknown>;
  serializeCompleteSettlement(value: Record<string, unknown>): Promise<unknown>;
  planGenesis(value: Record<string, unknown>): Promise<unknown>;
  finalizeGenesis(value: Record<string, unknown>, signatureHex: string): Promise<unknown>;
}>>;
