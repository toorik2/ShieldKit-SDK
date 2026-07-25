/** Product TypeScript surface — createKit only. */
export type NetworkName = 'chipnet' | 'mainnet';

export interface ProfileCoordinates {
  readonly network: NetworkName | string;
  readonly profileId: string;
  readonly instanceId: string;
}

export interface KitConfig {
  readonly network?: NetworkName | string;
  readonly bundleDirectory: string;
  readonly expectedProfile: ProfileCoordinates;
  readonly mainnetAcknowledged?: boolean;
  readonly allowDevelopmentOnMainnet?: boolean;
  readonly broadcast?: (hex: string) => Promise<string> | string;
}

export interface FundingRequest {
  readonly kind: 'deposit' | 'transfer' | 'withdrawal';
  readonly bindingCarrierBaseValueSatoshis: string;
  readonly bindingLockingBytecode: string;
  readonly fundingOutpointIndex: string;
  readonly fundingOutpointTransactionHashWire: string;
  readonly fundingPublicKey: string;
  readonly fundingSourceValueSatoshis: string;
  readonly settlementFeeFundingSatoshis: string;
}

export declare class KitError extends Error {
  readonly code: string;
  constructor(code: string, message: string);
}

export declare function createKit(config: KitConfig): Promise<Readonly<{
  schema: string;
  network: { name: string; networkId: number };
  profile: ProfileCoordinates & { bundleDirectory: string; setupMode: string };
  qualification: string;
  assertCanBroadcast(): unknown;
  explorerTxUrl(txid: string): string;
  broadcastRaw(hex: string): Promise<string>;
  planCompletePreparation(request: FundingRequest): Promise<unknown>;
  preparationSigningRequest(request: FundingRequest): Promise<unknown>;
  finalizeCompletePreparation(request: FundingRequest, signatureHex: string): Promise<unknown>;
  deriveRecipientAddress: Function;
  constructRecipientOutput: Function;
  recoverChainOutput: Function;
  recoverAuthenticatedHistory: Function;
  serializeHistoryActions: Function;
}>>;

export declare function assertBroadcastAllowed(opts: {
  network: string;
  setupMode?: string;
  mainnetAcknowledged?: boolean;
  allowDevelopmentOnMainnet?: boolean;
}): unknown;

export declare function resolveNetwork(name: string): { name: string; networkId: number };
export declare function explorerTxUrl(network: string, txid: string): string;
export declare function defaultNetworkName(): string;
