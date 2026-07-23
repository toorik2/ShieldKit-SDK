export type HashId = `sha256:${string}`;
export type ActionKind = 'deposit' | 'transfer' | 'withdrawal';
export interface ProfileCoordinates { readonly network: 'chipnet'; readonly profileId: HashId; readonly instanceId: HashId; }
export interface RecipientAddress { readonly schema: 'shield.cash/recipient-address/v1'; readonly profileId: string; readonly instanceId: string; readonly ak: string; readonly recoveryPublicKey: string; }
export interface ActionState { readonly profileId: string; readonly instanceId: string; readonly noteRoot: string; readonly nullifierRoot: string; readonly nextLeafIndex: string; readonly actionSequence: string; readonly liveNoteCount: string; readonly reserveSats: string; readonly maximumReserve: string; readonly stateCommitment: string; }
export interface ChainHistory { readonly initialState: Uint8Array; readonly terminalState: Uint8Array; readonly packets: readonly Uint8Array[]; }
export interface DecodedChainHistory { readonly initialState: Uint8Array; readonly terminalState: Uint8Array; readonly actions: readonly Record<string, unknown>[]; }
export interface RecoveredNote { readonly ak: string; readonly cm: string; readonly nf: string; readonly rho: string; readonly r: string; readonly sk: string; readonly noteIndex: string; readonly createdAtActionSequence: string; readonly spentAtActionSequence: string | null; }
export interface ChainHistoryRecovery { readonly schema: 'shield.cash/chain-history-recovery/v1'; readonly qualification: string; readonly profileId: string; readonly instanceId: string; readonly initialState: ActionState; readonly terminalState: ActionState; readonly notes: readonly RecoveredNote[]; readonly unspentNotes: readonly RecoveredNote[]; readonly spentNullifiers: readonly string[]; }
export interface LocalProverCapability { readonly schema: 'shield.cash/local-prover-capability/v1'; readonly mode: 'local-only'; readonly prove: (request: unknown) => Promise<unknown>; }
export class WalletSdkError extends Error { readonly code: string; }
export function createProfileCoordinates(value: ProfileCoordinates): ProfileCoordinates;
export function requireLocalProverCapability(value: LocalProverCapability): LocalProverCapability;
export function createBrowserWalletSdk(value: { profile: ProfileCoordinates }): Readonly<{
  schema: 'shield.cash/browser-wallet-sdk/v1'; profile: ProfileCoordinates; qualification: string;
  deriveRecipientAddress(seed: Uint8Array): Promise<RecipientAddress>;
  constructRecipientOutput(request: { address: RecipientAddress; kind: Exclude<ActionKind, 'withdrawal'>; slot: number; rng?: { bytes(length: number): Uint8Array } }): Promise<{ output: Record<string, string>; record: Uint8Array }>;
  recoverChainOutput(request: { seed: Uint8Array; kind: ActionKind; slot: number; outputCommitment: string; record: Uint8Array }): Promise<Record<string, string>>;
  recoverAuthenticatedHistory(request: { accountSeed: Uint8Array; history: ChainHistory | DecodedChainHistory }): Promise<ChainHistoryRecovery>;
  serializeHistoryActions(actions: readonly Record<string, unknown>[]): readonly Uint8Array[];
}>;
