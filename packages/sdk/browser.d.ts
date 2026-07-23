export type HashId = `sha256:${string}`;
export type ActionKind = 'deposit' | 'transfer' | 'withdrawal';
export interface ProfileCoordinates { readonly network: 'chipnet'; readonly profileId: HashId; readonly instanceId: HashId; }
export interface RecipientAddress { readonly schema: 'shield.cash/recipient-address/v1'; readonly profileId: string; readonly instanceId: string; readonly ak: string; readonly recoveryPublicKey: string; }
export interface LocalProverCapability { readonly schema: 'shield.cash/local-prover-capability/v1'; readonly mode: 'local-only'; readonly prove: (request: unknown) => Promise<unknown>; }
export class WalletSdkError extends Error { readonly code: string; }
export function createProfileCoordinates(value: ProfileCoordinates): ProfileCoordinates;
export function requireLocalProverCapability(value: LocalProverCapability): LocalProverCapability;
export function createBrowserWalletSdk(value: { profile: ProfileCoordinates }): Readonly<{
  schema: 'shield.cash/browser-wallet-sdk/v1'; profile: ProfileCoordinates; qualification: string;
  deriveRecipientAddress(seed: Uint8Array): Promise<RecipientAddress>;
  constructRecipientOutput(request: { address: RecipientAddress; kind: Exclude<ActionKind, 'withdrawal'>; slot: number; rng?: { bytes(length: number): Uint8Array } }): Promise<{ output: Record<string, string>; record: Uint8Array }>;
  recoverChainOutput(request: { seed: Uint8Array; kind: ActionKind; slot: number; outputCommitment: string; record: Uint8Array }): Promise<Record<string, string>>;
}>;
