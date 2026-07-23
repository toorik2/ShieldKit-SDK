import type { ProfileCoordinates } from './browser.mjs';
export interface AndroidRuntimeContract { readonly platform: 'android'; readonly bigInt: true; readonly esModules: true; readonly uint8Array: true; readonly webCryptoGetRandomValues: true; }
export function assertAndroidRuntimeContract(value: AndroidRuntimeContract): AndroidRuntimeContract;
export function createAndroidWalletSdk(value: { profile: ProfileCoordinates; runtime: AndroidRuntimeContract }): ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk> & Readonly<{ schema: 'shield.cash/android-wallet-sdk/v1'; runtime: AndroidRuntimeContract }>;
