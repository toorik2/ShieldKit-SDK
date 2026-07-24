import type { ProfileCoordinates } from './browser.mjs';
export interface AndroidRuntimeContract { readonly platform: 'android'; readonly bigInt: true; readonly esModules: true; readonly uint8Array: true; readonly webCryptoGetRandomValues: true; }
export function assertAndroidRuntimeContract(value: AndroidRuntimeContract): AndroidRuntimeContract;
/** Observes the current Android JavaScript runtime; it is not device/prover qualification. */
export function probeAndroidRuntime(globals?: typeof globalThis): AndroidRuntimeContract;
export function createAndroidWalletSdk(value: { profile: ProfileCoordinates; runtime: AndroidRuntimeContract }): ReturnType<typeof import('./browser.mjs').createBrowserWalletSdk> & Readonly<{ schema: 'shield.cash/android-wallet-sdk/v2'; runtime: AndroidRuntimeContract }>;
/** Creates the facade only after `probeAndroidRuntime()` succeeds in the current runtime. */
export function createDetectedAndroidWalletSdk(value: { profile: ProfileCoordinates }): ReturnType<typeof createAndroidWalletSdk>;
