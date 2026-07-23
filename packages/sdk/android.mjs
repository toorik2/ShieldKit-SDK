// Android is a typed JavaScript binding boundary. This module makes the
// required runtime surface explicit; it does not claim device qualification.
import { WalletSdkError, createBrowserWalletSdk, createProfileCoordinates } from './browser.mjs';

const fail = (code, message) => { throw new WalletSdkError(code, message); };
const exactKeys = (value, label, expected) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object') fail('INVALID_OBJECT', `${label} must be an object`);
  const actual = Object.keys(value).sort(); const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) fail('UNKNOWN_PROPERTY', `${label} has missing or unknown properties`);
};

/** Validate the minimum Android JS bridge contract required by portable V1 recovery. */
export function assertAndroidRuntimeContract(value) {
  exactKeys(value, 'Android runtime contract', ['bigInt', 'esModules', 'platform', 'uint8Array', 'webCryptoGetRandomValues']);
  if (value.platform !== 'android' || value.bigInt !== true || value.esModules !== true || value.uint8Array !== true || value.webCryptoGetRandomValues !== true) {
    fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android requires BigInt, ESM, Uint8Array, and WebCrypto getRandomValues');
  }
  return Object.freeze({ ...value });
}

/** Create an Android-bound portable recovery SDK after checking the JS contract. */
export function createAndroidWalletSdk(value) {
  exactKeys(value, 'Android wallet SDK input', ['profile', 'runtime']);
  const profile = createProfileCoordinates(value.profile); const runtime = assertAndroidRuntimeContract(value.runtime);
  const portable = createBrowserWalletSdk({ profile });
  return Object.freeze({
    ...portable,
    schema: 'shield.cash/android-wallet-sdk/v1',
    runtime,
    qualification: 'Android JavaScript binding contract only; no emulator, device, proving-performance, or app-RSS qualification claim',
  });
}
