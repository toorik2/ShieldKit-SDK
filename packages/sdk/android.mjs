// Android is a local JavaScript binding boundary. It neither opens a network
// connection nor accepts a remote-prover capability. A runtime self-probe can
// establish that an Android WebView-like engine has the portable recovery
// prerequisites; that is deliberately narrower than device/prover
// qualification.
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

/**
 * Observe the runtime primitives required by portable recovery in the current
 * Android JavaScript engine. Importing this ESM module is the ESM check; the
 * remaining checks are actively exercised rather than accepted as booleans
 * supplied by an embedding application.
 *
 * `navigator.userAgent` is capability routing metadata, not an authentication
 * boundary. It prevents accidentally treating a desktop/Node test host as
 * Android, but it cannot prove a device model or an app memory budget.
 */
export function probeAndroidRuntime(globals = globalThis) {
  if (globals === null || (typeof globals !== 'object' && typeof globals !== 'function')) {
    fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android runtime global object is unavailable');
  }
  const userAgent = globals.navigator?.userAgent;
  if (typeof userAgent !== 'string' || !/\bAndroid\b/i.test(userAgent)) {
    fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android user agent is required for the detected-runtime entrypoint');
  }
  if (typeof globals.BigInt !== 'function' || globals.BigInt(1) + globals.BigInt(1) !== globals.BigInt(2)) {
    fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android requires working BigInt');
  }
  if (typeof globals.Uint8Array !== 'function') fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android requires Uint8Array');
  const probe = new globals.Uint8Array(16);
  const random = globals.crypto?.getRandomValues;
  if (typeof random !== 'function') fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android requires WebCrypto getRandomValues');
  let returned;
  try { returned = random.call(globals.crypto, probe); }
  catch { fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android WebCrypto getRandomValues failed'); }
  if (returned !== probe || !(probe instanceof globals.Uint8Array)) fail('ANDROID_RUNTIME_UNSUPPORTED', 'Android WebCrypto returned an invalid random buffer');
  return assertAndroidRuntimeContract({ platform: 'android', bigInt: true, esModules: true, uint8Array: true, webCryptoGetRandomValues: true });
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

/** Create the Android facade only after probing the actual current runtime. */
export function createDetectedAndroidWalletSdk(value) {
  exactKeys(value, 'detected Android wallet SDK input', ['profile']);
  return createAndroidWalletSdk({ profile: value.profile, runtime: probeAndroidRuntime() });
}
