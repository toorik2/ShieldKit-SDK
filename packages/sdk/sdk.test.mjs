import assert from 'node:assert/strict';
import test from 'node:test';
import {
  WalletSdkError,
  createBrowserWalletSdk,
  createProfileCoordinates,
  requireLocalProverCapability,
} from './browser.mjs';
import { assertAndroidRuntimeContract, createAndroidWalletSdk } from './android.mjs';
import { createDesktopWalletSdk } from './sdk.mjs';

const profile = Object.freeze({ network: 'chipnet', profileId: `sha256:${'11'.repeat(32)}`, instanceId: `sha256:${'22'.repeat(32)}` });
const rng = (() => { let n = 1; return Object.freeze({ bytes(length) { const out = new Uint8Array(length); out[length - 1] = n++; return out; } }); })();

test('portable wallet is profile/instance-bound and chain recovery accepts exact serialized fields only', async () => {
  const sdk = createBrowserWalletSdk({ profile });
  const seed = new Uint8Array(32).fill(7);
  const address = await sdk.deriveRecipientAddress(seed);
  const sent = await sdk.constructRecipientOutput({ address, kind: 'transfer', slot: 0, rng });
  const recovered = await sdk.recoverChainOutput({ seed, kind: 'transfer', slot: 0, outputCommitment: sent.output.cm, record: sent.record });
  assert.equal(recovered.cm, sent.output.cm);
  await assert.rejects(
    () => sdk.constructRecipientOutput({ address: { ...address, instanceId: '33'.repeat(32) }, kind: 'transfer', slot: 0, rng }),
    (error) => error instanceof WalletSdkError && error.code === 'PROFILE_MISMATCH',
  );
  await assert.rejects(
    () => sdk.recoverChainOutput({ seed, kind: 'transfer', slot: 0, outputCommitment: sent.output.cm, record: sent.record, unexpected: true }),
    (error) => error instanceof WalletSdkError && error.code === 'UNKNOWN_PROPERTY',
  );
});

test('profile, local prover, and Android contracts fail closed', () => {
  assert.deepEqual(createProfileCoordinates(profile), profile);
  assert.throws(() => createProfileCoordinates({ ...profile, network: 'mainnet' }), /only Chipnet/);
  assert.throws(() => requireLocalProverCapability({ schema: 'shield.cash/local-prover-capability/v1', mode: 'remote', prove: async () => ({}) }), /local-only/);
  const capability = requireLocalProverCapability({ schema: 'shield.cash/local-prover-capability/v1', mode: 'local-only', prove: async () => ({}) });
  assert.equal(capability.mode, 'local-only');
  const runtime = { platform: 'android', bigInt: true, esModules: true, uint8Array: true, webCryptoGetRandomValues: true };
  assert.deepEqual(assertAndroidRuntimeContract(runtime), runtime);
  assert.equal(createAndroidWalletSdk({ profile, runtime }).schema, 'shield.cash/android-wallet-sdk/v1');
  assert.throws(() => assertAndroidRuntimeContract({ ...runtime, bigInt: false }), /requires BigInt/);
});

test('desktop facade rejects unauthenticated profile paths before exposing planning methods', async () => {
  await assert.rejects(
    () => createDesktopWalletSdk({ bundleDirectory: '/definitely/not/a/profile', expectedProfile: profile }),
    (error) => error instanceof WalletSdkError && error.code === 'PROFILE_AUTHENTICATION_FAILED',
  );
});
