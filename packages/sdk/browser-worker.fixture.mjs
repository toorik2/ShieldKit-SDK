import { createBrowserWalletSdk } from './.browser-test-bundle.mjs';

const sdk = createBrowserWalletSdk({
  profile: { network: 'chipnet', profileId: `sha256:${'12'.repeat(32)}`, instanceId: `sha256:${'34'.repeat(32)}` },
});
const seed = new Uint8Array(32).fill(7);
const address = await sdk.deriveRecipientAddress(seed);
const sent = await sdk.constructRecipientOutput({ address, kind: 'transfer', slot: 0 });
const note = await sdk.recoverChainOutput({ seed, kind: 'transfer', slot: 0, outputCommitment: sent.output.cm, record: sent.record });
self.postMessage({ recovered: note.cm === sent.output.cm, recordBytes: sent.record.length });
