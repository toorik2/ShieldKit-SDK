import { constructRecipientOutput, deriveRecipientAddress, recoverRecipientOutput } from './.browser-test-bundle.mjs';

const seed = new Uint8Array(32).fill(7);
const profileId = '12'.repeat(32); const instanceId = '34'.repeat(32);
const address = await deriveRecipientAddress({ seed, profileId, instanceId });
const sent = await constructRecipientOutput({ address, kind: 'transfer', slot: 0 });
const recovered = await recoverRecipientOutput({ seed, profileId, instanceId, kind: 'transfer', slot: 0, outputCommitment: sent.output.cm, record: sent.record });
self.postMessage({ recovered: recovered.cm === sent.output.cm, recordBytes: sent.record.length });
