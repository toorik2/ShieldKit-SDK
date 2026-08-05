import { constructRecipientOutput, deriveRecipientAddress, encodePortableActionPacket, encodePortableActionState, recoverAuthenticatedChainHistory, recoverRecipientOutput } from './.browser-test-bundle.mjs';

const seed = new Uint8Array(32).fill(7);
const profileId = '12'.repeat(32); const instanceId = '34'.repeat(32);
const address = await deriveRecipientAddress({ seed, profileId, instanceId });
const sent = await constructRecipientOutput({ address, kind: 'deposit', slot: 0 });
const recovered = await recoverRecipientOutput({ seed, profileId, instanceId, kind: 'deposit', slot: 0, outputCommitment: sent.output.cm, record: sent.record });
const state = (sequence, next, live, reserve, marker) => ({ profileId, instanceId, noteRoot: marker.repeat(64), nullifierRoot: marker.repeat(64), nextLeafIndex: String(next), actionSequence: String(sequence), liveNoteCount: String(live), reserveSats: String(reserve), maximumReserve: '10000000', stateCommitment: marker.repeat(64) });
const initial = state(0, 0, 0, 0, '1'); const terminal = state(1, 1, 1, 10000000, '2');
const packet = encodePortableActionPacket({ kind: 'deposit', networkId: 2, preState: initial, postState: terminal, inputCommitment: '0'.repeat(64), inputNullifier: '0'.repeat(64), outputCommitment: sent.output.cm, outputRecord: sent.record, boundaryAmount: '10000000', withdrawalScriptHash: '0'.repeat(64), transactionContextDigest: '3'.repeat(64) });
const history = await recoverAuthenticatedChainHistory({ accountSeed: seed, profileId, instanceId, history: { initialState: encodePortableActionState(initial), terminalState: encodePortableActionState(terminal), packets: [packet] } });
self.postMessage({ recovered: recovered.cm === sent.output.cm && history.unspentNotes.length === 1, recordBytes: sent.record.length });
