/* Cross-language parity fixture. The TypeScript codec itself imports no JS codec. */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runStrictCodecQualification } from '../strict-codec-qualification.mjs';

const directory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(directory, '../../../../..');
const compilation = spawnSync(
  'npx',
  ['--no-install', 'tsc', '-p', path.join(directory, 'tsconfig.json')],
  {
    cwd: repositoryRoot,
    encoding: 'utf8',
    shell: false,
  },
);
if (compilation.status !== 0) {
  throw new Error(
    `strict TypeScript codec compilation failed:\n${compilation.stdout}${compilation.stderr}`,
  );
}

const {
  actionPacketPublicLimbs: tsLimbs,
  decodeActionPacket: decodeTsPacket,
  decodeStateNft: decodeTsState,
  digestActionPacket: digestTsPacket,
  encodeActionPacket: encodeTsPacket,
  encodeStateNft: encodeTsState,
  internal: tsInternal,
} = await import('../../../../../.codex-build/v2-typescript/codec.js');
const { validateStateBoundaryVectors } = await import('../../../../../.codex-build/v2-typescript/boundary-vectors.js');
await import('../../../../../.codex-build/v2-typescript/codec.test.js');
import {
  actionPacketPublicLimbs as jsLimbs,
  decodeActionPacket as decodeJsPacket,
  encodeActionPacket as encodeJsPacket,
} from '../packet.mjs';
import { decodeStateNftCommitment as decodeJsState, encodeStateNftCommitment as encodeJsState } from '../state.mjs';

const context = Object.freeze({ denominationSats: '10000000' });
const boundaryVectorPath = path.join(directory, '..', 'vectors', 'q01-state-boundary-vectors.jsonl');
validateStateBoundaryVectors(readFileSync(boundaryVectorPath, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line)));
const fr = (value) => value.toString(16).padStart(64, '0');
const hex = (byte) => byte.repeat(32);
const preState = Object.freeze({ profileId: hex('11'), noteRoot: fr(1n), nullifierRoot: fr(2n), noteCount: '0', nullifierCount: '0', maximumLiveNotes: '7', reserveSats: '0', actionSequence: '0' });
const postState = Object.freeze({ ...preState, noteRoot: fr(3n), noteCount: '1', reserveSats: '10000000', actionSequence: '1' });
const packet = Object.freeze({ kind: 'deposit', networkId: 2, instanceId: hex('22'), preState, postState, publicNullifier: hex('00'), outputNoteLeaf: fr(5n), encryptedRecord: Buffer.alloc(128, 0x44), withdrawalLockingBytecodeHash: hex('00'), transactionContextHash: hex('55') });
const equal = (left, right) => assert.equal(tsInternal.bytesToHex(left), Buffer.from(right).toString('hex'));

equal(encodeTsState(preState, context), encodeJsState(preState, context));
assert.deepEqual(decodeTsState(encodeTsState(postState, context), context), decodeJsState(encodeJsState(postState, context), context));
const fromTs = encodeTsPacket(packet, context);
const fromJs = encodeJsPacket(packet, context);
equal(fromTs, fromJs);
equal(encodeTsPacket(decodeTsPacket(fromJs, context), context), fromJs);
equal(encodeJsPacket(decodeJsPacket(fromTs, context), context), fromTs);
assert.deepEqual(tsLimbs(fromJs, context), jsLimbs(fromTs, context));
const qualification = runStrictCodecQualification({
  name: 'typescript', decodeState: decodeTsState, encodeState: encodeTsState,
  decodePacket: decodeTsPacket, encodePacket: encodeTsPacket,
  digestPacket: digestTsPacket,
  packetLimbs: tsLimbs,
});
console.log(`V2_STRICT_CODEC_QUALIFICATION=${JSON.stringify(qualification)}`);
console.log('V2 TypeScript/JavaScript codec parity: passed');
