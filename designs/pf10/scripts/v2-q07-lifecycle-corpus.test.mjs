import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, linkSync, mkdtempSync, readFileSync, rmSync, statSync,
  symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../packages/profile/load.mjs';
import { decodeActionPacket } from '../packages/action/v2/packet.mjs';
import { recoverDirectV2Output } from '../packages/action/v2/notes.mjs';
import { applyDirectV2Transition, createDirectV2PoolModel } from '../packages/action/v2/transition.mjs';
import {
  V2_Q07_LIFECYCLE_CORPUS_SCHEMA, V2_Q07_LIFECYCLE_TRANSCRIPT_DOMAIN, V2Q07LifecycleCorpusError,
  createQ07LifecycleFixtureContextForTest,
  parseQ07LifecycleCorpusArguments, verifyQ07LifecycleCorpusForTest,
  writeQ07LifecycleCorpus, writeQ07LifecycleCorpusForTest,
} from './v2-q07-lifecycle-corpus.mjs';

const COUNT = 3;
const LOCKED_FIXTURE_ACTION_COUNTS = Object.freeze([3, 33, 64]);
const context = Object.freeze({ denominationSats: '10000000' });
function lockedRustFixture(actionCount) { return new URL(`../crates/shieldkit-v2-recovery/tests/fixtures/q07-lifecycle-${actionCount}.ndjson`, import.meta.url); }
function fixture(t, prefix = 'q07-lifecycle-', actionCount = COUNT) {
  const directory = mkdtempSync(join(tmpdir(), prefix)); chmodSync(directory, 0o700);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const written = writeQ07LifecycleCorpusForTest({ outputDirectory: directory, actionCount });
  return { directory, ...written };
}
function records(path) { return readFileSync(path, 'utf8').trimEnd().split('\n').map((line) => JSON.parse(line)); }
function rewrite(path, mutate) {
  const result = mutate(records(path));
  writeFileSync(path, `${result.map(canonicalJson).join('\n')}\n`, { mode: 0o600 }); chmodSync(path, 0o600);
}
function cryptoAccount(account) { return { address: account.address, spendSecret: account.spendSecret, incomingViewSecret: account.incomingViewSecret }; }
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function actionTranscript(previous, record) {
  const { actionTranscriptSha256: _ignored, ...payload } = record;
  return createHash('sha256').update(V2_Q07_LIFECYCLE_TRANSCRIPT_DOMAIN, 'utf8').update(Buffer.from(previous, 'hex')).update(canonicalJson(payload), 'utf8').digest('hex');
}

test('Q07 lifecycle corpus is deterministic, securely published, and replayable without a qualification claim', (t) => {
  const first = fixture(t, 'q07-lifecycle-a-');
  const secondDirectory = mkdtempSync(join(tmpdir(), 'q07-lifecycle-b-')); chmodSync(secondDirectory, 0o700); t.after(() => rmSync(secondDirectory, { recursive: true, force: true }));
  const second = writeQ07LifecycleCorpusForTest({ outputDirectory: secondDirectory, actionCount: COUNT });
  const verified = verifyQ07LifecycleCorpusForTest({ path: first.path, actionCount: COUNT });
  assert.equal(first.schema, V2_Q07_LIFECYCLE_CORPUS_SCHEMA);
  assert.equal(first.fileSha256, second.fileSha256);
  assert.equal(verified.fileSha256, first.fileSha256);
  assert.equal(verified.actionCount, String(COUNT));
  assert.equal(verified.chainAuthenticated, false);
  assert.equal(verified.q07Qualified, false);
  assert.equal(statSync(first.path).mode & 0o777, 0o600);
  const [header, ...tail] = records(first.path);
  assert.equal(header.account.credentialsClassification, 'explicit-public-deterministic-qualification-only-non-operational');
  assert.equal(header.networkId, '2');
  assert.equal(tail.at(-1).recordCount, String(COUNT + 2));
});

test('Q07 locked Rust fixtures are byte-for-byte generated test-only non-chain corpora', (t) => {
  for (const actionCount of LOCKED_FIXTURE_ACTION_COUNTS) {
    const subject = fixture(t, `q07-locked-rust-fixture-${actionCount}-`, actionCount);
    const verified = verifyQ07LifecycleCorpusForTest({ path: subject.path, actionCount });
    assert.deepEqual(readFileSync(subject.path), readFileSync(lockedRustFixture(actionCount)), `locked ${actionCount}-action fixture`);
    assert.equal(verified.actionCount, String(actionCount));
    assert.equal(verified.chainAuthenticated, false);
    assert.equal(verified.q07Qualified, false);
    assert.equal(verified.qualification, 'test-only-nonqualifying');
  }
});

test('Q07 reduced corpus differentially agrees with the immutable transition model', (t) => {
  const subject = fixture(t); const [header, ...tail] = records(subject.path); const actions = tail.slice(0, -1);
  let model = createDirectV2PoolModel({ profileId: header.profileId, maximumLiveNotes: header.maximumLiveNotes, denominationSats: header.denominationSats });
  let live = null;
  for (const row of actions) {
    const decoded = decodeActionPacket(Buffer.from(row.packetHex, 'hex'), context);
    const input = {
      kind: decoded.kind, networkId: decoded.networkId, profileId: header.profileId, instanceId: header.instanceId,
      denominationSats: header.denominationSats, preState: model.state, noteTree: model.noteTree,
      nullifierTree: model.nullifierTree, transactionContextHash: decoded.transactionContextHash,
      expectedPostState: decoded.postState,
      ...(decoded.kind === 'deposit' ? { output: { outputNoteLeaf: decoded.outputNoteLeaf, encryptedRecord: decoded.encryptedRecord } } : decoded.kind === 'transfer' ? {
        output: { outputNoteLeaf: decoded.outputNoteLeaf, encryptedRecord: decoded.encryptedRecord },
        spend: { inputNoteLeaf: live.outputNoteLeaf, noteIndex: live.noteIndex, publicNullifier: decoded.publicNullifier },
      } : {
        spend: { inputNoteLeaf: live.outputNoteLeaf, noteIndex: live.noteIndex, publicNullifier: decoded.publicNullifier },
        withdrawalLockingBytecodeHash: decoded.withdrawalLockingBytecodeHash,
      }),
    };
    const result = applyDirectV2Transition(input);
    assert.deepEqual(result.packet, Buffer.from(row.packetHex, 'hex'));
    if (decoded.kind !== 'withdrawal') {
      const note = recoverDirectV2Output({ account: cryptoAccount(header.account), outputNoteLeaf: decoded.outputNoteLeaf, encryptedRecord: decoded.encryptedRecord });
      live = { ...note, noteIndex: String(BigInt(decoded.postState.noteCount) - 1n) };
    } else live = null;
    model = result;
  }
  assert.equal(model.state.noteCount, '2'); assert.equal(model.state.nullifierCount, '2');
  assert.equal(model.state.reserveSats, '0'); assert.equal(model.state.actionSequence, '3');
});

test('Q07 SDC2 fixture commits the instanceId-category state NFT prefixes', (t) => {
  const subject = fixture(t); const [header, first] = records(subject.path); const packet = decodeActionPacket(Buffer.from(first.packetHex, 'hex'), context);
  const exact = createQ07LifecycleFixtureContextForTest({ kind: packet.kind, ordinal: 1, preState: packet.preState, postState: packet.postState });
  const alien = createQ07LifecycleFixtureContextForTest({ kind: packet.kind, ordinal: 1, preState: packet.preState, postState: packet.postState, stateCategory: '11'.repeat(32) });
  assert.equal(exact.bytes.toString('hex'), first.contextHex);
  assert.notEqual(alien.bytes.toString('hex'), first.contextHex);
  assert.notEqual(alien.hash, first.contextSha256);
  assert.equal(header.instanceId.length, 64);
});

test('Q07 verifier rejects a transcript-rebound withdrawal packet whose payout lock hash differs from SDC2', (t) => {
  const subject = fixture(t); rewrite(subject.path, (lines) => {
    const withdrawal = lines[3]; const packet = Buffer.from(withdrawal.packetHex, 'hex'); packet.fill(0, 488, 520);
    withdrawal.packetHex = packet.toString('hex'); withdrawal.packetSha256 = hash(packet);
    withdrawal.actionTranscriptSha256 = actionTranscript(lines[2].actionTranscriptSha256, withdrawal);
    const end = lines.at(-1); end.actionTranscriptSha256 = withdrawal.actionTranscriptSha256;
    end.bodySha256 = hash(Buffer.from(lines.slice(0, -1).map(canonicalJson).join('\n') + '\n', 'utf8'));
    return lines;
  });
  assert.throws(() => verifyQ07LifecycleCorpusForTest({ path: subject.path, actionCount: COUNT }), /withdrawal locking-bytecode hash/u);
});

test('Q07 verifier rejects truncation, reorder, duplicate, extra, packet/context/state/record/end mutations', (t) => {
  const cases = [
    ['packet', lines => { lines[1].packetHex = `00${lines[1].packetHex.slice(2)}`; return lines; }, /hash mismatch|packet is invalid/u],
    ['context', lines => { lines[1].contextHex = `00${lines[1].contextHex.slice(2)}`; return lines; }, /hash mismatch|context/u],
    ['state', lines => { const packet = Buffer.from(lines[1].packetHex, 'hex'); packet[140] ^= 1; lines[1].packetHex = packet.toString('hex'); return lines; }, /hash mismatch/u],
    ['record', lines => { lines[1].kind = 'transfer'; return lines; }, /kind is invalid|transcript/u],
    ['end', lines => { lines.at(-1).terminalStateSha256 = '0'.repeat(64); return lines; }, /terminal state mismatch/u],
    ['reorder', lines => { [lines[1], lines[2]] = [lines[2], lines[1]]; return lines; }, /ordinal/u],
    ['duplicate', lines => { lines.splice(2, 0, structuredClone(lines[1])); return lines; }, /ordinal/u],
    ['extra', lines => { lines.push(structuredClone(lines.at(-1))); return lines; }, /records after end|extra/u],
  ];
  for (const [name, mutate, pattern] of cases) {
    const subject = fixture(t, `q07-${name}-`); rewrite(subject.path, mutate);
    assert.throws(() => verifyQ07LifecycleCorpusForTest({ path: subject.path, actionCount: COUNT }), pattern, name);
  }
  const truncated = fixture(t, 'q07-truncate-'); const bytes = readFileSync(truncated.path); writeFileSync(truncated.path, bytes.subarray(0, -1), { mode: 0o600 });
  assert.throws(() => verifyQ07LifecycleCorpusForTest({ path: truncated.path, actionCount: COUNT }), /newline|truncated/u);
});

test('Q07 corpus refuses unsafe paths, overwrite, and reduced CLI knobs', (t) => {
  const subject = fixture(t); assert.throws(() => writeQ07LifecycleCorpusForTest({ outputDirectory: subject.directory, actionCount: COUNT }), /overwrite/u);
  const linked = join(subject.directory, 'linked.ndjson'); symlinkSync(subject.path, linked);
  assert.throws(() => verifyQ07LifecycleCorpusForTest({ path: linked, actionCount: COUNT }), V2Q07LifecycleCorpusError);
  const hard = join(subject.directory, 'hard.ndjson'); linkSync(subject.path, hard);
  assert.throws(() => verifyQ07LifecycleCorpusForTest({ path: hard, actionCount: COUNT }), /single-link/u);
  assert.throws(() => parseQ07LifecycleCorpusArguments(['--output-directory', '/tmp', '--action-count', '3']), V2Q07LifecycleCorpusError);
  assert.throws(() => parseQ07LifecycleCorpusArguments(['--output-directory', '/tmp', '--quick']), V2Q07LifecycleCorpusError);
  assert.throws(() => writeQ07LifecycleCorpus({ outputDirectory: subject.directory, actionCount: 3 }), /overwrite|unknown/u);
});
