import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { createPoolEngineV2 } from '../transition.mjs';
import { NETWORK_CHIPNET } from '../constants.mjs';
import {
  createAccountKeys, freshOutputNote, frFromHex, shieldAddress,
} from '../crypto/note.mjs';
import {
  createDurableTreeStore,
  persistEngineTrees,
  restoreEngineTrees,
} from './durable-store.mjs';

const testRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../.cache/v2-direct-tests',
);
mkdirSync(testRoot, { recursive: true });

describe('durable tree store', () => {
  it('commits snapshot mode 0600 and restores engine tip after reload', () => {
    const dir = mkdtempSync(path.join(testRoot, `store-${randomBytes(3).toString('hex')}-`));
    const store = createDurableTreeStore(dir);
    const profileId = createHash('sha256').update('store-p').digest('hex');
    const instanceId = createHash('sha256').update('store-i').digest('hex');
    const eng = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32, noteDepth: 8, nullifierDepth: 8,
    });
    const alice = createAccountKeys();
    const addr = shieldAddress({
      networkId: NETWORK_CHIPNET, profileId, instanceId, account: alice,
    });
    const n = freshOutputNote({
      profileId, instanceId, authority: addr.authority, postActionSequence: 1,
      viewPoint: [frFromHex(alice.V[0]), frFromHex(alice.V[1])],
    });
    eng.deposit({ outputNoteLeaf: n.outputNoteLeaf, encryptedRecord: n.encryptedRecord });
    const tipBefore = eng.tip();
    persistEngineTrees(store, eng);

    assert.equal(statSync(store.paths().snapshotPath).mode & 0o777, 0o600);
    assert.ok(existsSync(store.paths().walPath));

    const eng2 = createPoolEngineV2({
      profileId, instanceId, maximumLiveNotes: 32, noteDepth: 8, nullifierDepth: 8,
    });
    // Empty tip before restore
    assert.equal(eng2.tip().actionSequence, '0');
    assert.equal(restoreEngineTrees(store, eng2), true);
    // Note: engine tip counters live in engine state, not only trees — roots must match
    assert.equal(eng2.noteTree.root(), tipBefore.noteRoot);
    assert.equal(eng2.nullifierTree.root(), tipBefore.nullifierRoot);

    const loaded = store.load();
    assert.equal(loaded.tip.noteRoot, tipBefore.noteRoot);
    assert.equal(loaded.schema, 'shield.cash/v2-direct-tree-store/v1');
  });

  it('appendWal survives and is replayed into load after partial commit epoch', () => {
    const dir = mkdtempSync(path.join(testRoot, `wal-${randomBytes(3).toString('hex')}-`));
    const store = createDurableTreeStore(dir);
    store.commit({ tip: { actionSequence: '0' }, noteTree: null, nullifierTree: null });
    store.appendWal({ op: 'marker', n: 1 });
    const raw = readFileSync(store.paths().walPath, 'utf8');
    assert.match(raw, /"op":"marker"/);
  });
});
