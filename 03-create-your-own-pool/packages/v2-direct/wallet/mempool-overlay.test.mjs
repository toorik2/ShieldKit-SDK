import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';
import { createMempoolOverlay } from './mempool-overlay.mjs';

const testRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../.cache/v2-direct-tests',
);
mkdirSync(testRoot, { recursive: true });

describe('mempool overlay', () => {
  it('tracks mempool entries, projects tip, drops lost parents, 0600 file', () => {
    const dir = mkdtempSync(path.join(testRoot, `ov-${randomBytes(3).toString('hex')}-`));
    const ov = createMempoolOverlay(dir);
    const txid = 'ab'.repeat(32);
    const parent = 'cd'.repeat(32);
    ov.addEntry({
      txid,
      kind: 'deposit',
      digest: '11'.repeat(32),
      spentStateOutpoint: `${'00'.repeat(32)}:8`,
      createdStateOutpoint: `${txid}:8`,
      parents: [parent],
    });
    assert.equal(statSync(ov.path).mode & 0o777, 0o600);
    assert.equal(ov.list().length, 1);
    const proj = ov.projectTip({ actionSequence: '0' });
    assert.equal(proj.overlayDepth, 1);
    assert.deepEqual(proj.pendingTxids, [txid]);

    // parent lost → drop
    const dropped = ov.dropLostParents([txid]); // parent not live
    assert.equal(dropped, 1);
    assert.equal(ov.list().length, 0);

    ov.addEntry({ txid, kind: 'transfer', parents: [] });
    assert.equal(ov.markConfirmed(txid), true);
    assert.equal(ov.list().length, 0);
  });

  it('rejects non-64-char txid', () => {
    const dir = mkdtempSync(path.join(testRoot, `ovb-${randomBytes(3).toString('hex')}-`));
    const ov = createMempoolOverlay(dir);
    assert.throws(() => ov.addEntry({ txid: 'deadbeef', kind: 'deposit' }), /64 hex/);
  });
});
