import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, rmSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, after } from 'node:test';
import {
  loadFundingWallet,
  selectFundingUtxoFromList,
  resolveFundingWalletPath,
} from './funding-wallet.mjs';

// Prefer worktree cache over /tmp (user quota on /tmp is often exhausted).
const testRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../../.cache/v2-direct-tests',
);
mkdirSync(testRoot, { recursive: true });

const dirs = [];
function tmp() {
  const d = mkdtempSync(path.join(testRoot, 'v2-fund-'));
  dirs.push(d);
  return d;
}
after(() => {
  for (const d of dirs) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* */ }
  }
});

describe('funding-wallet blank-machine loader', () => {
  it('refuses missing wallet', () => {
    assert.throws(
      () => loadFundingWallet({ home: tmp() }),
      (e) => e.code === 'FUNDING_WALLET_MISSING',
    );
  });

  it('loads from home funding-wallet.json', () => {
    const home = tmp();
    const p = path.join(home, 'funding-wallet.json');
    writeFileSync(p, JSON.stringify({
      privateKeyHex: '11'.repeat(32),
      publicKeyHex: '02' + '22'.repeat(32),
      lockingBytecodeHex: '76a914' + '33'.repeat(20) + '88ac',
      address: 'bchtest:qqtest',
      utxos: [{ txid: 'aa'.repeat(32), vout: 0, valueSats: '20000000' }],
    }));
    chmodSync(p, 0o600);
    const w = loadFundingWallet({ home });
    assert.equal(w.utxos.length, 1);
    assert.equal(w.utxos[0].valueSats, 20_000_000n);
    assert.equal(resolveFundingWalletPath({ home }), p);
  });

  it('selects largest sufficient utxo', () => {
    const w = {
      utxos: [
        { txid: 'aa'.repeat(32), vout: 0, valueSats: 1_000_000n },
        { txid: 'bb'.repeat(32), vout: 1, valueSats: 15_000_000n },
      ],
    };
    const u = selectFundingUtxoFromList(w, 10_200_000n);
    assert.equal(u.txid, 'bb'.repeat(32));
  });

  it('rejects world-readable wallet', () => {
    const home = tmp();
    const p = path.join(home, 'funding-wallet.json');
    writeFileSync(p, JSON.stringify({
      privateKeyHex: '11'.repeat(32),
      publicKeyHex: '02' + '22'.repeat(32),
      lockingBytecodeHex: '76a914' + '33'.repeat(20) + '88ac',
    }));
    chmodSync(p, 0o644);
    assert.throws(
      () => loadFundingWallet({ home }),
      (e) => e.code === 'FUNDING_WALLET_INSECURE',
    );
  });
});
