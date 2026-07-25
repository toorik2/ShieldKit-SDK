import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const requiredCashcVersion = '0.14.0-next.1';

export const loadPinnedCashc = async () => {
  const cashcRoot = process.env.CASHC_ROOT;
  assert.ok(cashcRoot, 'CASHC_ROOT must name verifier.cash vendor/cashc-resched/packages/cashc');
  const entrypoint = resolve(cashcRoot, 'dist/index.js');
  await access(entrypoint);
  const cashc = await import(pathToFileURL(entrypoint).href);
  assert.equal(cashc.version, requiredCashcVersion, `expected cashc@${requiredCashcVersion}`);
  return cashc;
};
