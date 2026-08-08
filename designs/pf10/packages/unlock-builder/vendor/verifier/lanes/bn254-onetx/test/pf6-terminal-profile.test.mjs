import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { validateBuild } from '../src/build-adapter.mjs';

const candidate = JSON.parse(readFileSync(
  new URL('../candidates/bn254-onetx-pf6-a3-r1.json', import.meta.url),
  'utf8',
));

test('PF6 terminal profile is manifest-pinned and structurally validated', () => {
  assert.deepEqual(candidate.build.terminal, {
    frobFuse: true,
    wSelector: true,
    densDropBytes: 1115,
    bqReserveBytes: 160,
    bqResidualNoFuel: true,
  });
  assert.doesNotThrow(() => validateBuild(candidate.build));
  assert.throws(
    () => validateBuild({
      ...candidate.build,
      terminal: { ...candidate.build.terminal, bqReserveBytes: -1 },
    }),
    /bqReserveBytes/,
  );
  assert.throws(
    () => validateBuild({
      ...candidate.build,
      terminal: { ...candidate.build.terminal, ambientOnly: true },
    }),
    /must define exactly/,
  );
});
