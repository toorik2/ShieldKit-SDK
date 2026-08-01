import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  V2_BETA_LOCAL_FALSE_CLAIMS,
} from '../packages/profile/v2/beta-local-profile.mjs';

import {
  parseV2BetaLocalIntegrationArguments,
  parseV2BetaLocalIntegrationVerifyArguments,
} from './v2-beta-local-integration.mjs';
import {
  V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS,
} from './v2-beta-single-contributor-ceremony.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

test('historic ceremony claims remain exact while the local lane adds its label and explicit nonclaims', () => {
  for (const [name, value] of Object.entries(
    V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS,
  )) {
    assert.equal(value, false);
    assert.equal(V2_BETA_LOCAL_FALSE_CLAIMS[name], false);
  }
  assert.deepEqual(
    Object.keys(V2_BETA_LOCAL_FALSE_CLAIMS)
      .filter((name) => !Object.hasOwn(
        V2_BETA_SINGLE_CONTRIBUTOR_FALSE_CLAIMS,
        name,
      )),
    [
      'bchVm', 'betaSingleContributor', 'developmentKey', 'q01Qualified',
      'q04Qualified', 'q05Qualified', 'q06Qualified',
    ],
  );
  assert.equal(V2_BETA_LOCAL_FALSE_CLAIMS.betaSingleContributor, true);
});

test('beta integration accepts only the complete local custody/build interface', () => {
  const root = path.join(ROOT, '.codex-build', 'beta-integration-test');
  const parsed = parseV2BetaLocalIntegrationArguments([
    '--ceremony-dir', '/tmp/beta-ceremony',
    '--b01-manifest', '/tmp/b01/manifest.json',
    '--b01-runtime', '/tmp/b01/runtime',
    '--output', root,
    '--temporary-root', '/tmp/beta-tmp',
  ]);
  assert.equal(parsed.outputDirectory, root);
  assert.equal(parsed.ceremonyDirectory, '/tmp/beta-ceremony');
  assert.equal(parsed.b01Runtime, '/tmp/b01/runtime');
  assert.throws(() => parseV2BetaLocalIntegrationArguments([
    '--ceremony-dir', '/tmp/beta-ceremony',
    '--b01-manifest', '/tmp/b01/manifest.json',
    '--b01-runtime', '/tmp/b01/runtime',
    '--output', path.join(ROOT, 'not-private'),
    '--temporary-root', '/tmp/beta-tmp',
  ]), /\.codex-build/u);
});

test('beta integration verify interface cannot quietly select a normal runtime', () => {
  const output = path.join(ROOT, '.codex-build', 'beta-integration-verify');
  assert.deepEqual(
    parseV2BetaLocalIntegrationVerifyArguments([
      '--verify', output, '--temporary-root', '/tmp/beta-tmp',
    ]),
    { outputDirectory: output, temporaryRoot: '/tmp/beta-tmp' },
  );
  assert.throws(
    () => parseV2BetaLocalIntegrationVerifyArguments(['--verify', output]),
    /usage/u,
  );
});

test('beta integration source has no network, broadcaster, or descriptor admission dependency', async () => {
  const source = await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)), 'v2-beta-local-integration.mjs'),
    'utf8',
  );
  for (const forbidden of [
    "from './v2-network", "from '../packages/network", "from '../packages/kit/v2/network",
    'resolveV2Instance', 'fetch(', 'http:', 'https:', 'WebSocket',
  ]) assert.equal(source.includes(forbidden), false, `forbidden beta integration dependency: ${forbidden}`);
  assert.match(source, /maximumLiveNotes: MAXIMUM_LIVE_NOTES/u);
  assert.match(source, /const CARRIER_COUNT = 10/u);
});
