/**
 * Integration adversary checks for the unified CLI boundary.
 *
 * These intentionally test the composition of parser → home resolution →
 * capability gate → backend dispatch.  A green adapter unit test is not a
 * substitute for these fail-closed properties.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Writable } from 'node:stream';

import { dispatch } from '../front-controller.mjs';
import { OperationCoordinator } from '../lifecycle/coordinator.mjs';
import { createSingleSendAdmission } from '../chain/admission.mjs';
import { CliError } from '../contracts/errors.mjs';
import { writeHomeManifest } from '../home/resolve.mjs';
import { showDesign } from '../registry/designs.mjs';

const EXACT_TEST_PROFILE_ID = '22'.repeat(32);
const EXACT_TEST_INSTANCE_ID = '33'.repeat(32);
const PF10 = showDesign('pf10');

function capture(argv, env = {}) {
  let out = '';
  const stdout = new Writable({
    write(chunk, _encoding, done) {
      out += String(chunk);
      done();
    },
  });
  const xdg = mkdtempSync(path.join(tmpdir(), 'sk-integration-xdg-'));
  return dispatch(argv, {
    stdout,
    // Do not accidentally inherit a developer's default design/home.
    env: { ...process.env, ...env, XDG_CONFIG_HOME: xdg },
  }).then((result) => {
    rmSync(xdg, { recursive: true, force: true });
    return { ...result, envelope: JSON.parse(out), out };
  }, (error) => {
    rmSync(xdg, { recursive: true, force: true });
    throw error;
  });
}

test('design aliases stay design-family selectors; Lab acknowledgement never creates mutation authority', async () => {
  const pf10 = await capture(['--design', 'pf10', 'action', 'deposit']);
  assert.equal(pf10.exitCode, 2, pf10.out);
  assert.equal(pf10.envelope.code, 'HOME_NOT_FOUND');
  assert.equal(pf10.envelope.identity.profileStatus, 'unselected');
  assert.equal(pf10.envelope.identity.profileId, null);

  for (const [design, action] of [['pf6', 'deposit'], ['fri', 'transfer']]) {
    const blocked = await capture(['--design', design, '--allow-lab', 'action', action]);
    assert.equal(blocked.exitCode, 2, blocked.out);
    assert.equal(blocked.envelope.code, 'CAPABILITY_BLOCKED');
    assert.equal(blocked.envelope.result.emulated, false);
    assert.equal(blocked.envelope.identity.profileStatus, 'unfrozen');
    assert.equal(blocked.envelope.identity.profileId, null);
  }
});

test('unsafe home is rejected before backend delegation can become a fallback', async () => {
  const target = mkdtempSync(path.join(tmpdir(), 'sk-integration-home-target-'));
  const link = `${target}-link`;
  try {
    symlinkSync(target, link, 'dir');
    const result = await capture(['--design', 'pf10', '--home', link, 'action', 'deposit']);
    assert.equal(result.exitCode, 2, result.out);
    assert.equal(result.envelope.code, 'HOME_NOT_FOUND');
    assert.match(result.envelope.error, /symlink/i);
    // Adapter envelopes identify delegation; resolver failure must occur first.
    assert.equal(result.envelope.result, null);
    assert.equal(result.envelope.identity, null);
  } finally {
    rmSync(link, { force: true });
    rmSync(target, { recursive: true, force: true });
  }
});

test('generic lifecycle cannot begin in memory or stage without an exact profile-bound validation', async () => {
  let sends = 0;
  const admission = {
    async sendOnce() {
      sends += 1;
      return { accepted: true, readback: { match: true } };
    },
  };

  assert.throws(
    () => new OperationCoordinator({ admission }),
    /branded SingleSendAdmission/,
  );
  const branded = createSingleSendAdmission({
    async sendrawtransaction() {
      sends += 1;
      return '00'.repeat(32);
    },
  });
  const volatile = new OperationCoordinator({ admission: branded });
  assert.throws(
    () => volatile.begin({ kind: 'deposit', identity: { profileId: EXACT_TEST_PROFILE_ID } }),
    (error) => error instanceof CliError && error.code === 'DURABILITY_REQUIRED',
  );

  const home = mkdtempSync(path.join(tmpdir(), 'sk-integration-lifecycle-'));
  try {
    writeHomeManifest(home, {
      backendId: PF10.backendId,
      designId: PF10.id,
      profileId: EXACT_TEST_PROFILE_ID,
      instanceId: EXACT_TEST_INSTANCE_ID,
      genesisDescriptorHash: '44'.repeat(32),
    });
    const durable = new OperationCoordinator({ admission: branded, homePath: home });
    assert.throws(
      () => durable.begin({ kind: 'deposit', identity: { profileId: null, instanceId: EXACT_TEST_INSTANCE_ID } }),
      (error) => error instanceof CliError && error.code === 'DURABILITY_REQUIRED',
    );
    assert.equal(sends, 0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('the CLI has no stub developer benchmark that can fabricate a pipeline measurement', async () => {
  const result = await capture(['dev', 'bench']);
  assert.equal(result.exitCode, 64, result.out);
  assert.equal(result.envelope.code, 'UNKNOWN_COMMAND');
  assert.equal(result.envelope.result, null);
  assert.doesNotMatch(result.out, /mempool acceptance.*(?:ms|\d)/i);
});
