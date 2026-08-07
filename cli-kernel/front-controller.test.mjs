import assert from 'node:assert/strict';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Writable } from 'node:stream';
import os from 'node:os';
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';

import { dispatch } from './front-controller.mjs';
import { RESULT_SCHEMA } from './contracts/envelopes.mjs';
import { DEPRECATION_WINDOW } from './parser.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(HERE, 'bin/shieldkit.mjs');

function captureDispatch(argv, env = {}) {
  let out = '';
  const stdout = new Writable({
    write(chunk, _enc, cb) {
      out += String(chunk);
      cb();
    },
  });
  return dispatch(argv, {
    stdout,
    env: {
      XDG_CONFIG_HOME: path.join(os.tmpdir(), 'shieldkit-cli-kernel-no-config'),
      ...env,
    },
  }).then((r) => ({ ...r, out }));
}

test('help and design list expose canonical groups; no backend modules loaded', async () => {
  const help = await captureDispatch(['--help']);
  assert.equal(help.exitCode, 0);
  assert.match(help.out, /design/);
  assert.match(help.out, /action/);
  assert.match(help.out, /operation/);
  assert.match(help.out, /demo/);
  assert.doesNotMatch(help.out, /^\s*wallet\s/m);
  assert.doesNotMatch(help.out, /^\s*dev\s/m);

  const list = await captureDispatch(['design', 'list']);
  assert.equal(list.exitCode, 0);
  const env = JSON.parse(list.out);
  assert.equal(env.schema, RESULT_SCHEMA);
  assert.equal(env.ok, true);
  assert.equal(env.result.backendModuleLoaded, false);
  assert.ok(env.result.designs.some((d) => d.alias === 'pf10'));
  assert.ok(env.result.designs.every((d) => d.backendModuleLoaded === false));
});

test('CLI binary help twice is consistent', () => {
  const a = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' });
  const b = spawnSync(process.execPath, [BIN, '--help'], { encoding: 'utf8' });
  assert.equal(a.status, 0);
  assert.equal(b.status, 0);
  assert.equal(a.stdout, b.stdout);
  assert.match(a.stdout, /Existing homes bind exact profile identity/i);
});

test('FRI and PF6 mutations remain blocked even with Lab acknowledgement', async () => {
  const fri = await captureDispatch(['--design', 'fri', 'action', 'transfer']);
  assert.equal(fri.exitCode, 2);
  const friEnv = JSON.parse(fri.out);
  assert.equal(friEnv.ok, false);
  assert.equal(friEnv.code, 'CAPABILITY_BLOCKED');
  assert.equal(friEnv.result?.emulated, false);

  const pf6 = await captureDispatch(['--design', 'pf6', '--allow-lab', 'action', 'deposit']);
  const pf6Env = JSON.parse(pf6.out);
  assert.equal(pf6Env.ok, false);
  assert.equal(pf6Env.code, 'CAPABILITY_BLOCKED');
});

test('demo catalog is explicitly unavailable rather than a forged signed placeholder', async () => {
  const r = await captureDispatch(['demo', 'list']);
  assert.equal(r.exitCode, 0);
  const env = JSON.parse(r.out);
  assert.equal(env.result.catalog.readOnly, true);
  assert.equal(env.result.verified, false);
  assert.equal(env.result.unavailableStateValid, true);
  assert.equal(env.result.authenticity, 'unavailable');
  assert.equal(env.result.catalog.availability, 'unavailable');
  assert.equal(env.result.mutableSharedPoolDefault, false);
});

test('unimplemented developer groups are absent rather than advertised as stubs', async () => {
  const r = await captureDispatch(['dev', 'bench']);
  assert.equal(r.exitCode, 64, r.out);
  const env = JSON.parse(r.out);
  assert.equal(env.ok, false);
  assert.equal(env.code, 'UNKNOWN_COMMAND');
  assert.equal(env.result, null);
  assert.doesNotMatch(r.out, /mempool.*(?:ms|milliseconds)/i);
});

test('strict parser rejects unknown flags and conflicting design/profile selectors', async () => {
  const unknown = await captureDispatch(['design', 'list', '--unknown']);
  assert.equal(unknown.exitCode, 64);
  assert.equal(JSON.parse(unknown.out).code, 'USAGE');

  const conflict = await captureDispatch([
    '--design', 'pf10', '--profile', 'ab'.repeat(32), 'design', 'doctor',
  ]);
  assert.equal(conflict.exitCode, 64);
  assert.notEqual(JSON.parse(conflict.out).ok, true);
});

test('explicit selector pair overrides config selectors; unsafe config symlinks fail closed', async () => {
  const xdg = mkdtempSync(path.join(os.tmpdir(), 'sk-front-xdg-'));
  const configDir = path.join(xdg, 'shieldkit');
  mkdirSync(configDir, { mode: 0o700 });
  const configPath = path.join(configDir, 'config.json');
  try {
    writeFileSync(configPath, `${JSON.stringify({ profile: 'ab'.repeat(32) })}\n`, { mode: 0o600 });
    const explicit = await captureDispatch(
      ['--design', 'pf10', 'design', 'doctor'],
      { XDG_CONFIG_HOME: xdg },
    );
    assert.equal(explicit.exitCode, 0, explicit.out);
    assert.equal(JSON.parse(explicit.out).identity.profileStatus, 'unselected');

    rmSync(configPath);
    const target = path.join(xdg, 'real-config.json');
    writeFileSync(target, '{}\n', { mode: 0o600 });
    symlinkSync(target, configPath);
    const unsafe = await captureDispatch(
      ['--design', 'pf10', 'design', 'doctor'],
      { XDG_CONFIG_HOME: xdg },
    );
    assert.equal(unsafe.exitCode, 64, unsafe.out);
    assert.equal(JSON.parse(unsafe.out).code, 'AMBIENT_CONFIG_FORBIDDEN');
  } finally {
    rmSync(xdg, { recursive: true, force: true });
  }
});

test('instance doctor and recovery require an explicit bound operation context', async () => {
  const doctor = await captureDispatch(['--design', 'pf10', 'pool', 'doctor']);
  assert.equal(doctor.exitCode, 2, doctor.out);
  assert.equal(JSON.parse(doctor.out).code, 'HOME_NOT_FOUND');
  assert.equal(JSON.parse(doctor.out).command, 'pool doctor');

  const missingOperation = await captureDispatch([
    '--design', 'pf10', 'operation', 'rebroadcast', '--acknowledge-rebroadcast',
  ]);
  assert.equal(JSON.parse(missingOperation.out).code, 'USAGE');

  const missingCas = await captureDispatch([
    '--design', 'pf10', 'operation', 'rebroadcast',
    '--operation-id', `deposit.${'ab'.repeat(32)}`,
    '--acknowledge-rebroadcast',
  ]);
  assert.equal(JSON.parse(missingCas.out).code, 'REBROADCAST_CAS_REQUIRED');
});

test('version and contextual help are complete and non-mutating', async () => {
  const version = await captureDispatch(['--version']);
  assert.equal(version.exitCode, 0);
  assert.match(version.out, /^shieldkit \S+/);
  const help = await captureDispatch(['pool', 'create', '--help']);
  assert.equal(help.exitCode, 0);
  assert.match(help.out, /funding-wallet/);
});

test('deprecation window is bounded', () => {
  assert.equal(DEPRECATION_WINDOW.ends, '2026-11-07');
  assert.match(DEPRECATION_WINDOW.message, /not a permanent|Shims end|deprecated/i);
});
