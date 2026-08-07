import assert from 'node:assert/strict';
import test from 'node:test';

import { parseArgv } from './parser.mjs';

test('parser rejects unknown flags, duplicates, and trailing positionals', () => {
  assert.throws(() => parseArgv(['design', 'list', '--wat']), /unknown option/);
  assert.throws(() => parseArgv(['design', 'list', '--json', '--json']), /only once/);
  assert.throws(() => parseArgv(['pool', 'status', 'unexpected']), /unexpected positional/);
  assert.throws(() => parseArgv(['design', 'list', '--to', 'x']), /not valid/);
  assert.throws(() => parseArgv(['action', 'deposit', '--data-home', '/legacy']), /not valid/);
  assert.throws(() => parseArgv(['operation', 'inspect', '--data-home', '/legacy']), /not valid/);
});

test('parser preserves exact profile and operation id as explicit fields', () => {
  const profile = 'ab'.repeat(32);
  const parsed = parseArgv([
    '--profile', profile, 'operation', 'inspect', '--operation-id', 'op-1',
  ]);
  assert.equal(parsed.flags.profile, profile);
  assert.equal(parsed.flags.operationId, 'op-1');
  assert.equal(parsed.flags.raw, undefined);
});

test('parser maps only documented PF10 muscle-memory aliases', () => {
  const parsed = parseArgv(['pool', 'deposit']);
  assert.equal(parsed.group, 'action');
  assert.equal(parsed.command, 'deposit');
  assert.equal(parsed.deprecation.canonical, 'action deposit');
});

test('version accepts only optional json', () => {
  assert.equal(parseArgv(['--version']).group, 'version');
  assert.equal(parseArgv(['--version', '--json']).group, 'version');
  assert.throws(() => parseArgv(['--version', 'design', 'list']), /--version/);
});
