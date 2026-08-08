import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { Writable } from 'node:stream';

import { parseBenchArgs, printHelp, runBench } from './run-bench.mjs';

function nullStdout() {
  return new Writable({ write(_c, _e, cb) { cb(); } });
}

function capture() {
  let text = '';
  const stream = new Writable({
    write(chunk, _enc, cb) {
      text += String(chunk);
      cb();
    },
  });
  return {
    stream,
    text: () => text,
  };
}

test('parseBenchArgs accepts only public surface flags', () => {
  const a = parseBenchArgs(['--cold-start', '--data-home', '/abs/x', '--keep']);
  assert.equal(a.coldStart, true);
  assert.equal(a.dataHome, path.resolve('/abs/x'));
  assert.equal(a.keep, true);

  const b = parseBenchArgs(['--kind', 'deposit', '--data-home', '/abs/y']);
  assert.equal(b.coldStart, false);
  assert.equal(b.kind, 'deposit');

  assert.throws(() => parseBenchArgs(['--s0']), /unknown argument/);
  assert.throws(() => parseBenchArgs(['--live']), /unknown argument/);
  assert.throws(() => parseBenchArgs(['--kind', 'bogus']), /--kind must be/);
  assert.throws(() => parseBenchArgs(['--kind', 'withdraw']), /withdraw requires --to/);
  assert.throws(() => parseBenchArgs(['--kind', 'transfer']), /transfer requires --note/);
});

test('printHelp describes both modes and required data-home', () => {
  const cap = capture();
  printHelp(cap.stream);
  const t = cap.text();
  assert.match(t, /two modes only/);
  assert.match(t, /--cold-start/);
  assert.match(t, /--data-home/);
  assert.match(t, /Pipeline/);
  assert.match(t, /SHIELDKIT_BENCH_DATA_HOME|required/i);
});

test('runBench help does not require data-home', async () => {
  const cap = capture();
  const result = await runBench(['--help'], { stdout: cap.stream, env: {} });
  assert.equal(result.ok, true);
  assert.equal(result.mode, 'help');
  assert.match(cap.text(), /ShieldKit bench/);
});

test('runBench fails closed without data-home', async () => {
  await assert.rejects(
    () => runBench([], { env: {}, runNode: () => true }),
    (err) => err.code === 'BENCH_DATA_HOME_REQUIRED',
  );
});

test('runBench cold-start dispatches machine sandbox with product home', async () => {
  const outer = '/tmp/bench-install-test';
  const product = path.join(outer, 'shieldkit', 'v2-beta-product');
  const session = path.join(product, 'session.json');
  const existsSync = (p) => path.resolve(p) === path.resolve(session);
  const calls = [];
  const cap = capture();
  const result = await runBench(
    ['--cold-start', '--data-home', outer, '--sandbox', '/tmp/bench-sandbox', '--json-out', '/tmp/out.json'],
    {
      env: {},
      existsSync,
      stdout: cap.stream,
      runNode: (script, args) => {
        calls.push({ script, args });
        return true;
      },
    },
  );
  assert.equal(result.ok, true);
  assert.equal(result.mode, 'cold-start');
  assert.equal(result.productHome, product);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].script.endsWith('run-coldstart.mjs'));
  assert.deepEqual(
    calls[0].args.slice(0, 8),
    [
      '--sandbox', path.resolve('/tmp/bench-sandbox'),
      '--machine',
      '--data-home', product,
      '--json-out', path.resolve('/tmp/out.json'),
    ],
  );
  assert.match(cap.text(), /mode=cold-start/);
});

test('runBench pipeline maps nested product to outer CLI data-home', async () => {
  const outer = '/tmp/bench-install-pipe';
  const product = path.join(outer, 'shieldkit', 'v2-beta-product');
  const session = path.join(product, 'session.json');
  const existsSync = (p) => path.resolve(p) === path.resolve(session);
  const calls = [];
  const result = await runBench(
    ['--data-home', product, '--kind', 'deposit'],
    {
      env: {},
      existsSync,
      stdout: nullStdout(),
      runNode: (script, args) => {
        calls.push({ script, args });
        return true;
      },
    },
  );
  assert.equal(result.ok, true);
  assert.equal(result.mode, 'pipeline');
  assert.equal(result.cliHome, outer);
  assert.ok(calls[0].script.endsWith('run-pipeline.mjs'));
  assert.ok(calls[0].args.includes('--live'));
  assert.ok(calls[0].args.includes(outer));
  assert.ok(calls[0].args.includes('deposit'));
});
