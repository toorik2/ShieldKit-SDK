import assert from 'node:assert/strict';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertCompleteCargoTestRun,
  discoverRustCrates,
  parseCargoTestOutput,
  preflightRustCrates,
} from './run-rust-tests.mjs';

async function fixture(crates) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'shieldkit-rust-runner-'));
  await mkdir(path.join(root, 'crates'), { recursive: true });
  for (const [crate, files] of Object.entries(crates)) {
    for (const [relativePath, source] of Object.entries(files)) {
      const filename = path.join(root, 'crates', crate, relativePath);
      await mkdir(path.dirname(filename), { recursive: true });
      await writeFile(filename, source);
    }
  }
  return root;
}

const manifest = (name) => [
  '[package]',
  `name = "${name}"`,
  'version = "0.1.0"',
  'edition = "2024"',
  'rust-version = "1.97"',
  '',
].join('\n');

test('discovers every locked Rust crate and its test sources in stable order', async () => {
  const root = await fixture({
    zebra: {
      'Cargo.toml': manifest('zebra'),
      'Cargo.lock': 'version = 4\n',
      'src/lib.rs': '#[cfg(test)] mod tests { #[test] fn z() {} }\n',
    },
    alpha: {
      'Cargo.toml': manifest('alpha'),
      'Cargo.lock': 'version = 4\n',
      'tests/security.rs': '#[test]\nfn boundary() {}\n',
    },
  });
  const crates = discoverRustCrates({ projectRoot: root });
  assert.deepEqual(crates.map((crate) => crate.name), ['alpha', 'zebra']);
  assert.deepEqual(crates.map((crate) => crate.sourceTestDeclarations), [1, 1]);
  assert.doesNotThrow(() => preflightRustCrates(crates));
});

test('new crates without locks and ignored Rust tests fail closed', async () => {
  const unlockedRoot = await fixture({
    unlocked: {
      'Cargo.toml': manifest('unlocked'),
      'src/lib.rs': '#[test] fn test_me() {}\n',
    },
  });
  assert.throws(
    () => discoverRustCrates({ projectRoot: unlockedRoot }),
    /missing Cargo\.lock/,
  );

  const ignoredRoot = await fixture({
    ignored: {
      'Cargo.toml': manifest('ignored'),
      'Cargo.lock': 'version = 4\n',
      'src/lib.rs': '#[test]\n#[' + 'ignore]\nfn hidden() {}\n',
    },
  });
  const ignored = discoverRustCrates({ projectRoot: ignoredRoot });
  assert.throws(() => preflightRustCrates(ignored), /ignored Rust tests/);
});

test('Cargo summaries fail closed on ignored, filtered, failed, and empty runs', () => {
  const parsed = parseCargoTestOutput([
    'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
    'test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out;',
  ].join('\n'));
  assert.equal(parsed.summaries.length, 2);
  assert.equal(parsed.passed, 4);
  assert.equal(parsed.ignored, 1);
  assert.equal(parsed.filteredOut, 2);
  assert.throws(() => assertCompleteCargoTestRun(parsed), /not fully executed/);
  assert.throws(
    () => assertCompleteCargoTestRun(parseCargoTestOutput(
      'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
    )),
    /empty crate test suite/,
  );
  assert.doesNotThrow(() => assertCompleteCargoTestRun(parseCargoTestOutput(
    'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',
  )));
});
