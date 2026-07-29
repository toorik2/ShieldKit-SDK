#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const project = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PINNED_RUST_TOOLCHAIN = '1.97.1';
const REQUIRED_RUST_VERSION = '1.97';
const RUST_TEST_DECLARATION = /#\s*\[\s*test\s*\]/g;
const RUST_IGNORED_TEST = /#\s*\[\s*ignore(?:\s*=\s*[^]*?)?\s*\]/;

export class RustTestRunnerError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RustTestRunnerError';
  }
}

const fail = (message) => { throw new RustTestRunnerError(message); };
const posix = (value) => value.split(path.sep).join('/');

function rustSources(crateRoot) {
  const sources = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name, 'en'))) {
      if (entry.name === 'target' || entry.name.startsWith('.')) continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.endsWith('.rs')) sources.push(full);
    }
  };
  visit(crateRoot);
  return sources;
}

export function discoverRustCrates({ projectRoot = project } = {}) {
  const cratesRoot = path.join(projectRoot, 'crates');
  if (!existsSync(cratesRoot)) fail('crates directory is missing');
  const crates = [];
  for (const entry of readdirSync(cratesRoot, { withFileTypes: true })
    .sort((left, right) => left.name.localeCompare(right.name, 'en'))) {
    if (!entry.isDirectory() || entry.name === 'target' || entry.name.startsWith('.')) continue;
    const crateRoot = path.join(cratesRoot, entry.name);
    const manifestPath = path.join(crateRoot, 'Cargo.toml');
    const sourceFiles = rustSources(crateRoot);
    if (!existsSync(manifestPath)) {
      if (sourceFiles.length > 0) fail(`crates/${entry.name} has Rust sources but no Cargo.toml`);
      continue;
    }
    const lockPath = path.join(crateRoot, 'Cargo.lock');
    if (!existsSync(lockPath)) fail(`crates/${entry.name} is missing Cargo.lock`);
    const manifest = readFileSync(manifestPath, 'utf8');
    const name = manifest.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const rustVersion = manifest.match(/^\s*rust-version\s*=\s*"([^"]+)"/m)?.[1];
    if (name === undefined) fail(`crates/${entry.name}/Cargo.toml is missing package.name`);
    if (rustVersion !== REQUIRED_RUST_VERSION) {
      fail(`crates/${entry.name}/Cargo.toml must pin rust-version = "${REQUIRED_RUST_VERSION}"`);
    }
    if (sourceFiles.length === 0) fail(`crates/${entry.name} contains no Rust sources`);
    const sources = sourceFiles.map((filename) => {
      const source = readFileSync(filename, 'utf8');
      return Object.freeze({
        path: filename,
        relativePath: posix(path.relative(projectRoot, filename)),
        testDeclarations: [...source.matchAll(RUST_TEST_DECLARATION)].length,
        containsIgnoredTest: RUST_IGNORED_TEST.test(source),
      });
    });
    crates.push(Object.freeze({
      name,
      root: crateRoot,
      relativeRoot: posix(path.relative(projectRoot, crateRoot)),
      manifestPath,
      lockPath,
      rustVersion,
      sources: Object.freeze(sources),
      sourceTestDeclarations: sources.reduce((sum, source) => sum + source.testDeclarations, 0),
    }));
  }
  if (crates.length === 0) fail('no locked Rust crates discovered');
  return Object.freeze(crates);
}

export function preflightRustCrates(crates) {
  for (const crate of crates) {
    const ignored = crate.sources
      .filter((source) => source.containsIgnoredTest)
      .map((source) => source.relativePath);
    if (ignored.length > 0) {
      fail(`${crate.relativeRoot} contains ignored Rust tests: ${JSON.stringify(ignored)}`);
    }
  }
}

export function parseCargoTestOutput(output) {
  const summaries = [...output.matchAll(
    /test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;/g,
  )].map((match) => Object.freeze({
    result: match[1],
    passed: Number(match[2]),
    failed: Number(match[3]),
    ignored: Number(match[4]),
    measured: Number(match[5]),
    filteredOut: Number(match[6]),
  }));
  return Object.freeze({
    summaries: Object.freeze(summaries),
    passed: summaries.reduce((sum, summary) => sum + summary.passed, 0),
    failed: summaries.reduce((sum, summary) => sum + summary.failed, 0),
    ignored: summaries.reduce((sum, summary) => sum + summary.ignored, 0),
    measured: summaries.reduce((sum, summary) => sum + summary.measured, 0),
    filteredOut: summaries.reduce((sum, summary) => sum + summary.filteredOut, 0),
  });
}

export function assertCompleteCargoTestRun(summary, crateLabel = 'Rust crate') {
  if (summary.summaries.length === 0) fail(`${crateLabel}: cargo omitted test summaries`);
  if (
    summary.failed !== 0
    || summary.ignored !== 0
    || summary.measured !== 0
    || summary.filteredOut !== 0
    || summary.summaries.some((entry) => entry.result !== 'ok')
  ) {
    fail(`${crateLabel}: cargo tests were not fully executed: ${JSON.stringify(summary)}`);
  }
  if (summary.passed === 0) fail(`${crateLabel}: cargo reported an empty crate test suite`);
}

export function runSelectedRustCrates(
  crates,
  {
    cwd = project,
    environment = process.env,
    crateTimeoutMs = 600_000,
  } = {},
) {
  if (!Number.isSafeInteger(crateTimeoutMs) || crateTimeoutMs <= 0) {
    fail(`invalid per-crate timeout: ${crateTimeoutMs}`);
  }
  const aggregate = {
    crates: crates.length,
    tests: 0,
    pass: 0,
    fail: 0,
    ignored: 0,
    measured: 0,
    filteredOut: 0,
  };
  for (const [index, crate] of crates.entries()) {
    process.stderr.write(`${JSON.stringify({
      phase: 'rust-test-crate',
      index: index + 1,
      total: crates.length,
      crate: crate.name,
      manifest: posix(path.relative(cwd, crate.manifestPath)),
    })}\n`);
    const result = spawnSync('cargo', [
      `+${PINNED_RUST_TOOLCHAIN}`,
      'test',
      '--locked',
      '--manifest-path',
      crate.manifestPath,
    ], {
      cwd,
      env: {
        ...environment,
        MISE_RUST_VERSION: PINNED_RUST_TOOLCHAIN,
        RUSTUP_TOOLCHAIN: PINNED_RUST_TOOLCHAIN,
      },
      encoding: 'utf8',
      maxBuffer: 128 * 1024 * 1024,
      timeout: crateTimeoutMs,
      killSignal: 'SIGKILL',
    });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.error) {
      const detail = result.error.code === 'ETIMEDOUT'
        ? `timed out after ${crateTimeoutMs}ms`
        : `could not start: ${result.error.message}`;
      fail(`${crate.relativeRoot}: cargo ${detail}`);
    }
    if (result.status !== 0 || result.signal !== null) {
      fail(`${crate.relativeRoot}: cargo test failed: exit=${result.status ?? 'none'} signal=${result.signal ?? 'none'}`);
    }
    const summary = parseCargoTestOutput(`${result.stdout ?? ''}\n${result.stderr ?? ''}`);
    assertCompleteCargoTestRun(summary, crate.relativeRoot);
    aggregate.tests += summary.passed + summary.failed + summary.ignored + summary.measured;
    aggregate.pass += summary.passed;
    aggregate.fail += summary.failed;
    aggregate.ignored += summary.ignored;
    aggregate.measured += summary.measured;
    aggregate.filteredOut += summary.filteredOut;
  }
  process.stderr.write(`${JSON.stringify({ phase: 'rust-test-complete', ...aggregate })}\n`);
  return Object.freeze(aggregate);
}

export function runRustTests({ projectRoot = project } = {}) {
  const crates = discoverRustCrates({ projectRoot });
  preflightRustCrates(crates);
  process.stderr.write(`${JSON.stringify({
    phase: 'rust-test-discovery',
    toolchain: PINNED_RUST_TOOLCHAIN,
    selectedCount: crates.length,
    selected: crates.map((crate) => ({
      crate: crate.name,
      root: crate.relativeRoot,
      manifest: posix(path.relative(projectRoot, crate.manifestPath)),
      lock: posix(path.relative(projectRoot, crate.lockPath)),
      rustVersion: crate.rustVersion,
      sourceTestDeclarations: crate.sourceTestDeclarations,
      sources: crate.sources.map((source) => source.relativePath),
    })),
  }, null, 2)}\n`);
  return Object.freeze({
    crates,
    summary: runSelectedRustCrates(crates, { cwd: projectRoot }),
  });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    runRustTests();
  } catch (error) {
    process.stderr.write(`mandatory Rust test runner failed: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
