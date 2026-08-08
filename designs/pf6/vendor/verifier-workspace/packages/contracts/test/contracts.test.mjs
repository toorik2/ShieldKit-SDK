import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalJson,
  hashCanonical,
  readJson,
  validateCandidate,
  validateLane,
} from '../src/index.mjs';

const lanePath = new URL('../../../lanes/bn254-onetx/lane.json', import.meta.url);
const frontierPath = new URL('../../../lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-public-ds1.json', import.meta.url);
const sourcePath = new URL('../../../lanes/bn254-onetx/candidates/bn254-onetx-directstate-10-source-r25.json', import.meta.url);
const bnNativePath = new URL('../../../lanes/bn254-native/candidates/bn254-native-covenant-mtx-frozen-pa1.json', import.meta.url);
const blsNativePath = new URL('../../../lanes/bls12-381-native/candidates/bls12-381-native-covenant-mtx-frozen-lc1.json', import.meta.url);
const bnSingletonPath = new URL('../../../lanes/bn254-singleton/candidates/bn254-singleton-genpow-1-public-gp1.json', import.meta.url);
const blsSingletonPath = new URL('../../../lanes/bls12-381-singleton/candidates/bls12-381-singleton-genpow-1-public-gp1.json', import.meta.url);

test('canonical JSON and hashes ignore object insertion order', () => {
  const left = { b: 2, a: { d: 4, c: 3 } };
  const right = { a: { c: 3, d: 4 }, b: 2 };
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(hashCanonical(left), hashCanonical(right));
});

test('the migrated lanes and real candidates satisfy contracts', () => {
  assert.deepEqual(validateLane(readJson(lanePath)), []);
  assert.deepEqual(validateCandidate(readJson(frontierPath)), []);
  assert.deepEqual(validateCandidate(readJson(sourcePath)), []);
  assert.deepEqual(validateCandidate(readJson(bnNativePath)), []);
  assert.deepEqual(validateCandidate(readJson(blsNativePath)), []);
  assert.deepEqual(validateCandidate(readJson(bnSingletonPath)), []);
  assert.deepEqual(validateCandidate(readJson(blsSingletonPath)), []);
});

test('candidate contracts reject repository path traversal', () => {
  const candidate = structuredClone(readJson(frontierPath));
  candidate.build.artifactRoot = '../outside';
  assert.match(validateCandidate(candidate).join('\n'), /repository-relative/);
});

test('candidate contracts reject malformed expected artifact hashes', () => {
  const candidate = structuredClone(readJson(sourcePath));
  candidate.judge.expected.artifactHashes.transaction = 'not-a-digest';
  assert.match(validateCandidate(candidate).join('\n'), /artifactHashes\.transaction must be SHA-256/);
});

test('lane build modules remain repository-contained', () => {
  const candidate = structuredClone(readJson(sourcePath));
  candidate.build.module = '../../outside.mjs';
  assert.match(validateCandidate(candidate).join('\n'), /build\.module must be a repository-relative/);
});

test('covenant execution profiles require an explicit 32-byte category', () => {
  const candidate = structuredClone(readJson(bnNativePath));
  candidate.judge.execution.category = 'cd';
  assert.match(validateCandidate(candidate).join('\n'), /32-byte hex/);
});

test('singleton size profiles require a valid locking hash', () => {
  const candidate = structuredClone(readJson(bnSingletonPath));
  candidate.judge.expected.lockingSha256 = 'not-a-digest';
  assert.match(validateCandidate(candidate).join('\n'), /lockingSha256 must be SHA-256/);
});
