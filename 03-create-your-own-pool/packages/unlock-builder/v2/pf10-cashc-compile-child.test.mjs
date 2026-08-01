import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import {
  executeV2Pf10CashcCompileRequest,
  parseV2Pf10CashcCompileRequest,
  V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA,
  V2_PF10_CASHC_COMPILE_RESULT_SCHEMA,
  V2Pf10CashcCompileChildError,
} from './pf10-cashc-compile-child.mjs';

const request = Object.freeze({
  files: Object.freeze({}),
  schema: V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA,
  source: 'pragma cashscript ^0.14.0;\ncontract Child() { function run() { require(true); } }',
});
const CHILD = fileURLToPath(new URL('./pf10-cashc-compile-child.mjs', import.meta.url));
function framedJcs(value) {
  const body = Buffer.from(canonicalizeJcs(value), 'utf8'); const header = Buffer.alloc(4); header.writeUInt32BE(body.length);
  return Buffer.concat([header, body]);
}

test('PF10 CashC child accepts only exact JCS and returns raw hex', () => {
  const parsed = parseV2Pf10CashcCompileRequest(Buffer.from(canonicalizeJcs(request), 'utf8'));
  assert.equal(parsed.source, request.source);
  const result = executeV2Pf10CashcCompileRequest(request);
  assert.equal(result.schema, V2_PF10_CASHC_COMPILE_RESULT_SCHEMA);
  assert.match(result.rawHex, /^[0-9a-f]+$/u);
  assert.throws(
    () => parseV2Pf10CashcCompileRequest(Buffer.from(`${canonicalizeJcs(request)}\n`, 'utf8')),
    (error) => error instanceof V2Pf10CashcCompileChildError && error.code === 'PF10_CASHC_CHILD_REQUEST_INVALID',
  );
});

test('PF10 CashC child rejects file names outside its private protocol', () => {
  assert.throws(
    () => executeV2Pf10CashcCompileRequest({ ...request, files: { './untrusted.cash': 'x' } }),
    (error) => error instanceof V2Pf10CashcCompileChildError && error.code === 'PF10_CASHC_CHILD_REQUEST_INVALID',
  );
});

test('PF10 CashC child one-shot process uses the exact JCS protocol', () => {
  const child = spawnSync(process.execPath, [CHILD], {
    encoding: 'buffer', input: Buffer.concat([framedJcs(request), framedJcs(request)]), shell: false,
    env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
  });
  assert.equal(child.status, 0, Buffer.from(child.stderr ?? []).toString('utf8'));
  assert.equal(Buffer.from(child.stderr ?? []).byteLength, 0);
  const output = Buffer.from(child.stdout);
  let offset = 0;
  for (let index = 0; index < 2; index += 1) {
    const length = output.readUInt32BE(offset); offset += 4;
    const body = output.subarray(offset, offset + length); offset += length;
    const result = JSON.parse(body.toString('utf8'));
    assert.equal(canonicalizeJcs(result), body.toString('utf8'));
    assert.equal(result.schema, V2_PF10_CASHC_COMPILE_RESULT_SCHEMA);
  }
  assert.equal(offset, output.length);
});
