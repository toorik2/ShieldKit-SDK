/** Private one-shot CashC protocol used by the PF10 instance linker. */
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

import { compileString, utils as cashcUtils } from '../vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';

export const V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA =
  'shieldkit-v2-direct-pf10-cashc-compile-request-v1';
export const V2_PF10_CASHC_COMPILE_RESULT_SCHEMA =
  'shieldkit-v2-direct-pf10-cashc-compile-result-v1';
export const V2_PF10_CASHC_COMPILE_ERROR_SCHEMA =
  'shieldkit-v2-direct-pf10-cashc-compile-error-v1';
const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const MAX_SOURCE_BYTES = 6 * 1024 * 1024;
const OPTIONS = Object.freeze({ optimizeFor: 'opcost', rescheduleStacks: true });

export class V2Pf10CashcCompileChildError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2Pf10CashcCompileChildError'; this.code = code;
  }
}
const fail = (code, message, cause = undefined) => { throw new V2Pf10CashcCompileChildError(code, message, cause); };
const plain = (value, label) => {
  if (value === null || Array.isArray(value) || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('PF10_CASHC_CHILD_REQUEST_INVALID', `${label} must be an object`);
  return value;
};
const exact = (value, keys, label) => {
  plain(value, label); const actual = Object.keys(value).sort(); const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) fail('PF10_CASHC_CHILD_REQUEST_INVALID', `${label} has missing or unknown properties`);
  return value;
};
function canonicalRequest(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > MAX_REQUEST_BYTES) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request size is outside the private protocol limit');
  let value;
  try { value = JSON.parse(Buffer.from(bytes).toString('utf8')); } catch (error) { fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request is not valid JSON', error); }
  let canonical;
  try { canonical = canonicalizeJcs(value); } catch (error) { fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request is not valid JCS data', error); }
  if (!Buffer.from(canonical, 'utf8').equals(Buffer.from(bytes))) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request must be exact JCS without framing bytes');
  return value;
}

export function parseV2Pf10CashcCompileRequest(bytes) {
  const value = canonicalRequest(bytes);
  exact(value, ['files', 'schema', 'source'], 'request');
  if (value.schema !== V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA || typeof value.source !== 'string' || Buffer.byteLength(value.source, 'utf8') > MAX_SOURCE_BYTES) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request schema or source is invalid');
  plain(value.files, 'request.files');
  const names = Object.keys(value.files);
  if (names.length > 1 || names.some((name) => name !== 'Bn254LazyAff.cash') || names.some((name) => typeof value.files[name] !== 'string' || Buffer.byteLength(value.files[name], 'utf8') > MAX_SOURCE_BYTES)) {
    fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'request.files is invalid');
  }
  return Object.freeze({ schema: value.schema, source: value.source, files: Object.freeze({ ...value.files }) });
}

export function executeV2Pf10CashcCompileRequest(value) {
  const request = parseV2Pf10CashcCompileRequest(Buffer.from(canonicalizeJcs(value), 'utf8'));
  try {
    const raw = Buffer.from(cashcUtils.asmToBytecode(compileString(request.source, { files: request.files, ...OPTIONS }).bytecode));
    return Object.freeze({ schema: V2_PF10_CASHC_COMPILE_RESULT_SCHEMA, rawHex: raw.toString('hex') });
  } catch (error) {
    fail('PF10_CASHC_CHILD_COMPILE_FAILED', `CashC compilation failed: ${error instanceof Error ? error.message : String(error)}`, error);
  }
}

function frame(bytes) {
  if (bytes.length === 0 || bytes.length > MAX_REQUEST_BYTES) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'frame size is outside the private protocol limit');
  const header = Buffer.alloc(4); header.writeUInt32BE(bytes.length);
  return Buffer.concat([header, bytes]);
}
async function writeFrame(value) {
  const output = frame(Buffer.from(canonicalizeJcs(value), 'utf8'));
  if (!process.stdout.write(output)) await once(process.stdout, 'drain');
}
async function main() {
  let buffered = Buffer.alloc(0);
  try {
    for await (const chunk of process.stdin) {
      buffered = Buffer.concat([buffered, chunk]);
      while (buffered.length >= 4) {
        const length = buffered.readUInt32BE(0);
        if (length === 0 || length > MAX_REQUEST_BYTES) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'frame size is outside the private protocol limit');
        if (buffered.length < 4 + length) break;
        const request = buffered.subarray(4, 4 + length); buffered = buffered.subarray(4 + length);
        try {
          await writeFrame(executeV2Pf10CashcCompileRequest(parseV2Pf10CashcCompileRequest(request)));
        } catch (error) {
          await writeFrame({ schema: V2_PF10_CASHC_COMPILE_ERROR_SCHEMA, code: typeof error?.code === 'string' ? error.code : 'PF10_CASHC_CHILD_FAILED', message: error instanceof Error ? error.message : String(error) });
        }
      }
    }
    if (buffered.length !== 0) fail('PF10_CASHC_CHILD_REQUEST_INVALID', 'stdin ended with a truncated private frame');
  } catch (error) {
    await writeFrame({ schema: V2_PF10_CASHC_COMPILE_ERROR_SCHEMA, code: typeof error?.code === 'string' ? error.code : 'PF10_CASHC_CHILD_FAILED', message: error instanceof Error ? error.message : String(error) });
    process.exitCode = 1;
  }
}
if (typeof process.argv[1] === 'string' && fileURLToPath(import.meta.url) === process.argv[1]) main();
