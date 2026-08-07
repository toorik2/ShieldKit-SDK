/**
 * PF10 instance linker.
 *
 * This is deliberately not a byte-search-and-replace cache. It re-compiles
 * each retained CashScript source after replacing only its declared instance
 * and successor constants, proves the old source still compiles to the
 * retained raw program, then links canonical optimizer output only through
 * data-push locations which are proven to have changed in that raw program.
 * A changed compiler/optimizer layout is therefore a hard failure, never a
 * reason to issue a merely similar runtime.
 */
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { availableParallelism } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  binToHex,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';
import { compileString, utils as cashcUtils } from '../vendor/verifier/vendor/cashc-resched/packages/cashc/dist/index.js';
import {
  V2_PF10_CASHC_COMPILE_ERROR_SCHEMA,
  V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA,
  V2_PF10_CASHC_COMPILE_RESULT_SCHEMA,
} from './pf10-cashc-compile-child.mjs';
import { canonicalizeJcs } from '../../profile/v2/profile-core.mjs';
import { recordV2BetaRuntimeWork } from '../../profile/v2/beta-runtime-work-observer.mjs';
import {
  assertV2BetaProductLinkedRuntimeTemplateCapability,
} from '../../profile/v2/beta-product-artifact-installation.mjs';

import { DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, DIRECT_V2_PF10_FUSED_VERIFIER_ROLES } from '../../action/v2/topology.mjs';
import { deriveV2RollingBaseSats } from '../../action/v2/dust-policy.mjs';
import {
  DIRECT_V2_PF10_BETA_ELIGIBILITY,
  DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA,
  DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES,
  DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID,
  validateDirectV2Pf10BetaRuntimeMaterial,
} from './pf10-action-witness.mjs';
import { buildDirectV2Pf10FusedQGenesisRedeem } from './pf10-fused-q-genesis.mjs';
import { buildDirectV2PairFoldLoader, splitDirectV2PairFoldBody } from './total-pairfold-cashscript.mjs';
import {
  buildDirectV2BindingLock,
  buildDirectV2BindingRedeem,
  buildDirectV2StateHelper,
  buildDirectV2StateTrampolineLock,
  buildDirectV2StateTrampolineUnlock,
} from './structural-covenants.mjs';

export const V2_PF10_INSTANCE_SPECIALIZER_SCHEMA =
  'shieldkit-v2-direct-pf10-instance-specializer-v1';

const HEX_32 = /^[0-9a-f]{64}$/u;
const HASH = /^[0-9a-f]{64}$/u;
const DENOMINATION_SATS = 10_000_000n;
const MINIMUM_CHANGE_SATS = 546n;
const OPCOST_COMPILER_OPTIONS = Object.freeze({ optimizeFor: 'opcost', rescheduleStacks: true });
const CASHC_CHILD = fileURLToPath(new URL('./pf10-cashc-compile-child.mjs', import.meta.url));
const MAX_CHILD_PROTOCOL_BYTES = 8 * 1024 * 1024;
const MAX_CHILD_STDERR_BYTES = 64 * 1024;
const MAX_CHILDREN = Math.min(64, Math.max(1, availableParallelism()));

// These brands deliberately have no serializable representation. A profile
// cache can retain an authentic capability/result, but a JSON-shaped
// lookalike can never enter it as a specialized runtime.
const authenticatedTemplateCapabilities = new WeakMap();
const compiledCapabilitiesByTemplate = new WeakMap();
const receiptCapabilitiesByTemplate = new WeakMap();
const specializedRuntimeCapabilities = new WeakMap();

export class V2Pf10InstanceSpecializerError extends Error {
  constructor(code, message, cause = undefined) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'V2Pf10InstanceSpecializerError';
    this.code = code;
  }
}
const fail = (code, message, cause = undefined) => { throw new V2Pf10InstanceSpecializerError(code, message, cause); };
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const p2sh32 = (redeem) => Buffer.from(encodeLockingBytecodeP2sh32(hash256(redeem)));

function fingerprintPart(digest, tag, value) {
  const body = Buffer.from(value);
  digest.update(Buffer.from(`${tag}:${body.length}:`, 'utf8')).update(body);
}

function fingerprintTemplateValue(digest, value) {
  if (value instanceof Uint8Array) {
    fingerprintPart(digest, 'bytes', value);
  } else if (Array.isArray(value)) {
    fingerprintPart(digest, 'array', Buffer.from(String(value.length), 'utf8'));
    for (const item of value) fingerprintTemplateValue(digest, item);
  } else if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    fingerprintPart(digest, 'object', Buffer.from(String(keys.length), 'utf8'));
    for (const key of keys) {
      fingerprintPart(digest, 'key', Buffer.from(key, 'utf8'));
      fingerprintTemplateValue(digest, value[key]);
    }
  } else if (value === null) {
    fingerprintPart(digest, 'null', Buffer.alloc(0));
  } else {
    fingerprintPart(digest, typeof value, Buffer.from(String(value), 'utf8'));
  }
}

function templateFingerprint(template) {
  const digest = createHash('sha256');
  fingerprintTemplateValue(digest, template);
  return digest.digest('hex');
}

function identity(value, label) {
  if (typeof value !== 'string' || !HEX_32.test(value)) fail('PF10_LINK_INPUT_INVALID', `${label} must be lowercase 32-byte hex`);
  return value;
}
function bytes(value, label) {
  if (!(value instanceof Uint8Array) || value.byteLength === 0) fail('PF10_LINK_INPUT_INVALID', `${label} must be nonempty bytes`);
  return Buffer.from(value);
}
function exact(value, keys, label) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) {
    fail('PF10_LINK_INPUT_INVALID', `${label} has missing or unknown properties`);
  }
  return value;
}
function compile(source, files = {}) {
  try {
    return Buffer.from(cashcUtils.asmToBytecode(compileString(source, { files, ...OPCOST_COMPILER_OPTIONS }).bytecode));
  } catch (error) {
    fail('PF10_LINK_COMPILE_FAILED', `CashC compilation failed: ${error instanceof Error ? error.message : String(error)}`, error);
  }
}

function strictChildPayload(bytes, label) {
  if (bytes.length === 0 || bytes.length > MAX_CHILD_PROTOCOL_BYTES) fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child emitted an invalid response size`);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch (error) { fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child emitted invalid JSON`, error); }
  let canonical;
  try { canonical = Buffer.from(canonicalizeJcs(value), 'utf8'); } catch (error) { fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child emitted invalid JCS`, error); }
  if (!canonical.equals(bytes)) fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child response was not exact JCS`);
  return value;
}

function childResult(bytes, label) {
  const value = strictChildPayload(bytes, label);
  if (value?.schema === V2_PF10_CASHC_COMPILE_ERROR_SCHEMA) {
    exact(value, ['code', 'message', 'schema'], `${label} CashC child error`);
    if (typeof value.code !== 'string' || typeof value.message !== 'string') fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child error was malformed`);
    fail('PF10_LINK_COMPILE_CHILD_FAILED', `${label} CashC child failed (${value.code}): ${value.message}`);
  }
  exact(value, ['rawHex', 'schema'], `${label} CashC child result`);
  if (value.schema !== V2_PF10_CASHC_COMPILE_RESULT_SCHEMA || typeof value.rawHex !== 'string' || value.rawHex.length === 0 || value.rawHex.length % 2 !== 0 || !/^[0-9a-f]+$/u.test(value.rawHex)) {
    fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child result was malformed`);
  }
  return Buffer.from(value.rawHex, 'hex');
}

function delay(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

function childRequest({ label, source, lazyAffineLibrary = undefined }) {
  let input;
  try {
    input = Buffer.from(canonicalizeJcs({
      files: lazyAffineLibrary === undefined ? {} : { 'Bn254LazyAff.cash': lazyAffineLibrary },
      schema: V2_PF10_CASHC_COMPILE_REQUEST_SCHEMA,
      source,
    }), 'utf8');
  } catch (error) { fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child request could not be canonicalized`, error); }
  if (input.length === 0 || input.length > MAX_CHILD_PROTOCOL_BYTES) fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', `${label} CashC child request exceeds the protocol limit`);
  const header = Buffer.alloc(4); header.writeUInt32BE(input.length);
  return Buffer.concat([header, input]);
}

function startCashcChild() {
  let child;
  try {
    child = spawn(process.execPath, [CASHC_CHILD], {
      cwd: path.dirname(CASHC_CHILD), shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { LANG: 'C', LC_ALL: 'C', TZ: 'UTC' },
    });
  } catch (error) { fail('PF10_LINK_COMPILE_CHILD_SPAWN', 'CashC child could not be spawned', error); }
  let stdout = Buffer.alloc(0); let stderrBytes = 0; let terminal = false; let stopping = false; let current; let failed;
  const stop = (error) => {
    if (failed === undefined) failed = error;
    if (current !== undefined) { current.reject(failed); current = undefined; }
    if (!terminal) child.kill('SIGTERM');
  };
  child.stdout.on('data', (chunk) => {
    if (failed !== undefined) return;
    stdout = Buffer.concat([stdout, chunk]);
    while (stdout.length >= 4) {
      const length = stdout.readUInt32BE(0);
      if (length === 0 || length > MAX_CHILD_PROTOCOL_BYTES) {
        stop(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_PROTOCOL', 'CashC child emitted an invalid private frame length')); return;
      }
      if (stdout.length < 4 + length) return;
      const payload = stdout.subarray(4, 4 + length); stdout = stdout.subarray(4 + length);
      if (current === undefined) { stop(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_PROTOCOL', 'CashC child emitted an unsolicited private response')); return; }
      const request = current; current = undefined;
      try { request.resolve(childResult(payload, request.label)); } catch (error) { request.reject(error); }
    }
  });
  child.stderr.on('data', (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > MAX_CHILD_STDERR_BYTES) stop(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_PROTOCOL', 'CashC child exceeded its private stderr limit'));
  });
  const closed = new Promise((resolve) => {
    child.once('error', (error) => resolve(Object.freeze({ error })));
    child.once('close', (code, signal) => resolve(Object.freeze({ code, signal })));
  }).then((result) => {
    terminal = true;
    if (current !== undefined) {
      const reason = result.error ?? new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_EXIT', `CashC child exited (${result.signal ?? `exit ${result.code}`})`);
      current.reject(reason); current = undefined;
    }
    return result;
  });
  return Object.freeze({
    compile(job) {
      if (failed !== undefined) return Promise.reject(failed);
      if (terminal) return Promise.reject(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_EXIT', 'CashC child is no longer running'));
      if (current !== undefined) return Promise.reject(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_PROTOCOL', 'CashC child received concurrent requests'));
      let resolve; let reject; const done = new Promise((ok, no) => { resolve = ok; reject = no; });
      current = Object.freeze({ label: job.label, resolve, reject });
      const input = childRequest(job);
      try { child.stdin.write(input, (error) => { if (error != null) stop(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_IO', `${job.label} CashC child stdin failed`, error)); }); } catch (error) { stop(new V2Pf10InstanceSpecializerError('PF10_LINK_COMPILE_CHILD_IO', `${job.label} CashC child stdin failed`, error)); }
      return done;
    },
    async terminate() {
      if (terminal) return;
      stopping = true;
      child.stdin.end();
      await Promise.race([closed, delay(1_000)]);
      if (!terminal) child.kill('SIGTERM');
      await Promise.race([closed, delay(1_000)]);
      if (!terminal) { child.kill('SIGKILL'); await closed; }
    },
    async close() {
      if (terminal) return;
      stopping = true;
      child.stdin.end();
      await Promise.race([closed, delay(1_000)]);
      if (!terminal) { child.kill('SIGTERM'); await closed; }
    },
    get stopping() { return stopping; },
  });
}

async function createCashcChildPool() {
  // The DAG has at most three independent target nodes. Starting exactly that
  // many persistent children uses every independent core without excess forks.
  const children = [];
  try {
    for (let index = 0; index < Math.min(3, MAX_CHILDREN); index += 1) {
      recordV2BetaRuntimeWork({ type: 'compiler-child-spawn' });
      children.push(startCashcChild());
    }
  } catch (error) {
    await Promise.allSettled(children.map((child) => child.terminate()));
    throw error;
  }
  return Object.freeze({
    async compileBatch(jobs) {
      if (!Array.isArray(jobs) || jobs.length === 0 || jobs.length > 64) fail('PF10_LINK_COMPILE_CHILD_PROTOCOL', 'CashC child batch is outside its fixed bound');
      const results = [];
      for (let offset = 0; offset < jobs.length; offset += children.length) {
        const active = jobs.slice(offset, offset + children.length);
        try { results.push(...await Promise.all(active.map((job, index) => children[index].compile(job)))); } catch (error) {
          await Promise.allSettled(children.map((child) => child.terminate()));
          throw error;
        }
      }
      return Object.freeze(results);
    },
    async close() { await Promise.allSettled(children.map((child) => child.close())); },
  });
}

/** Run only independent compiler jobs concurrently on a persistent child pool. */
async function compileCashcBatch(pool, jobs) {
  return pool.compileBatch(jobs);
}


/** Parse bytecode while retaining each exact data-push payload offset. */
export function parseV2Pf10LinkBytecode(value, label = 'bytecode') {
  const program = bytes(value, label);
  const instructions = [];
  for (let offset = 0; offset < program.length;) {
    const start = offset; const opcode = program[offset++];
    let length = null;
    if (opcode >= 1 && opcode <= 75) length = opcode;
    else if (opcode === 0x4c) { if (offset >= program.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} has truncated PUSHDATA1`); length = program[offset++]; }
    else if (opcode === 0x4d) { if (offset + 1 >= program.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} has truncated PUSHDATA2`); length = program[offset] | (program[offset + 1] << 8); offset += 2; }
    else if (opcode === 0x4e) { if (offset + 3 >= program.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} has truncated PUSHDATA4`); length = program.readUInt32LE(offset); offset += 4; }
    if (length === null) { instructions.push(Object.freeze({ opcode, start, end: offset })); continue; }
    const dataOffset = offset; offset += length;
    if (offset > program.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} has truncated pushed data`);
    instructions.push(Object.freeze({ opcode, start, end: offset, dataOffset, data: Buffer.from(program.subarray(dataOffset, offset)) }));
  }
  return Object.freeze(instructions);
}

function replaceOne(source, from, to, label) {
  const needle = `0x${from}`;
  const hits = source.split(needle).length - 1;
  if (hits !== 1) fail('PF10_LINK_SOURCE_DRIFT', `${label} must contain exactly one declared constant (${hits} found)`);
  return source.replace(needle, `0x${to}`);
}
function sourceFor(program, { oldInstanceId, instanceId, replacements, label }) {
  if (typeof program?.source !== 'string' || typeof program?.raw !== 'object' || typeof program?.redeem !== 'object') {
    fail('PF10_LINK_INPUT_INVALID', `${label} must retain exact source/raw/redeem bytes`);
  }
  // CashScript source serializes this literal in the human/API byte order;
  // only the eventual token wire encoding is reversed elsewhere. Derive it
  // from the retained source itself, never from an assumed VM byte order.
  let source = replaceOne(program.source, oldInstanceId, instanceId, `${label} state category`);
  for (const [oldValue, newValue, name] of replacements) source = replaceOne(source, oldValue, newValue, `${label} ${name}`);
  return source;
}

function rawChanges(oldRaw, newRaw, label) {
  const before = parseV2Pf10LinkBytecode(oldRaw, `${label} retained raw`);
  const after = parseV2Pf10LinkBytecode(newRaw, `${label} target raw`);
  if (before.length !== after.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} raw instruction count drifted`);
  const substitutions = new Map();
  for (let index = 0; index < before.length; index += 1) {
    const left = before[index]; const right = after[index];
    if (left.opcode !== right.opcode || (left.dataOffset === undefined) !== (right.dataOffset === undefined)) {
      fail('PF10_LINK_LAYOUT_DRIFT', `${label} raw opcode/push layout drifted at instruction ${index}`);
    }
    if (left.dataOffset === undefined) continue;
    if (left.data.length !== right.data.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} raw push width drifted at instruction ${index}`);
    if (!left.data.equals(right.data)) {
      const key = left.data.toString('hex'); const next = right.data.toString('hex');
      const prior = substitutions.get(key);
      if (prior !== undefined && prior !== next) fail('PF10_LINK_LAYOUT_DRIFT', `${label} maps one raw constant to multiple targets`);
      substitutions.set(key, next);
    }
  }
  if (substitutions.size === 0) fail('PF10_LINK_LAYOUT_DRIFT', `${label} source changed but raw program did not`);
  return substitutions;
}

function linkCanonicalRedeem(redeem, substitutions, label) {
  const original = bytes(redeem, `${label} redeem`);
  const parsed = parseV2Pf10LinkBytecode(original, `${label} canonical redeem`);
  const linked = Buffer.from(original); const used = new Set();
  for (const instruction of parsed) {
    if (instruction.dataOffset === undefined) continue;
    const replacement = substitutions.get(instruction.data.toString('hex'));
    if (replacement === undefined) continue;
    const next = Buffer.from(replacement, 'hex');
    if (next.length !== instruction.data.length) fail('PF10_LINK_LAYOUT_DRIFT', `${label} canonical replacement changes push width`);
    next.copy(linked, instruction.dataOffset); used.add(instruction.data.toString('hex'));
  }
  for (const key of substitutions.keys()) if (!used.has(key)) fail('PF10_LINK_LAYOUT_DRIFT', `${label} optimizer layout no longer retains a changed raw constant`);
  return linked;
}

async function linkedProgram({ program, oldInstanceId, instanceId, replacements, label, lazyAffineLibrary = undefined, retainedAuthenticated = false, compiledRaw = undefined }) {
  const oldRaw = bytes(program.raw, `${label}.raw`);
  if (!retainedAuthenticated) {
    const retained = compile(program.source, lazyAffineLibrary === undefined ? {} : { 'Bn254LazyAff.cash': lazyAffineLibrary });
    if (!retained.equals(oldRaw)) fail('PF10_LINK_SOURCE_DRIFT', `${label} retained source no longer compiles to retained raw bytes`);
  }
  const source = sourceFor(program, { oldInstanceId, instanceId, replacements, label });
  const raw = compiledRaw === undefined
    ? compile(source, lazyAffineLibrary === undefined ? {} : { 'Bn254LazyAff.cash': lazyAffineLibrary })
    : bytes(compiledRaw, `${label}.compiledRaw`);
  const redeem = linkCanonicalRedeem(program.redeem, rawChanges(oldRaw, raw, label), label);
  const specialized = Object.freeze({
    source,
    raw,
    redeem,
    lock: p2sh32(redeem),
    hashes: Object.freeze({ source: sha256(Buffer.from(source, 'utf8')), raw: sha256(raw), redeem: sha256(redeem), lock: sha256(p2sh32(redeem)) }),
  });
  return specialized;
}

function literalData(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length % 2 !== 0 || !/^[0-9a-f]+$/iu.test(value)) fail('PF10_LINK_RELOCATION_INVALID', `${label} must be exact hex`);
  return Buffer.from(value, 'hex');
}
function declaredPushMatch(parsed, value, label) {
  const data = literalData(value, label); const matches = [];
  for (const instruction of parsed) {
    if (instruction.dataOffset === undefined) continue;
    for (let offset = instruction.data.indexOf(data); offset !== -1; offset = instruction.data.indexOf(data, offset + 1)) {
      matches.push(Object.freeze({ instruction, relativeOffset: offset }));
    }
  }
  if (matches.length !== 1) fail('PF10_LINK_RELOCATION_LAYOUT', `${label} requires exactly one declared retained push occurrence (${matches.length} found)`);
  return matches[0];
}

function relocatePushes(value, declarations, label) {
  const original = bytes(value, label);
  const parsed = parseV2Pf10LinkBytecode(original, `${label} retained`);
  const relocated = Buffer.from(original); const changed = [];
  for (const declaration of declarations) {
    const matched = declaredPushMatch(parsed, declaration.oldValue, `${label} ${declaration.name} old`);
    const oldData = literalData(declaration.oldValue, `${label} ${declaration.name} old`);
    const newData = literalData(declaration.newValue, `${label} ${declaration.name} new`);
    if (oldData.length !== newData.length) fail('PF10_LINK_RELOCATION_WIDTH', `${label} ${declaration.name} changes fixed push width`);
    const instruction = matched.instruction;
    const start = instruction.dataOffset + matched.relativeOffset;
    if (changed.some((range) => start < range.start + range.length && range.start < start + newData.length)) fail('PF10_LINK_RELOCATION_LAYOUT', `${label} declarations alias one retained push range`);
    newData.copy(relocated, start); changed.push(Object.freeze({ start, length: newData.length }));
  }
  const after = parseV2Pf10LinkBytecode(relocated, `${label} relocated`);
  if (after.length !== parsed.length) fail('PF10_LINK_RELOCATION_LAYOUT', `${label} instruction count changed during relocation`);
  for (let index = 0; index < parsed.length; index += 1) {
    const before = parsed[index]; const next = after[index];
    if (before.opcode !== next.opcode || before.start !== next.start || before.end !== next.end || before.dataOffset !== next.dataOffset) fail('PF10_LINK_RELOCATION_LAYOUT', `${label} opcode/push layout changed during relocation`);
    if (before.dataOffset === undefined) continue;
    if (before.data.length !== next.data.length) fail('PF10_LINK_RELOCATION_WIDTH', `${label} changed a declared push width`);
    for (let byte = 0; byte < before.data.length; byte += 1) if (before.data[byte] !== next.data[byte]) {
      const absolute = before.dataOffset + byte;
      if (!changed.some((range) => absolute >= range.start && absolute < range.start + range.length)) fail('PF10_LINK_RELOCATION_LAYOUT', `${label} contains an undeclared push change`);
    }
  }
  return relocated;
}

async function relocatedProgram({ program, oldInstanceId, instanceId, replacements, label }) {
  const source = sourceFor(program, { oldInstanceId, instanceId, replacements, label });
  const declarations = Object.freeze([
    Object.freeze({ oldValue: oldInstanceId, newValue: instanceId, name: 'state category' }),
    ...replacements.map(([oldValue, newValue, name]) => Object.freeze({ oldValue, newValue, name })),
  ]);
  const raw = relocatePushes(program.raw, declarations, `${label}.raw`);
  const redeem = relocatePushes(program.redeem, declarations, `${label}.redeem`);
  return Object.freeze({
    source,
    raw,
    redeem,
    lock: p2sh32(redeem),
    hashes: Object.freeze({ source: sha256(Buffer.from(source, 'utf8')), raw: sha256(raw), redeem: sha256(redeem), lock: sha256(p2sh32(redeem)) }),
  });
}


function templateInput(value) {
  if (value === null || Array.isArray(value) || typeof value !== 'object'
    || ['instanceId', 'layout', 'programs', 'runtimeMaterial', 'runtimeMaterialInput', 'structural']
      .some((name) => !Object.hasOwn(value, name))) {
    fail('PF10_LINK_INPUT_INVALID', 'PF10 linker template lacks required retained runtime fields');
  }
  const oldInstanceId = identity(value.instanceId, 'template.instanceId');
  const material = validateDirectV2Pf10BetaRuntimeMaterial(value.runtimeMaterialInput);
  if (value.runtimeMaterial?.materialSha256 !== material.materialSha256 || material.instanceId !== oldInstanceId
    || value.runtimeMaterialInput.instanceId !== oldInstanceId) fail('PF10_LINK_INPUT_INVALID', 'template runtime material is not the exact validated beta material');
  if (!Array.isArray(value.layout?.fragmentOffsets) || value.layout.fragmentOffsets.length !== 5) fail('PF10_LINK_INPUT_INVALID', 'template requires five retained executor fragment offsets');
  if (!Array.isArray(value.programs?.exactMsm) || value.programs.exactMsm.length !== 3) fail('PF10_LINK_INPUT_INVALID', 'template requires three retained exact-MSM programs');
  return Object.freeze({ value, oldInstanceId, material });
}

function retainedPrograms(template) {
  return Object.freeze([
    ['terminal', template.programs.terminal, true],
    ['executor', template.programs.executor, true],
    ['exact-final', template.programs.exactFinal, false],
    ['miller', template.programs.miller, true],
    ...template.programs.exactMsm.map((program, index) => [`exact-msm-${index}`, program, false]),
  ]);
}

function proveRetainedPrograms(template, lazyAffineLibrary) {
  for (const [label, program, needsLazyAffineLibrary] of retainedPrograms(template)) {
    const retained = compile(program.source, needsLazyAffineLibrary ? { 'Bn254LazyAff.cash': lazyAffineLibrary } : {});
    if (!retained.equals(bytes(program.raw, `${label}.raw`))) {
      fail('PF10_LINK_SOURCE_DRIFT', `${label} retained source no longer compiles to retained raw bytes`);
    }
  }
}

function capabilityRecord(capability) {
  const record = authenticatedTemplateCapabilities.get(capability);
  if (record === undefined) fail('PF10_LINK_TEMPLATE_CAPABILITY_INVALID', 'template capability lacks the opaque PF10 linker brand');
  if (record.receiptTemplate !== undefined) {
    assertV2BetaProductLinkedRuntimeTemplateCapability(record.receiptTemplate);
  }
  // Validate both the beta material and all linker-relevant bytes before a
  // cached proof is trusted. This is intentionally cheap, but detects mutable
  // Buffer/source changes as well as a substituted template object.
  templateInput(record.template);
  if (templateFingerprint(record.template) !== record.templateFingerprint) {
    fail('PF10_LINK_TEMPLATE_CAPABILITY_STALE', 'authenticated template bytes changed after attestation');
  }
  return record;
}

/**
 * Assert an opaque template capability issued by this module. The returned
 * value is the same opaque object; its associated template remains private to
 * the linker and cannot be reconstructed from serialized fields.
 */
export function assertV2Pf10AuthenticatedTemplateCapability(capability) {
  capabilityRecord(capability);
  return capability;
}

/**
 * Attest all retained source/raw pairs once. Reusing the returned opaque
 * capability avoids only those redundant proofs; every target specialization
 * is still compiled and layout-checked from source.
 */
export async function authenticateV2Pf10BetaRuntimeTemplate({ repositoryRoot, template } = {}) {
  if (typeof repositoryRoot !== 'string' || !path.isAbsolute(repositoryRoot)) fail('PF10_LINK_INPUT_INVALID', 'repositoryRoot must be absolute');
  const root = path.resolve(repositoryRoot);
  const { value } = templateInput(template);
  const lazyAffineLibrary = await readFile(path.join(root, 'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash'), 'utf8');
  const fingerprint = templateFingerprint(value);
  const librarySha256 = sha256(Buffer.from(lazyAffineLibrary, 'utf8'));
  const existing = compiledCapabilitiesByTemplate.get(value);
  if (existing !== undefined) {
    const record = capabilityRecord(existing);
    if (record.repositoryRoot === root && record.librarySha256 === librarySha256 && record.templateFingerprint === fingerprint) return existing;
  }
  proveRetainedPrograms(value, lazyAffineLibrary);
  const capability = Object.freeze(Object.create(null));
  authenticatedTemplateCapabilities.set(capability, Object.freeze({
    attestation: 'compiler-source-rebuild',
    repositoryRoot: root, template: value, templateFingerprint: fingerprint, librarySha256,
  }));
  compiledCapabilitiesByTemplate.set(value, capability);
  return capability;
}

/**
 * Warm production attestation. The profile layer has already fully rebuilt and
 * verified this runtime at installation, then re-read the fixed linker
 * allow-list against the durable receipt. This path preserves that opaque
 * authority and re-fingerprints every retained byte without invoking CashC.
 */
export async function authenticateV2Pf10ReceiptLinkedRuntimeTemplate({
  repositoryRoot,
  linkedTemplate,
} = {}) {
  if (typeof repositoryRoot !== 'string' || !path.isAbsolute(repositoryRoot)) {
    fail('PF10_LINK_INPUT_INVALID', 'repositoryRoot must be absolute');
  }
  const receiptTemplate = assertV2BetaProductLinkedRuntimeTemplateCapability(linkedTemplate);
  const root = path.resolve(repositoryRoot);
  const { value } = templateInput(receiptTemplate.template);
  const lazyAffineLibrary = await readFile(path.join(
    root,
    'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash',
  ), 'utf8');
  const fingerprint = templateFingerprint(value);
  const librarySha256 = sha256(Buffer.from(lazyAffineLibrary, 'utf8'));
  const existing = receiptCapabilitiesByTemplate.get(value);
  if (existing !== undefined) {
    const record = capabilityRecord(existing);
    if (record.repositoryRoot === root && record.librarySha256 === librarySha256
      && record.templateFingerprint === fingerprint) return existing;
  }
  const capability = Object.freeze(Object.create(null));
  authenticatedTemplateCapabilities.set(capability, Object.freeze({
    attestation: 'receipt-verified-installation',
    librarySha256,
    receiptTemplate,
    repositoryRoot: root,
    template: value,
    templateFingerprint: fingerprint,
  }));
  receiptCapabilitiesByTemplate.set(value, capability);
  return capability;
}


/**
 * Specialize a retained full PF10 beta builder result without executing the
 * optimizer. It validates the source/raw/optimized layout before every
 * constant-bearing successor edge and returns a normal validator-branded beta
 * material plus the complete specialized structural runtime.
 */
export async function specializeV2Pf10BetaRuntime({ repositoryRoot, template = undefined, templateCapability = undefined, instanceId } = {}) {
  recordV2BetaRuntimeWork({ type: 'instance-specialization' });
  if (typeof repositoryRoot !== 'string' || !path.isAbsolute(repositoryRoot)) fail('PF10_LINK_INPUT_INVALID', 'repositoryRoot must be absolute');
  const targetInstanceId = identity(instanceId, 'instanceId');
  const root = path.resolve(repositoryRoot);
  const capability = templateCapability === undefined
    ? await authenticateV2Pf10BetaRuntimeTemplate({ repositoryRoot: root, template })
    : assertV2Pf10AuthenticatedTemplateCapability(templateCapability);
  const attestation = capabilityRecord(capability);
  if (attestation.repositoryRoot !== root) fail('PF10_LINK_TEMPLATE_CAPABILITY_INVALID', 'template capability was issued for a different repository root');
  if (template !== undefined && template !== attestation.template) fail('PF10_LINK_TEMPLATE_CAPABILITY_INVALID', 'template does not match the supplied opaque capability');
  const { value: source, oldInstanceId, material } = templateInput(attestation.template);
  if (targetInstanceId === oldInstanceId) fail('PF10_LINK_INPUT_INVALID', 'instanceId must differ from the retained template instance');
  const lazyAffineLibrary = await readFile(path.join(root, 'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash'), 'utf8');
  if (sha256(Buffer.from(lazyAffineLibrary, 'utf8')) !== attestation.librarySha256) {
    fail('PF10_LINK_TEMPLATE_CAPABILITY_STALE', 'the authenticated CashScript dependency changed after template attestation');
  }
  const compilerPool = await createCashcChildPool();
  try {
  const bindingRedeem = Buffer.from(buildDirectV2BindingRedeem({ networkId: 2, profileId: material.profileId, stateCategory: targetInstanceId, denominationSats: DENOMINATION_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
  const bindingLock = Buffer.from(buildDirectV2BindingLock({ networkId: 2, profileId: material.profileId, stateCategory: targetInstanceId, denominationSats: DENOMINATION_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
  const old = source.structural;
  const oldBindingLockHash = sha256(old.bindingLock);
  const bindingLockHash = sha256(bindingLock);
  const terminalSource = sourceFor(source.programs.terminal, { oldInstanceId, instanceId: targetInstanceId, replacements: [], label: 'terminal' });
  const [terminalRaw] = await compileCashcBatch(compilerPool, [{ label: 'terminal', source: terminalSource, lazyAffineLibrary }]);
  const terminal = await linkedProgram({ program: source.programs.terminal, oldInstanceId, instanceId: targetInstanceId, replacements: [], label: 'terminal', lazyAffineLibrary, retainedAuthenticated: true, compiledRaw: terminalRaw });
  const executorReplacements = [[binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const exactFinalReplacements = [[oldBindingLockHash, bindingLockHash, 'binding lock hash'], [binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const millerReplacements = [[binToHex(old.bindingLock), binToHex(bindingLock), 'binding lock'], [binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const [executorRaw, exactFinalRaw, millerRaw] = await compileCashcBatch(compilerPool, [
    { label: 'executor', source: sourceFor(source.programs.executor, { oldInstanceId, instanceId: targetInstanceId, replacements: executorReplacements, label: 'executor' }), lazyAffineLibrary },
    { label: 'exact-final', source: sourceFor(source.programs.exactFinal, { oldInstanceId, instanceId: targetInstanceId, replacements: exactFinalReplacements, label: 'exact-final' }) },
    { label: 'miller', source: sourceFor(source.programs.miller, { oldInstanceId, instanceId: targetInstanceId, replacements: millerReplacements, label: 'miller' }), lazyAffineLibrary },
  ]);
  const [executor, exactFinal, miller] = await Promise.all([
    linkedProgram({ program: source.programs.executor, oldInstanceId, instanceId: targetInstanceId, replacements: executorReplacements, label: 'executor', lazyAffineLibrary, retainedAuthenticated: true, compiledRaw: executorRaw }),
    linkedProgram({ program: source.programs.exactFinal, oldInstanceId, instanceId: targetInstanceId, replacements: exactFinalReplacements, label: 'exact-final', retainedAuthenticated: true, compiledRaw: exactFinalRaw }),
    linkedProgram({ program: source.programs.miller, oldInstanceId, instanceId: targetInstanceId, replacements: millerReplacements, label: 'miller', lazyAffineLibrary, retainedAuthenticated: true, compiledRaw: millerRaw }),
  ]);
  const fragments = splitDirectV2PairFoldBody(executor.redeem);
  const loader = buildDirectV2PairFoldLoader({ body: executor.redeem, fragmentOffsets: source.layout.fragmentOffsets, fragmentLengths: fragments.map((entry) => entry.length), functionId: DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID, densityPadBytes: DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES });
  const fusedRedeem = Buffer.from(buildDirectV2Pf10FusedQGenesisRedeem({ millerRedeem: miller.redeem, exactMsmRedeem: exactFinal.redeem }));
  const fusedLock = p2sh32(fusedRedeem);
  const exactMsm = Array(3);
  let successorOld = Buffer.from(old.verifierLocks[8]); let successorNew = fusedLock;
  for (let index = 2; index >= 0; index -= 1) {
    const replacements = [[oldBindingLockHash, bindingLockHash, 'binding lock hash'], [binToHex(successorOld), binToHex(successorNew), 'successor lock']];
    const label = `exact-msm-${index}`;
    const [raw] = await compileCashcBatch(compilerPool, [{ label, source: sourceFor(source.programs.exactMsm[index], { oldInstanceId, instanceId: targetInstanceId, replacements, label }) }]);
    const program = await linkedProgram({ program: source.programs.exactMsm[index], oldInstanceId, instanceId: targetInstanceId, replacements, label, retainedAuthenticated: true, compiledRaw: raw });
    exactMsm[index] = program; successorOld = Buffer.from(old.verifierLocks[index + 5]); successorNew = program.lock;
  }
  const verifierLocks = Object.freeze([...Array(5).fill(Buffer.from(loader.lock)), ...exactMsm.map((entry) => Buffer.from(entry.lock)), fusedLock, terminal.lock]);
  const verifierSats = Object.freeze(verifierLocks.map((lockingBytecode) => deriveV2RollingBaseSats({ lockingBytecode })));
  const bindingSats = deriveV2RollingBaseSats({ lockingBytecode: bindingLock });
  let stateSats = 1_000n; let helper; let stateLock; let converged = false;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    helper = Buffer.from(buildDirectV2StateHelper({ bindingLock, verifierLocks, verifierBaseValues: verifierSats, bindingBaseValueSats: bindingSats, stateBaseValueSats: stateSats, denominationSats: DENOMINATION_SATS, stateCategory: targetInstanceId, minimumChangeSats: MINIMUM_CHANGE_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
    stateLock = Buffer.from(buildDirectV2StateTrampolineLock({ helper, bindingLock, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
    const next = deriveV2RollingBaseSats({ lockingBytecode: stateLock, token: { category: Buffer.from(targetInstanceId, 'hex'), amount: 0n, nft: { capability: 'mutable', commitment: Buffer.alloc(128) } } });
    if (next === stateSats) { converged = true; break; } stateSats = next;
  }
  if (!converged) fail('PF10_LINK_DUST_BASE_DID_NOT_CONVERGE', 'target state dust base did not converge');
  const stateUnlock = Buffer.from(buildDirectV2StateTrampolineUnlock(helper));
  const runtimeMaterialInput = Object.freeze({ schema: DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA, eligibility: DIRECT_V2_PF10_BETA_ELIGIBILITY, profileId: material.profileId, instanceId: targetInstanceId, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES, proofArtifactHashes: material.proofArtifactHashes, verificationKeyBytes: source.runtimeMaterialInput.verificationKeyBytes, executorBody: executor.redeem, exactMsmRedeems: exactMsm.map((entry) => entry.redeem), fixedCarrierPads: source.runtimeMaterialInput.fixedCarrierPads, fusedRedeem, terminalRedeem: terminal.redeem, stateUnlockingBytecode: stateUnlock, bindingRedeemBytecode: bindingRedeem, bindingLockingBytecode: bindingLock, verifierLockingBytecodes: verifierLocks });
  const runtimeMaterial = validateDirectV2Pf10BetaRuntimeMaterial(runtimeMaterialInput);
  const specialized = Object.freeze({
    schema: V2_PF10_INSTANCE_SPECIALIZER_SCHEMA,
    instanceId: targetInstanceId,
    profileId: material.profileId,
    runtimeMaterial,
    runtimeMaterialInput,
    baseValues: Object.freeze({
      verifierSats: Object.freeze(verifierSats.map(String)),
      bindingSats: bindingSats.toString(), stateSats: stateSats.toString(),
      minimumChangeSats: MINIMUM_CHANGE_SATS.toString(),
    }),
    layout: Object.freeze({
      ...source.layout,
      fragmentLengths: Object.freeze(fragments.map((entry) => entry.length)),
    }),
    programs: Object.freeze({
      terminal, executor, exactFinal, miller,
      fused: Object.freeze({ redeem: fusedRedeem, lock: fusedLock, hashes: Object.freeze({ redeem: sha256(fusedRedeem), lock: sha256(fusedLock) }) }),
      exactMsm: Object.freeze(exactMsm),
    }),
    structural: Object.freeze({ bindingRedeem, bindingLock, stateHelper: helper, stateUnlock, stateLock, verifierLocks }),
    fixedTables: source.fixedTables,
  });
  specializedRuntimeCapabilities.set(specialized, Object.freeze({
    instanceId: targetInstanceId,
    materialSha256: runtimeMaterial.materialSha256,
    templateCapability: capability,
  }));
  return specialized;
  } finally {
    await compilerPool.close();
  }
}

/**
 * Production warm path: relocate only receipt-attested, fixed-width data
 * pushes. Unlike the compiler-backed specializer above, this never invokes
 * CashC or the optimizer; callers retain that function as a qualification
 * oracle and must compare it before promotion.
 */
export async function relocateV2Pf10BetaRuntime({ repositoryRoot, template = undefined, templateCapability = undefined, instanceId } = {}) {
  if (typeof repositoryRoot !== 'string' || !path.isAbsolute(repositoryRoot)) fail('PF10_LINK_INPUT_INVALID', 'repositoryRoot must be absolute');
  const targetInstanceId = identity(instanceId, 'instanceId');
  const root = path.resolve(repositoryRoot);
  const capability = templateCapability === undefined
    ? await authenticateV2Pf10BetaRuntimeTemplate({ repositoryRoot: root, template })
    : assertV2Pf10AuthenticatedTemplateCapability(templateCapability);
  const attestation = capabilityRecord(capability);
  if (attestation.repositoryRoot !== root) fail('PF10_LINK_TEMPLATE_CAPABILITY_INVALID', 'template capability was issued for a different repository root');
  if (template !== undefined && template !== attestation.template) fail('PF10_LINK_TEMPLATE_CAPABILITY_INVALID', 'template does not match the supplied opaque capability');
  recordV2BetaRuntimeWork({ type: 'instance-specialization' });
  const { value: source, oldInstanceId, material } = templateInput(attestation.template);
  if (targetInstanceId === oldInstanceId) fail('PF10_LINK_INPUT_INVALID', 'instanceId must differ from the retained template instance');
  const lazyAffineLibrary = await readFile(path.join(root, 'shieldkit-groth-94kb/packages/unlock-builder/vendor/verifier/build/singleton/bn254/lib/lazy/Bn254LazyAff_kspec.cash'), 'utf8');
  if (sha256(Buffer.from(lazyAffineLibrary, 'utf8')) !== attestation.librarySha256) fail('PF10_LINK_TEMPLATE_CAPABILITY_STALE', 'the authenticated CashScript dependency changed after template attestation');
  const bindingRedeem = Buffer.from(buildDirectV2BindingRedeem({ networkId: 2, profileId: material.profileId, stateCategory: targetInstanceId, denominationSats: DENOMINATION_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
  const bindingLock = Buffer.from(buildDirectV2BindingLock({ networkId: 2, profileId: material.profileId, stateCategory: targetInstanceId, denominationSats: DENOMINATION_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
  const old = source.structural;
  const oldBindingLockHash = sha256(old.bindingLock); const bindingLockHash = sha256(bindingLock);
  const terminal = await relocatedProgram({ program: source.programs.terminal, oldInstanceId, instanceId: targetInstanceId, replacements: [], label: 'terminal' });
  const executorReplacements = [[binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const exactFinalReplacements = [[oldBindingLockHash, bindingLockHash, 'binding lock hash'], [binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const millerReplacements = [[binToHex(old.bindingLock), binToHex(bindingLock), 'binding lock'], [binToHex(old.verifierLocks[9]), binToHex(terminal.lock), 'terminal successor lock']];
  const [executor, exactFinal, miller] = await Promise.all([
    relocatedProgram({ program: source.programs.executor, oldInstanceId, instanceId: targetInstanceId, replacements: executorReplacements, label: 'executor' }),
    relocatedProgram({ program: source.programs.exactFinal, oldInstanceId, instanceId: targetInstanceId, replacements: exactFinalReplacements, label: 'exact-final' }),
    relocatedProgram({ program: source.programs.miller, oldInstanceId, instanceId: targetInstanceId, replacements: millerReplacements, label: 'miller' }),
  ]);
  const fragments = splitDirectV2PairFoldBody(executor.redeem);
  const loader = buildDirectV2PairFoldLoader({ body: executor.redeem, fragmentOffsets: source.layout.fragmentOffsets, fragmentLengths: fragments.map((entry) => entry.length), functionId: DIRECT_V2_PF10_EXECUTOR_FUNCTION_ID, densityPadBytes: DIRECT_V2_PF10_EXECUTOR_DENSITY_PAD_BYTES });
  const fusedRedeem = Buffer.from(buildDirectV2Pf10FusedQGenesisRedeem({ millerRedeem: miller.redeem, exactMsmRedeem: exactFinal.redeem }));
  const fusedLock = p2sh32(fusedRedeem);
  const exactMsm = Array(3); let successorOld = Buffer.from(old.verifierLocks[8]); let successorNew = fusedLock;
  for (let index = 2; index >= 0; index -= 1) {
    const replacements = [[oldBindingLockHash, bindingLockHash, 'binding lock hash'], [binToHex(successorOld), binToHex(successorNew), 'successor lock']];
    const program = await relocatedProgram({ program: source.programs.exactMsm[index], oldInstanceId, instanceId: targetInstanceId, replacements, label: `exact-msm-${index}` });
    exactMsm[index] = program; successorOld = Buffer.from(old.verifierLocks[index + 5]); successorNew = program.lock;
  }
  const verifierLocks = Object.freeze([...Array(5).fill(Buffer.from(loader.lock)), ...exactMsm.map((entry) => Buffer.from(entry.lock)), fusedLock, terminal.lock]);
  const verifierSats = Object.freeze(verifierLocks.map((lockingBytecode) => deriveV2RollingBaseSats({ lockingBytecode })));
  const bindingSats = deriveV2RollingBaseSats({ lockingBytecode: bindingLock });
  let stateSats = 1_000n; let helper; let stateLock; let converged = false;
  for (let iteration = 0; iteration < 8; iteration += 1) {
    helper = Buffer.from(buildDirectV2StateHelper({ bindingLock, verifierLocks, verifierBaseValues: verifierSats, bindingBaseValueSats: bindingSats, stateBaseValueSats: stateSats, denominationSats: DENOMINATION_SATS, stateCategory: targetInstanceId, minimumChangeSats: MINIMUM_CHANGE_SATS, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
    stateLock = Buffer.from(buildDirectV2StateTrampolineLock({ helper, bindingLock, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES }));
    const next = deriveV2RollingBaseSats({ lockingBytecode: stateLock, token: { category: Buffer.from(targetInstanceId, 'hex'), amount: 0n, nft: { capability: 'mutable', commitment: Buffer.alloc(128) } } });
    if (next === stateSats) { converged = true; break; } stateSats = next;
  }
  if (!converged) fail('PF10_LINK_DUST_BASE_DID_NOT_CONVERGE', 'target state dust base did not converge');
  const stateUnlock = Buffer.from(buildDirectV2StateTrampolineUnlock(helper));
  const runtimeMaterialInput = Object.freeze({ schema: DIRECT_V2_PF10_BETA_RUNTIME_SCHEMA, eligibility: DIRECT_V2_PF10_BETA_ELIGIBILITY, profileId: material.profileId, instanceId: targetInstanceId, topologyId: DIRECT_V2_PF10_FUSED_TOPOLOGY_ID, verifierRoles: DIRECT_V2_PF10_FUSED_VERIFIER_ROLES, proofArtifactHashes: material.proofArtifactHashes, verificationKeyBytes: source.runtimeMaterialInput.verificationKeyBytes, executorBody: executor.redeem, exactMsmRedeems: exactMsm.map((entry) => entry.redeem), fixedCarrierPads: source.runtimeMaterialInput.fixedCarrierPads, fusedRedeem, terminalRedeem: terminal.redeem, stateUnlockingBytecode: stateUnlock, bindingRedeemBytecode: bindingRedeem, bindingLockingBytecode: bindingLock, verifierLockingBytecodes: verifierLocks });
  const runtimeMaterial = validateDirectV2Pf10BetaRuntimeMaterial(runtimeMaterialInput);
  const specialized = Object.freeze({ schema: V2_PF10_INSTANCE_SPECIALIZER_SCHEMA, instanceId: targetInstanceId, profileId: material.profileId, runtimeMaterial, runtimeMaterialInput, baseValues: Object.freeze({ verifierSats: Object.freeze(verifierSats.map(String)), bindingSats: bindingSats.toString(), stateSats: stateSats.toString(), minimumChangeSats: MINIMUM_CHANGE_SATS.toString() }), layout: Object.freeze({ ...source.layout, fragmentLengths: Object.freeze(fragments.map((entry) => entry.length)) }), programs: Object.freeze({ terminal, executor, exactFinal, miller, fused: Object.freeze({ redeem: fusedRedeem, lock: fusedLock, hashes: Object.freeze({ redeem: sha256(fusedRedeem), lock: sha256(fusedLock) }) }), exactMsm: Object.freeze(exactMsm) }), structural: Object.freeze({ bindingRedeem, bindingLock, stateHelper: helper, stateUnlock, stateLock, verifierLocks }), fixedTables: source.fixedTables });
  specializedRuntimeCapabilities.set(specialized, Object.freeze({ instanceId: targetInstanceId, materialSha256: runtimeMaterial.materialSha256, templateCapability: capability }));
  return specialized;
}

/** Reject structural lookalikes; only this module can issue the brand. */
export function assertV2Pf10SpecializedRuntimeCapability(value) {
  const record = specializedRuntimeCapabilities.get(value);
  if (record === undefined) fail('PF10_LINK_SPECIALIZED_CAPABILITY_INVALID', 'specialized runtime lacks the opaque PF10 linker brand');
  if (value.instanceId !== record.instanceId || value.runtimeMaterial?.materialSha256 !== record.materialSha256) {
    fail('PF10_LINK_SPECIALIZED_CAPABILITY_STALE', 'specialized runtime identity or material commitment changed after issuance');
  }
  const checked = validateDirectV2Pf10BetaRuntimeMaterial(value.runtimeMaterialInput);
  if (checked.materialSha256 !== record.materialSha256 || checked.instanceId !== record.instanceId) {
    fail('PF10_LINK_SPECIALIZED_CAPABILITY_STALE', 'specialized runtime material no longer validates to its branded commitment');
  }
  return value;
}

/** Profile-layer installer derivation: branded runtime material only. */
export function deriveV2Pf10SpecializedRuntimeMaterial(value) {
  return assertV2Pf10SpecializedRuntimeCapability(value).runtimeMaterial;
}

/** Compare every executable and structural byte field of two same-ID builds. */
export function assertV2Pf10SpecializedRuntimeByteEquality(left, right) {
  if (left?.instanceId !== right?.instanceId || !HEX_32.test(left?.instanceId ?? '')) {
    fail('PF10_LINK_EQUALITY_INVALID', 'byte equality requires two runtimes for one exact instance ID');
  }
  const checkBytes = (a, b, label) => {
    if (!Buffer.from(a ?? []).equals(Buffer.from(b ?? []))) fail('PF10_LINK_BYTE_MISMATCH', `${label} differs from independent full build`);
  };
  if (left.runtimeMaterial?.materialSha256 !== right.runtimeMaterial?.materialSha256) fail('PF10_LINK_BYTE_MISMATCH', 'runtime material commitment differs from independent full build');
  for (const name of ['bindingRedeem', 'bindingLock', 'stateHelper', 'stateUnlock', 'stateLock']) checkBytes(left.structural?.[name], right.structural?.[name], `structural.${name}`);
  for (let index = 0; index < 10; index += 1) checkBytes(left.structural?.verifierLocks?.[index], right.structural?.verifierLocks?.[index], `structural.verifierLocks[${index}]`);
  for (const name of ['terminal', 'executor', 'exactFinal', 'miller']) {
    for (const field of ['source', 'raw', 'redeem', 'lock']) {
      const a = field === 'source' ? Buffer.from(left.programs?.[name]?.[field] ?? '', 'utf8') : left.programs?.[name]?.[field];
      const b = field === 'source' ? Buffer.from(right.programs?.[name]?.[field] ?? '', 'utf8') : right.programs?.[name]?.[field];
      checkBytes(a, b, `programs.${name}.${field}`);
    }
  }
  for (let index = 0; index < 3; index += 1) for (const field of ['source', 'raw', 'redeem', 'lock']) {
    const a = field === 'source' ? Buffer.from(left.programs?.exactMsm?.[index]?.[field] ?? '', 'utf8') : left.programs?.exactMsm?.[index]?.[field];
    const b = field === 'source' ? Buffer.from(right.programs?.exactMsm?.[index]?.[field] ?? '', 'utf8') : right.programs?.exactMsm?.[index]?.[field];
    checkBytes(a, b, `programs.exactMsm[${index}].${field}`);
  }
  checkBytes(left.programs?.fused?.redeem, right.programs?.fused?.redeem, 'programs.fused.redeem');
  checkBytes(left.programs?.fused?.lock, right.programs?.fused?.lock, 'programs.fused.lock');
  return Object.freeze({ schema: V2_PF10_INSTANCE_SPECIALIZER_SCHEMA, instanceId: left.instanceId, runtimeMaterialSha256: left.runtimeMaterial.materialSha256, byteEqual: true });
}
