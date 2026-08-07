/**
 * Result envelopes with exact identity fields.
 */

import { buildIdentityFields } from './identity.mjs';
import { isOperationState } from './operation-states.mjs';

export const RESULT_SCHEMA = 'shieldkit-cli-result/v1';

/**
 * Success or fail-closed result envelope.
 */
export function buildResultEnvelope({
  ok,
  code = null,
  error = null,
  command = null,
  identity = null,
  operationState = null,
  result = null,
  warnings = [],
  deprecation = null,
} = {}) {
  if (ok !== true && ok !== false) throw new Error('ok must be boolean');
  if (operationState !== null && !isOperationState(operationState)) {
    throw new Error(`invalid operationState: ${operationState}`);
  }
  let id = null;
  if (identity) {
    id = buildIdentityFields(identity);
  }
  return Object.freeze({
    schema: RESULT_SCHEMA,
    ok,
    code: code === null ? (ok ? null : 'ERROR') : code,
    error: ok ? null : (typeof error === 'string' ? error : error?.message ?? String(error)),
    command,
    identity: id,
    operationState,
    result: result === undefined ? null : result,
    warnings: Object.freeze([...(warnings || [])]),
    deprecation: deprecation === null ? null : Object.freeze({ ...deprecation }),
  });
}

export function printEnvelope(envelope, { json = true, stream = process.stdout } = {}) {
  if (json) {
    stream.write(`${JSON.stringify(envelope, null, 2)}\n`);
  } else if (envelope.ok) {
    stream.write(`${envelope.command ?? 'ok'}\n`);
  } else {
    stream.write(`${envelope.code}: ${envelope.error}\n`);
  }
}
