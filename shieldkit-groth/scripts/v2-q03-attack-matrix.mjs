/*
 * Pure PF10 negative-conformance matrix and typed byte-closure validator.
 *
 * This module has no filesystem, signing, VM, or qualification authority. A
 * caller must independently authenticate the raw bytes and execute them in
 * every required VM lane.
 */
import { createHash } from 'node:crypto';

import { canonicalizeJcs } from '../packages/profile/v2/profile-core.mjs';

export const V2_Q03_ACTIONS = Object.freeze([
  'deposit',
  'transfer',
  'withdrawal',
]);
export const V2_Q03_VERIFIER_ROLES = Object.freeze([
  'exec0',
  'exec1',
  'exec2',
  'exec3',
  'exec4',
  'msm5',
  'msm6',
  'msm7',
  'fused-q-genesis8',
  'terminal9',
]);
export const V2_Q03_ALL_INPUT_ROLES = Object.freeze([
  ...V2_Q03_VERIFIER_ROLES,
  'binding',
  'state',
  'funding',
]);
export const V2_Q03_ATTACK_MATRIX_CASE_COUNT_PER_ACTION = 73;
export const V2_Q03_ATTACK_MATRIX_CASE_COUNT = 219;

const ROLE_INDEX = Object.freeze(Object.fromEntries(
  V2_Q03_ALL_INPUT_ROLES.map((role, index) => [role, index]),
));
const LATE_ROLES = Object.freeze(V2_Q03_VERIFIER_ROLES.slice(5));
const FUNDING_INDEX = ROLE_INDEX.funding;
const STATE_INDEX = ROLE_INDEX.state;
const ROLLING_LAST_INDEX = STATE_INDEX;

export class V2Q03AttackMatrixError extends Error {
  constructor(message) {
    super(message);
    this.name = 'V2Q03AttackMatrixError';
  }
}

const fail = (message) => {
  throw new V2Q03AttackMatrixError(message);
};
const canonical = (value) => Buffer.from(canonicalizeJcs(value), 'utf8');
const digest = (value) => createHash('sha256').update(value).digest('hex');
const same = (left, right) => canonical(left).equals(canonical(right));
const clone = (value) => structuredClone(value);

function caseRecord(action, family, role, extra = {}) {
  const { suffix = '', ...metadata } = extra;
  const inputIndex = ROLE_INDEX[role];
  return Object.freeze({
    action,
    caseId: `${action}:${family}:${role}${suffix}`,
    family,
    inputIndex,
    role,
    successorOutputIndex:
      role === 'state' ? 0 : role === 'funding' ? null : inputIndex + 1,
    ...metadata,
  });
}

function casesForAction(action) {
  const entries = [];
  for (const role of V2_Q03_VERIFIER_ROLES) {
    entries.push(caseRecord(action, 'standalone-burn', role));
  }
  for (const role of V2_Q03_VERIFIER_ROLES) {
    entries.push(caseRecord(action, 'partial-bundle', role));
  }
  for (const role of [...V2_Q03_VERIFIER_ROLES, 'binding', 'state']) {
    entries.push(caseRecord(action, 'mixed-parent', role));
  }
  entries.push(caseRecord(action, 'fake-category', 'state'));
  for (const role of [...V2_Q03_VERIFIER_ROLES, 'binding', 'funding']) {
    entries.push(caseRecord(action, 'duplicate-state-nft', role));
  }
  entries.push(caseRecord(action, 'minting-authority', 'state'));
  for (const role of [...V2_Q03_VERIFIER_ROLES, 'binding']) {
    entries.push(caseRecord(action, 'omitted-successor', role));
  }
  for (const role of ['binding', 'state', 'funding']) {
    entries.push(caseRecord(action, 'altered-role-count', role, {
      mode: 'missing',
      suffix: ':missing',
    }));
  }
  entries.push(caseRecord(action, 'altered-role-count', 'funding', {
    mode: 'extra-input',
    suffix: ':extra-input',
  }));
  entries.push(caseRecord(action, 'altered-role-count', 'funding', {
    mode: 'extra-output',
    suffix: ':extra-output',
  }));
  for (let left = 0; left < LATE_ROLES.length; left += 1) {
    for (let right = left + 1; right < LATE_ROLES.length; right += 1) {
      entries.push(Object.freeze({
        action,
        branch: 'affine',
        caseId:
          `${action}:role-swap:${LATE_ROLES[left]}:${LATE_ROLES[right]}:affine`,
        family: 'role-swap',
        leftInputIndex: ROLE_INDEX[LATE_ROLES[left]],
        leftRole: LATE_ROLES[left],
        rightInputIndex: ROLE_INDEX[LATE_ROLES[right]],
        rightRole: LATE_ROLES[right],
      }));
    }
  }
  entries.push(Object.freeze({
    action,
    branch: 'identity-substitution-only',
    caseId: `${action}:identity-branch-substitution:input8`,
    family: 'identity-branch-substitution',
    inputIndex: 8,
    projectionPayloadBytes: 480,
    qCoordinateBytes: 32,
    qXPayloadOffset: 128,
    qYPayloadOffset: 160,
    role: 'fused-q-genesis8',
  }));
  if (entries.length !== V2_Q03_ATTACK_MATRIX_CASE_COUNT_PER_ACTION) {
    fail('internal Q-03 matrix per-action count drift');
  }
  return entries;
}

export function buildV2Q03AttackMatrix() {
  const matrix = V2_Q03_ACTIONS.flatMap(casesForAction);
  if (matrix.length !== V2_Q03_ATTACK_MATRIX_CASE_COUNT) {
    fail('internal Q-03 matrix total count drift');
  }
  return Object.freeze(matrix);
}

export function digestV2Q03AttackMatrix(
  matrix = buildV2Q03AttackMatrix(),
) {
  if (
    !Array.isArray(matrix)
    || matrix.length !== V2_Q03_ATTACK_MATRIX_CASE_COUNT
  ) {
    fail('Q-03 matrix must have exactly 219 cases');
  }
  return digest(canonical(matrix));
}

export const v2Q03AttackMatrixSha256 =
  digestV2Q03AttackMatrix(buildV2Q03AttackMatrix());

function plain(value, label) {
  if (
    value === null
    || Array.isArray(value)
    || typeof value !== 'object'
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail(`${label} must be a plain object`);
  }
  return value;
}

function exact(value, keys, label) {
  plain(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} has missing or unknown fields`);
  }
  return value;
}

function closure(value, label) {
  exact(value, ['sources', 'transaction'], label);
  exact(value.transaction, ['inputs', 'outputs'], `${label}.transaction`);
  if (
    !Array.isArray(value.transaction.inputs)
    || !Array.isArray(value.transaction.outputs)
    || !Array.isArray(value.sources)
    || value.sources.length !== value.transaction.inputs.length
  ) {
    fail(`${label} must have one source closure per input`);
  }
  return value;
}

function requireIndex(list, index, label) {
  if (!Number.isInteger(index) || index < 0 || index >= list.length) {
    fail(`${label} index is outside its closure`);
  }
  return list[index];
}

function sameExcept(list, changed, index, predicate, label) {
  if (
    list.length !== changed.length
    || list.some((entry, position) =>
      position !== index && !same(entry, changed[position]))
    || !predicate(list[index], changed[index])
  ) {
    fail(`${label} has undeclared drift`);
  }
}

function removedExactly(list, changed, index, label) {
  if (!same(changed, [...list.slice(0, index), ...list.slice(index + 1)])) {
    fail(`${label} does not remove exactly its declared entry`);
  }
}

function sourceOutput(source, label) {
  plain(source, `${label}.source`);
  plain(source.output, `${label}.source.output`);
  if (
    typeof source.serializedOutputHex !== 'string'
    || source.serializedOutputHex !== source.output.serializedHex
  ) {
    fail(`${label} source output serialization is not self-consistent`);
  }
  return source.output;
}

function outputValue(output, label) {
  plain(output, label);
  if (
    typeof output.valueSatoshis !== 'string'
    || !/^(0|[1-9][0-9]*)$/u.test(output.valueSatoshis)
  ) {
    fail(`${label}.valueSatoshis is not canonical`);
  }
  return output.valueSatoshis;
}

function sameInputAllowFundingAuthorization(before, after) {
  const left = clone(before);
  const right = clone(after);
  if (
    typeof left.unlockingBytecodeHex !== 'string'
    || typeof right.unlockingBytecodeHex !== 'string'
  ) {
    return false;
  }
  right.unlockingBytecodeHex = left.unlockingBytecodeHex;
  return same(left, right);
}

function sameInputsAllowFundingAuthorization(
  inputs,
  changed,
  fundingIndex = FUNDING_INDEX,
) {
  return inputs.length === changed.length && inputs.every((input, index) =>
    index === fundingIndex
      ? sameInputAllowFundingAuthorization(input, changed[index])
      : same(input, changed[index]));
}

function outpointTxidOnly(
  before,
  after,
  label,
  { allowFundingAuthorization = false } = {},
) {
  plain(before, `${label}.before-input`);
  plain(after, `${label}.after-input`);
  const left = clone(before);
  const right = clone(after);
  plain(left.outpoint, `${label}.before-outpoint`);
  plain(right.outpoint, `${label}.after-outpoint`);
  if (
    typeof left.outpoint.txid !== 'string'
    || typeof right.outpoint.txid !== 'string'
    || left.outpoint.txid === right.outpoint.txid
    || left.outpoint.vout !== right.outpoint.vout
  ) {
    fail(`${label} must alter only its outpoint transaction ID`);
  }
  right.outpoint.txid = left.outpoint.txid;
  if (allowFundingAuthorization) {
    right.unlockingBytecodeHex = left.unlockingBytecodeHex;
  }
  if (!same(left, right)) {
    fail(`${label} changes fields beyond its outpoint transaction ID`);
  }
  return true;
}

function sourceTransactionOnly(before, after, label) {
  const left = clone(before);
  const right = clone(after);
  if (
    !Object.hasOwn(left, 'sourceTransaction')
    || !Object.hasOwn(right, 'sourceTransaction')
    || same(left.sourceTransaction, right.sourceTransaction)
  ) {
    fail(`${label} must replace exactly one authenticated source transaction`);
  }
  right.sourceTransaction = left.sourceTransaction;
  if (!same(left, right)) {
    fail(`${label} changes the referenced source output`);
  }
  return true;
}

function requireToken(value, label) {
  return plain(value, label);
}

function tokenChange(before, after, field, predicate, label) {
  const left = clone(requireToken(before, `${label}.before-token`));
  const right = clone(requireToken(after, `${label}.after-token`));
  const prior = left[field];
  const next = right[field];
  right[field] = prior;
  if (!predicate(prior, next) || !same(left, right)) {
    fail(`${label} changes undeclared token fields`);
  }
}

function tokenOutputChange(before, after, mode, stateToken, label) {
  const prior = sourceOutput(before, label);
  const next = sourceOutput(after, label);
  if (
    prior.valueSatoshis !== next.valueSatoshis
    || prior.lockingBytecodeHex !== next.lockingBytecodeHex
    || prior.serializedHex === next.serializedHex
    || prior.sha256 === next.sha256
  ) {
    fail(
      `${label} changes source value/lock or leaves its bytes/hash unchanged`,
    );
  }
  if (mode === 'category') {
    tokenChange(
      requireToken(prior.token, label),
      requireToken(next.token, label),
      'categoryWire',
      (left, right) => left !== right,
      label,
    );
  } else if (mode === 'duplicate') {
    if (prior.token !== null || !same(next.token, stateToken)) {
      fail(`${label} does not copy the exact state NFT onto a tokenless source`);
    }
  } else if (mode === 'minting') {
    const left = clone(requireToken(prior.token, label));
    const right = clone(requireToken(next.token, label));
    if (
      left.nft?.capability !== 'mutable'
      || right.nft?.capability !== 'minting'
    ) {
      fail(`${label} does not change mutable authority to minting`);
    }
    right.nft.capability = 'mutable';
    if (!same(left, right)) {
      fail(`${label} minting mutation changes other token fields`);
    }
  } else {
    fail(`${label} has an unknown token mutation`);
  }
  const leftSource = clone(before);
  const rightSource = clone(after);
  rightSource.sourceTransaction = leftSource.sourceTransaction;
  rightSource.serializedOutputHex = leftSource.serializedOutputHex;
  rightSource.output = leftSource.output;
  if (!same(leftSource, rightSource)) {
    fail(`${label} changes fields beyond its authenticated token output`);
  }
}

function successorIndex(entry) {
  if (entry.successorOutputIndex === null) {
    fail(`${entry.caseId} has no successor`);
  }
  return entry.successorOutputIndex;
}

function isExactZeroOpReturn(output) {
  return (
    output !== null
    && typeof output === 'object'
    && output.valueSatoshis === '0'
    && output.lockingBytecodeHex === '6a'
    && output.token === null
    && output.serializedHex === '0000000000000000016a'
  );
}

function validateRollingParentMutation(entry, baseline, mutant) {
  const base = baseline.transaction;
  const changed = mutant.transaction;
  if (
    !same(base.outputs, changed.outputs)
    || base.inputs.length !== changed.inputs.length
    || baseline.sources.length !== mutant.sources.length
  ) {
    fail(`${entry.caseId} changes child outputs or counts`);
  }
  let replacementParent;
  for (let index = 0; index <= ROLLING_LAST_INDEX; index += 1) {
    const beforeInput = base.inputs[index];
    const afterInput = changed.inputs[index];
    outpointTxidOnly(beforeInput, afterInput, entry.caseId);
    const beforeSource = baseline.sources[index];
    const afterSource = mutant.sources[index];
    if (same(beforeSource.sourceTransaction, afterSource.sourceTransaction)) {
      fail(`${entry.caseId} does not replace its complete rolling parent`);
    }
    if (replacementParent === undefined) {
      replacementParent = afterSource.sourceTransaction;
    } else if (!same(replacementParent, afterSource.sourceTransaction)) {
      fail(`${entry.caseId} rolling sources do not share one replacement parent`);
    }
    if (index !== entry.inputIndex) {
      const left = clone(beforeSource);
      const right = clone(afterSource);
      right.sourceTransaction = left.sourceTransaction;
      if (!same(left, right)) {
        fail(`${entry.caseId} drifts a non-target rolling source output`);
      }
    }
  }
  if (
    !sameInputAllowFundingAuthorization(
      base.inputs[FUNDING_INDEX],
      changed.inputs[FUNDING_INDEX],
    )
    || !same(baseline.sources[FUNDING_INDEX], mutant.sources[FUNDING_INDEX])
  ) {
    fail(`${entry.caseId} changes funding beyond re-authorization`);
  }
  const stateToken = requireToken(
    sourceOutput(baseline.sources[STATE_INDEX], entry.caseId).token,
    `${entry.caseId}.state-token`,
  );
  tokenOutputChange(
    baseline.sources[entry.inputIndex],
    mutant.sources[entry.inputIndex],
    entry.family === 'fake-category'
      ? 'category'
      : entry.family === 'duplicate-state-nft'
        ? 'duplicate'
        : 'minting',
    stateToken,
    entry.caseId,
  );
}

function validateFundingDuplicate(entry, baseline, mutant) {
  const base = baseline.transaction;
  const changed = mutant.transaction;
  if (!same(base.outputs, changed.outputs)) {
    fail(`${entry.caseId} changes child outputs`);
  }
  sameExcept(
    base.inputs,
    changed.inputs,
    FUNDING_INDEX,
    (before, after) => outpointTxidOnly(
      before,
      after,
      entry.caseId,
      { allowFundingAuthorization: true },
    ),
    entry.caseId,
  );
  const stateToken = requireToken(
    sourceOutput(baseline.sources[STATE_INDEX], entry.caseId).token,
    `${entry.caseId}.state-token`,
  );
  sameExcept(
    baseline.sources,
    mutant.sources,
    FUNDING_INDEX,
    (before, after) => {
      if (same(before.sourceTransaction, after.sourceTransaction)) return false;
      tokenOutputChange(
        before,
        after,
        'duplicate',
        stateToken,
        entry.caseId,
      );
      return true;
    },
    entry.caseId,
  );
}

function validateMixedParent(entry, baseline, mutant) {
  const base = baseline.transaction;
  const changed = mutant.transaction;
  if (
    !same(base.outputs, changed.outputs)
    || base.inputs.length !== changed.inputs.length
    || baseline.sources.length !== mutant.sources.length
  ) {
    fail(`${entry.caseId} changes counts or successors`);
  }
  for (let index = 0; index < base.inputs.length; index += 1) {
    if (index === entry.inputIndex) {
      outpointTxidOnly(base.inputs[index], changed.inputs[index], entry.caseId);
      sourceTransactionOnly(
        baseline.sources[index],
        mutant.sources[index],
        entry.caseId,
      );
      continue;
    }
    const inputMatches = index === FUNDING_INDEX
      ? sameInputAllowFundingAuthorization(
        base.inputs[index],
        changed.inputs[index],
      )
      : same(base.inputs[index], changed.inputs[index]);
    if (
      !inputMatches
      || !same(baseline.sources[index], mutant.sources[index])
    ) {
      fail(`${entry.caseId} has undeclared mixed-parent drift`);
    }
  }
}

function validateSimpleDelta(entry, baseline, mutant) {
  const base = baseline.transaction;
  const changed = mutant.transaction;
  if (entry.family === 'standalone-burn') {
    const index = successorIndex(entry);
    sameExcept(base.outputs, changed.outputs, index, (before, after) => {
      const left = clone(before);
      const right = clone(after);
      const prior = outputValue(left, entry.caseId);
      const next = outputValue(right, entry.caseId);
      if (
        left.lockingBytecodeHex !== right.lockingBytecodeHex
        || !same(left.token, right.token)
        || left.tokenPrefixHex !== right.tokenPrefixHex
        || left.serializedHex === right.serializedHex
        || left.sha256 === right.sha256
      ) {
        return false;
      }
      right.valueSatoshis = prior;
      right.serializedHex = left.serializedHex;
      right.sha256 = left.sha256;
      return prior !== '0' && next === '0' && same(left, right);
    }, entry.caseId);
    if (
      !sameInputsAllowFundingAuthorization(base.inputs, changed.inputs)
      || !same(baseline.sources, mutant.sources)
    ) {
      fail(`${entry.caseId} changes closure beyond funding re-authorization`);
    }
    return;
  }
  if (entry.family === 'partial-bundle') {
    const expectedInputs = [
      ...base.inputs.slice(0, entry.inputIndex),
      ...base.inputs.slice(entry.inputIndex + 1),
    ];
    if (
      !sameInputsAllowFundingAuthorization(
        expectedInputs,
        changed.inputs,
        expectedInputs.length - 1,
      )
    ) {
      fail(`${entry.caseId} input removal has undeclared drift`);
    }
    removedExactly(
      baseline.sources,
      mutant.sources,
      entry.inputIndex,
      entry.caseId,
    );
    removedExactly(
      base.outputs,
      changed.outputs,
      successorIndex(entry),
      entry.caseId,
    );
    return;
  }
  if (entry.family === 'omitted-successor') {
    const index = successorIndex(entry);
    sameExcept(base.outputs, changed.outputs, index, (before, after) => {
      const left = clone(before);
      const right = clone(after);
      if (
        left.valueSatoshis !== right.valueSatoshis
        || left.token !== null
        || right.token !== null
        || right.lockingBytecodeHex !== '6a'
        || left.lockingBytecodeHex === right.lockingBytecodeHex
      ) {
        return false;
      }
      right.lockingBytecodeHex = left.lockingBytecodeHex;
      right.serializedHex = left.serializedHex;
      right.sha256 = left.sha256;
      return same(left, right);
    }, entry.caseId);
    if (
      !sameInputsAllowFundingAuthorization(base.inputs, changed.inputs)
      || !same(baseline.sources, mutant.sources)
    ) {
      fail(`${entry.caseId} changes closure beyond funding re-authorization`);
    }
    return;
  }
  if (entry.family === 'altered-role-count') {
    if (entry.mode === 'missing') {
      const expectedInputs = [
        ...base.inputs.slice(0, entry.inputIndex),
        ...base.inputs.slice(entry.inputIndex + 1),
      ];
      const inputsMatch = entry.role === 'funding'
        ? same(expectedInputs, changed.inputs)
        : sameInputsAllowFundingAuthorization(
          expectedInputs,
          changed.inputs,
          expectedInputs.length - 1,
        );
      if (!inputsMatch) {
        fail(`${entry.caseId} missing-role input delta is invalid`);
      }
      removedExactly(
        baseline.sources,
        mutant.sources,
        entry.inputIndex,
        entry.caseId,
      );
      if (entry.role === 'funding') {
        if (!same(base.outputs, changed.outputs)) {
          fail(`${entry.caseId} missing funding changes outputs`);
        }
      } else {
        removedExactly(
          base.outputs,
          changed.outputs,
          successorIndex(entry),
          entry.caseId,
        );
      }
      return;
    }
    if (entry.mode === 'extra-input') {
      if (
        changed.inputs.length !== base.inputs.length + 1
        || mutant.sources.length !== baseline.sources.length + 1
        || !sameInputsAllowFundingAuthorization(
          base.inputs,
          changed.inputs.slice(0, -1),
        )
        || !same(baseline.sources, mutant.sources.slice(0, -1))
        || !same(base.outputs, changed.outputs)
      ) {
        fail(`${entry.caseId} extra-input delta is invalid`);
      }
      return;
    }
    if (entry.mode === 'extra-output') {
      if (
        changed.outputs.length !== base.outputs.length + 1
        || !same(base.outputs, changed.outputs.slice(0, -1))
        || !isExactZeroOpReturn(changed.outputs.at(-1))
        || !sameInputsAllowFundingAuthorization(base.inputs, changed.inputs)
        || !same(baseline.sources, mutant.sources)
      ) {
        fail(`${entry.caseId} extra-output delta is invalid`);
      }
      return;
    }
  }
  if (entry.family === 'role-swap') {
    if (
      base.inputs.length !== changed.inputs.length
      || baseline.sources.length !== mutant.sources.length
      || base.outputs.length !== changed.outputs.length
    ) {
      fail(`${entry.caseId} changes counts`);
    }
    const left = entry.leftInputIndex;
    const right = entry.rightInputIndex;
    for (let index = 0; index < base.inputs.length; index += 1) {
      const expectedInput =
        index === left ? base.inputs[right]
          : index === right ? base.inputs[left]
            : base.inputs[index];
      const expectedSource =
        index === left ? baseline.sources[right]
          : index === right ? baseline.sources[left]
            : baseline.sources[index];
      const inputMatches = index === FUNDING_INDEX
        ? sameInputAllowFundingAuthorization(
          expectedInput,
          changed.inputs[index],
        )
        : same(expectedInput, changed.inputs[index]);
      if (!inputMatches || !same(expectedSource, mutant.sources[index])) {
        fail(`${entry.caseId} input/source swap has undeclared drift`);
      }
    }
    const leftOutput = left + 1;
    const rightOutput = right + 1;
    for (let index = 0; index < base.outputs.length; index += 1) {
      const expected =
        index === leftOutput ? base.outputs[rightOutput]
          : index === rightOutput ? base.outputs[leftOutput]
            : base.outputs[index];
      if (!same(expected, changed.outputs[index])) {
        fail(`${entry.caseId} successor swap has undeclared drift`);
      }
    }
    return;
  }
  if (entry.family === 'identity-branch-substitution') {
    if (
      !same(base.outputs, changed.outputs)
      || !same(baseline.sources, mutant.sources)
      || base.inputs.length !== changed.inputs.length
    ) {
      fail(`${entry.caseId} changes counts, sources, or outputs`);
    }
    for (let index = 0; index < base.inputs.length; index += 1) {
      if (index === entry.inputIndex) continue;
      const matches = index === FUNDING_INDEX
        ? sameInputAllowFundingAuthorization(
          base.inputs[index],
          changed.inputs[index],
        )
        : same(base.inputs[index], changed.inputs[index]);
      if (!matches) {
        fail(`${entry.caseId} changes another input`);
      }
    }
    const beforeInput = base.inputs[entry.inputIndex];
    const afterInput = changed.inputs[entry.inputIndex];
    const before = Buffer.from(beforeInput.unlockingBytecodeHex ?? '', 'hex');
    const after = Buffer.from(afterInput.unlockingBytecodeHex ?? '', 'hex');
    if (
      before.length !== after.length
      || before.length < 195
      || before[0] !== 0x4d
      || before.readUInt16LE(1) !== 480
      || after[0] !== 0x4d
      || after.readUInt16LE(1) !== 480
    ) {
      fail(`${entry.caseId} lacks canonical PUSHDATA2(480)`);
    }
    if (
      before.subarray(131, 195).every((byte) => byte === 0)
      || after.subarray(131, 195).some((byte) => byte !== 0)
      || !before.subarray(0, 131).equals(after.subarray(0, 131))
      || !before.subarray(195).equals(after.subarray(195))
    ) {
      fail(`${entry.caseId} does not isolate the Q identity selector`);
    }
    const left = clone(beforeInput);
    const right = clone(afterInput);
    right.unlockingBytecodeHex = left.unlockingBytecodeHex;
    if (!same(left, right)) {
      fail(`${entry.caseId} changes other fused-input fields`);
    }
    return;
  }
  fail(`${entry.caseId} has an unknown matrix family`);
}

export function validateV2Q03AttackMatrixDelta({
  action,
  baseline,
  caseId,
  mutant,
}) {
  if (!V2_Q03_ACTIONS.includes(action) || typeof caseId !== 'string') {
    fail('Q-03 action or case ID is invalid');
  }
  const entry = buildV2Q03AttackMatrix().find(
    (candidate) =>
      candidate.action === action && candidate.caseId === caseId,
  );
  if (entry === undefined) {
    fail('Q-03 case ID is outside the exact matrix');
  }
  closure(baseline, 'baseline');
  closure(mutant, 'mutant');
  if (entry.family === 'mixed-parent') {
    validateMixedParent(entry, baseline, mutant);
  } else if (
    entry.family === 'duplicate-state-nft'
    && entry.role === 'funding'
  ) {
    validateFundingDuplicate(entry, baseline, mutant);
  } else if (
    ['fake-category', 'duplicate-state-nft', 'minting-authority']
      .includes(entry.family)
  ) {
    validateRollingParentMutation(entry, baseline, mutant);
  } else {
    validateSimpleDelta(entry, baseline, mutant);
  }
  return Object.freeze({
    caseId: entry.caseId,
    matrixSha256: v2Q03AttackMatrixSha256,
    nonqualifying: true,
  });
}
