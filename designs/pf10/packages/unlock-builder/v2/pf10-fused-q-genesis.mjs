import {
  encodeDataPush,
  encodeLockingBytecodeP2sh32,
  hash256,
} from '@bitauth/libauth';

import {
  DIRECT_V2_MSM_STATE_BYTES,
} from './exact-msm.mjs';
import {
  DIRECT_V2_MILLER_ENDPOINT_BYTES,
  DIRECT_V2_MILLER_RESIDUE_BYTES,
  DIRECT_V2_MILLER_SIGNAL_BYTES,
  DIRECT_V2_MILLER_SLOPE_BYTES,
} from './identity-aware-miller.mjs';

const OP_0 = 0x00;
const OP_1NEGATE = 0x4f;
const OP_1 = 0x51;
const OP_16 = 0x60;
const OP_VERIFY = 0x69;
const OP_DEFINE = 0x89;
const OP_INVOKE = 0x8a;
const MAXIMUM_FUNCTION_IDENTIFIER_BYTES = 7;

export const DIRECT_V2_PF10_INPUT_COUNT = 13;
export const DIRECT_V2_PF10_FUSED_ROLE = 8;
export const DIRECT_V2_PF10_TERMINAL_ROLE = 9;
export const DIRECT_V2_PF10_BINDING_ROLE = 10;
export const DIRECT_V2_PF10_STATE_ROLE = 11;
export const DIRECT_V2_PF10_FUNDING_ROLE = 12;

export class DirectV2Pf10FusedQGenesisError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2Pf10FusedQGenesisError';
  }
}

const fail = (message) => {
  throw new DirectV2Pf10FusedQGenesisError(message);
};

const exactBytes = (value, length, label) => {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    fail(`${label} must contain exactly ${length} bytes`);
  }
  return Uint8Array.from(value);
};

const nonemptyBytes = (value, label) => {
  if (!(value instanceof Uint8Array) || value.length === 0) {
    fail(`${label} must be nonempty bytes`);
  }
  return Uint8Array.from(value);
};

const concat = (...parts) => Uint8Array.from(
  parts.flatMap((part) => [...part]),
);

const push = (value) => Uint8Array.from(encodeDataPush(value));

const parseScript = (bytecode, label) => {
  const ops = [];
  for (let offset = 0; offset < bytecode.length;) {
    const opcode = bytecode[offset];
    let headerBytes = 1;
    let payloadBytes;
    if (opcode >= 1 && opcode <= 75) {
      payloadBytes = opcode;
    } else if (opcode === 0x4c) {
      if (offset + 2 > bytecode.length) {
        fail(`${label} ends inside OP_PUSHDATA_1`);
      }
      headerBytes = 2;
      payloadBytes = bytecode[offset + 1];
    } else if (opcode === 0x4d) {
      if (offset + 3 > bytecode.length) {
        fail(`${label} ends inside OP_PUSHDATA_2`);
      }
      headerBytes = 3;
      payloadBytes =
        bytecode[offset + 1] +
        (bytecode[offset + 2] * 0x100);
    } else if (opcode === 0x4e) {
      if (offset + 5 > bytecode.length) {
        fail(`${label} ends inside OP_PUSHDATA_4`);
      }
      headerBytes = 5;
      payloadBytes =
        bytecode[offset + 1] +
        (bytecode[offset + 2] * 0x100) +
        (bytecode[offset + 3] * 0x1_0000) +
        (bytecode[offset + 4] * 0x100_0000);
    }
    if (payloadBytes === undefined) {
      ops.push({ opcode });
      offset += 1;
      continue;
    }
    const payloadStart = offset + headerBytes;
    const payloadEnd = payloadStart + payloadBytes;
    if (payloadEnd > bytecode.length) {
      fail(`${label} contains a truncated data push`);
    }
    ops.push({
      opcode,
      data: bytecode.slice(payloadStart, payloadEnd),
    });
    offset = payloadEnd;
  }
  return ops;
};

const serializeScript = (ops) => concat(...ops.map((op) => (
  op.data === undefined
    ? Uint8Array.of(op.opcode)
    : push(op.data)
)));

const identifierBytes = (op) => {
  if (op === undefined) return undefined;
  if (op.opcode === OP_0 && op.data === undefined) {
    return new Uint8Array();
  }
  if (op.opcode === OP_1NEGATE && op.data === undefined) {
    return Uint8Array.of(0x81);
  }
  if (
    op.opcode >= OP_1 &&
    op.opcode <= OP_16 &&
    op.data === undefined
  ) {
    return Uint8Array.of(op.opcode - 0x50);
  }
  if (
    op.data !== undefined &&
    op.data.length <= MAXIMUM_FUNCTION_IDENTIFIER_BYTES
  ) {
    return Uint8Array.from(op.data);
  }
  return undefined;
};

const identifierKey = (identifier) => Buffer.from(identifier).toString('hex');

const identifierPush = (identifier) => {
  if (identifier.length > MAXIMUM_FUNCTION_IDENTIFIER_BYTES) {
    fail(
      `function identifier exceeds ${MAXIMUM_FUNCTION_IDENTIFIER_BYTES} bytes`,
    );
  }
  return parseScript(push(identifier), 'function identifier push')[0];
};

const dissectFunctionProgram = (bytecode, label) => {
  const ops = parseScript(bytecode, label);
  const definitions = [];
  let cursor = 0;
  while (
    cursor + 2 < ops.length &&
    ops[cursor].data !== undefined &&
    ops[cursor + 2].opcode === OP_DEFINE
  ) {
    const identifier = identifierBytes(ops[cursor + 1]);
    if (identifier === undefined) {
      fail(`${label} has a nonliteral OP_DEFINE identifier`);
    }
    definitions.push({
      body: ops[cursor].data,
      identifier,
    });
    cursor += 3;
  }
  const defined = new Set();
  for (const definition of definitions) {
    const key = identifierKey(definition.identifier);
    if (defined.has(key)) {
      fail(`${label} defines duplicate function identifier 0x${key}`);
    }
    defined.add(key);
  }
  return {
    defined,
    definitions,
    main: ops.slice(cursor),
  };
};

const rewriteInvocations = ({
  bytecode,
  defined,
  identifierMap,
  label,
}) => {
  const ops = parseScript(bytecode, label);
  const rewritten = [];
  for (let index = 0; index < ops.length; index += 1) {
    const op = ops[index];
    if (op.opcode !== OP_INVOKE) {
      rewritten.push(op);
      continue;
    }
    if (rewritten.length === 0) {
      fail(`${label} begins with OP_INVOKE`);
    }
    const originalPush = rewritten.pop();
    const original = identifierBytes(originalPush);
    if (original === undefined) {
      fail(`${label} computes a dynamic OP_INVOKE identifier`);
    }
    const key = identifierKey(original);
    if (!defined.has(key)) {
      fail(`${label} invokes undefined function identifier 0x${key}`);
    }
    rewritten.push(
      identifierPush(identifierMap.get(key) ?? original),
      op,
    );
  }
  return serializeScript(rewritten);
};

const namespaceFunctionProgram = ({
  bytecode,
  reservedIdentifiers,
  label,
}) => {
  const program = dissectFunctionProgram(bytecode, label);
  if (program.definitions.length === 0) {
    return Uint8Array.from(bytecode);
  }
  if (program.definitions.some(
    ({ identifier }) =>
      identifier.length >= MAXIMUM_FUNCTION_IDENTIFIER_BYTES,
  )) {
    fail(
      `${label} cannot namespace a ${MAXIMUM_FUNCTION_IDENTIFIER_BYTES}-byte function identifier`,
    );
  }
  let identifierMap;
  for (let namespace = 0; namespace <= 0xff; namespace += 1) {
    const candidate = new Map(program.definitions.map(({ identifier }) => {
      const mapped = concat(Uint8Array.of(namespace), identifier);
      return [identifierKey(identifier), mapped];
    }));
    const candidateKeys = new Set(
      [...candidate.values()].map(identifierKey),
    );
    if (
      candidateKeys.size === candidate.size &&
      [...candidateKeys].every((key) => !reservedIdentifiers.has(key))
    ) {
      identifierMap = candidate;
      break;
    }
  }
  if (identifierMap === undefined) {
    fail(`${label} has no collision-free one-byte function namespace`);
  }
  const output = [];
  for (const definition of program.definitions) {
    output.push({
      opcode: 0,
      data: rewriteInvocations({
        bytecode: definition.body,
        defined: program.defined,
        identifierMap,
        label: `${label} function 0x${identifierKey(
          definition.identifier,
        )}`,
      }),
    });
    output.push(
      identifierPush(identifierMap.get(identifierKey(
        definition.identifier,
      ))),
      { opcode: OP_DEFINE },
    );
  }
  const main = rewriteInvocations({
    bytecode: serializeScript(program.main),
    defined: program.defined,
    identifierMap,
    label: `${label} main`,
  });
  output.push(...parseScript(main, `${label} rewritten main`));
  return serializeScript(output);
};

const be32 = (value, label) => {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= (1n << 256n)) {
    fail(`${label} must fit one unsigned 32-byte integer`);
  }
  return Uint8Array.from(Buffer.from(
    parsed.toString(16).padStart(64, '0'),
    'hex',
  ));
};

/**
 * The combined redeem executes the singleton Miller-genesis component first.
 * That component consumes only the four Miller arguments at the top of the
 * stack and leaves one true item. OP_VERIFY removes it, then the exact-MSM
 * component consumes the four lower arguments and determines final success.
 */
export function buildDirectV2Pf10FusedQGenesisRedeem({
  millerRedeem,
  exactMsmRedeem,
}) {
  const miller = nonemptyBytes(
    millerRedeem,
    'Miller component redeem',
  );
  const exactMsm = nonemptyBytes(
    exactMsmRedeem,
    'exact-MSM component redeem',
  );
  const millerProgram = dissectFunctionProgram(
    miller,
    'Miller component redeem',
  );
  const namespacedExactMsm = namespaceFunctionProgram({
    bytecode: exactMsm,
    reservedIdentifiers: millerProgram.defined,
    label: 'exact-MSM component redeem',
  });
  return concat(
    miller,
    Uint8Array.of(OP_VERIFY),
    namespacedExactMsm,
  );
}

export function buildDirectV2Pf10FusedQGenesisLock(options) {
  const redeem = buildDirectV2Pf10FusedQGenesisRedeem(options);
  return encodeLockingBytecodeP2sh32(hash256(redeem));
}

export function directV2Pf10ExactMsmArgumentPrefix({
  projectionSignal,
  msmState,
  zInverse,
  exactMsmZeroPadding,
}) {
  const projection = exactBytes(
    projectionSignal,
    DIRECT_V2_MILLER_SIGNAL_BYTES,
    'projection signal',
  );
  const state = exactBytes(
    msmState,
    DIRECT_V2_MSM_STATE_BYTES,
    'exact-MSM state',
  );
  const padding = nonemptyBytes(
    exactMsmZeroPadding,
    'exact-MSM zero padding',
  );
  if (padding.some((byte) => byte !== 0)) {
    fail('exact-MSM zero padding must be all zero');
  }
  return concat(
    push(projection),
    push(state),
    push(be32(zInverse, 'exact-MSM z inverse')),
    push(padding),
  );
}

export function buildDirectV2Pf10FusedQGenesisUnlock({
  projectionSignal,
  msmState,
  zInverse,
  exactMsmZeroPadding,
  slope,
  endpoint,
  residue,
  millerZeroPadding,
  redeem,
}) {
  const exactPrefix = directV2Pf10ExactMsmArgumentPrefix({
    projectionSignal,
    msmState,
    zInverse,
    exactMsmZeroPadding,
  });
  const slopeBytes = exactBytes(
    slope,
    DIRECT_V2_MILLER_SLOPE_BYTES,
    'Miller slope witness',
  );
  const endpointBytes = exactBytes(
    endpoint,
    DIRECT_V2_MILLER_ENDPOINT_BYTES,
    'Miller endpoint witness',
  );
  const residueBytes = exactBytes(
    residue,
    DIRECT_V2_MILLER_RESIDUE_BYTES,
    'Miller residue witness',
  );
  const millerPadding = nonemptyBytes(
    millerZeroPadding,
    'Miller zero padding',
  );
  if (millerPadding.some((byte) => byte !== 0)) {
    fail('Miller zero padding must be all zero');
  }
  return concat(
    exactPrefix,
    push(slopeBytes),
    push(endpointBytes),
    push(residueBytes),
    push(millerPadding),
    push(nonemptyBytes(redeem, 'PF10 fused redeem')),
  );
}
