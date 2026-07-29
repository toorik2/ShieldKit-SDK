export const BN254_BASE_FIELD =
  21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;
export const DIRECT_V2_PUBLIC_INPUT_BITS = 128;
export const DIRECT_V2_PUBLIC_INPUT_LIMIT =
  1n << BigInt(DIRECT_V2_PUBLIC_INPUT_BITS);
export const DIRECT_V2_MSM_WINDOWS = Object.freeze([
  Object.freeze({ start: 0, end: 38 }),
  Object.freeze({ start: 38, end: 75 }),
  Object.freeze({ start: 75, end: 112 }),
  Object.freeze({ start: 112, end: 128 }),
]);
export const DIRECT_V2_MSM_STATE_BYTES = 128;

const FIELD_BYTES = 32;
const SCALAR_BYTES = 16;
const HEX_32 = /^[0-9a-f]{64}$/;

export class DirectV2ExactMsmError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DirectV2ExactMsmError';
  }
}

const fail = (message) => {
  throw new DirectV2ExactMsmError(message);
};

const mod = (value) => {
  const reduced = value % BN254_BASE_FIELD;
  return reduced < 0n ? reduced + BN254_BASE_FIELD : reduced;
};

const canonicalField = (value, label) => {
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    fail(`${label} must be an integer`);
  }
  if (parsed < 0n || parsed >= BN254_BASE_FIELD) {
    fail(`${label} must be a canonical BN254 base-field element`);
  }
  return parsed;
};

const scalar128 = (value, label) => {
  let parsed;
  try {
    parsed = BigInt(value);
  } catch {
    fail(`${label} must be an integer`);
  }
  if (parsed < 0n || parsed >= DIRECT_V2_PUBLIC_INPUT_LIMIT) {
    fail(`${label} must be an unsigned 128-bit integer`);
  }
  return parsed;
};

const isAffineOnCurve = ({ x, y }) =>
  mod(y * y) === mod(x * x * x + 3n);

const affinePoint = (value, label) => {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !Object.hasOwn(value, 'x')
    || !Object.hasOwn(value, 'y')
  ) {
    fail(`${label} must contain affine x and y coordinates`);
  }
  const point = Object.freeze({
    x: canonicalField(value.x, `${label}.x`),
    y: canonicalField(value.y, `${label}.y`),
  });
  if (!isAffineOnCurve(point)) fail(`${label} is not on BN254 G1`);
  return point;
};

const identity = () => Object.freeze({ x: 0n, y: 1n, z: 0n });

const jacobianPoint = (value, label) => {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
  ) {
    fail(`${label} must be a Jacobian point`);
  }
  const point = Object.freeze({
    x: canonicalField(value.x, `${label}.x`),
    y: canonicalField(value.y, `${label}.y`),
    z: canonicalField(value.z, `${label}.z`),
  });
  if (point.z === 0n) {
    if (point.x !== 0n || point.y !== 1n) {
      fail(`${label} has a noncanonical identity encoding`);
    }
    return identity();
  }
  const z2 = mod(point.z * point.z);
  const z6 = mod(z2 * z2 * z2);
  if (mod(point.y * point.y) !== mod(point.x * point.x * point.x + 3n * z6)) {
    fail(`${label} is not on the BN254 Jacobian curve`);
  }
  return point;
};

export function doubleDirectV2Jacobian(value) {
  const point = jacobianPoint(value, 'Jacobian point');
  if (point.z === 0n || point.y === 0n) return identity();
  const a = mod(point.x * point.x);
  const b = mod(point.y * point.y);
  const c = mod(b * b);
  const d = mod(2n * mod(mod((point.x + b) * (point.x + b)) - a - c));
  const e = mod(3n * a);
  const f = mod(e * e);
  const x = mod(f - 2n * d);
  const y = mod(e * mod(d - x) - 8n * c);
  const z = mod(2n * point.y * point.z);
  return z === 0n ? identity() : Object.freeze({ x, y, z });
}

export function addDirectV2Affine(value, affineValue) {
  const left = jacobianPoint(value, 'Jacobian point');
  if (affineValue === null) return left;
  const right = affinePoint(affineValue, 'affine addend');
  if (left.z === 0n) {
    return Object.freeze({ x: right.x, y: right.y, z: 1n });
  }
  const z1z1 = mod(left.z * left.z);
  const u1 = left.x;
  const u2 = mod(right.x * z1z1);
  const s1 = left.y;
  const s2 = mod(right.y * left.z * z1z1);
  if (u1 === u2) {
    if (s1 !== s2) return identity();
    return doubleDirectV2Jacobian(left);
  }
  const h = mod(u2 - u1);
  const i = mod(4n * h * h);
  const j = mod(h * i);
  const r = mod(2n * mod(s2 - s1));
  const v = mod(u1 * i);
  const x = mod(r * r - j - 2n * v);
  const y = mod(r * mod(v - x) - 2n * s1 * j);
  const z = mod(mod((left.z + h) * (left.z + h)) - z1z1 - h * h);
  return z === 0n ? identity() : Object.freeze({ x, y, z });
}

const inverse = (value) => {
  if (value === 0n) fail('cannot invert zero');
  let exponent = BN254_BASE_FIELD - 2n;
  let base = value;
  let result = 1n;
  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) result = mod(result * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  return result;
};

export function canonicalizeDirectV2Jacobian(value) {
  const point = jacobianPoint(value, 'Jacobian point');
  if (point.z === 0n) {
    return Object.freeze({
      infinity: true,
      x: 0n,
      y: 0n,
      zInverse: 0n,
    });
  }
  const zInverse = inverse(point.z);
  const zInverse2 = mod(zInverse * zInverse);
  const x = mod(point.x * zInverse2);
  const y = mod(point.y * zInverse2 * zInverse);
  const affine = affinePoint({ x, y }, 'canonical MSM output');
  return Object.freeze({
    infinity: false,
    ...affine,
    zInverse,
  });
}

const addAffinePoints = (left, right) => {
  if (left === null) return right;
  if (right === null) return left;
  const result = addDirectV2Affine(
    { x: left.x, y: left.y, z: 1n },
    right,
  );
  const canonical = canonicalizeDirectV2Jacobian(result);
  return canonical.infinity
    ? null
    : Object.freeze({ x: canonical.x, y: canonical.y });
};

const normalizeVerificationKey = (value) => {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || value.protocol !== 'groth16'
    || value.curve !== 'bn128'
    || value.nPublic !== 2
    || !Array.isArray(value.IC)
    || value.IC.length !== 3
  ) {
    fail('verification key must be a two-public-input snarkjs BN254 Groth16 key');
  }
  const points = value.IC.map((entry, index) => {
    if (!Array.isArray(entry) || entry.length !== 3) {
      fail(`verification key IC[${index}] must be canonical affine projective form`);
    }
    let z;
    try {
      z = BigInt(entry[2]);
    } catch {
      fail(`verification key IC[${index}] projective coordinate must be an integer`);
    }
    if (z === 0n) {
      if (BigInt(entry[0]) !== 0n || BigInt(entry[1]) !== 1n) {
        fail(`verification key IC[${index}] has a noncanonical identity encoding`);
      }
      return null;
    }
    if (z !== 1n) {
      fail(`verification key IC[${index}] must be affine or canonical identity`);
    }
    return affinePoint(
      { x: entry[0], y: entry[1] },
      `verification key IC[${index}]`,
    );
  });
  return Object.freeze({
    ic0: points[0],
    ic1: points[1],
    ic2: points[2],
    ic12: addAffinePoints(points[1], points[2]),
  });
};

export function directV2VerificationKeyPoints(value) {
  return normalizeVerificationKey(value);
}

const selectedAddend = (key, input0, input1, bit) => {
  const bit0 = (input0 >> BigInt(bit)) & 1n;
  const bit1 = (input1 >> BigInt(bit)) & 1n;
  if (bit0 === 1n && bit1 === 1n) return key.ic12;
  if (bit0 === 1n) return key.ic1;
  if (bit1 === 1n) return key.ic2;
  return null;
};

const runWindow = (key, state, start, end) => {
  let accumulator = state;
  for (let round = start; round < end; round += 1) {
    const bit = DIRECT_V2_PUBLIC_INPUT_BITS - 1 - round;
    if (accumulator.z !== 0n) {
      accumulator = doubleDirectV2Jacobian(accumulator);
    }
    accumulator = addDirectV2Affine(
      accumulator,
      selectedAddend(key, state.input0, state.input1, bit),
    );
  }
  return Object.freeze({
    ...accumulator,
    input0: state.input0,
    input1: state.input1,
  });
};

export function createDirectV2MsmInitialState(input0, input1) {
  const point = identity();
  return Object.freeze({
    ...point,
    input0: scalar128(input0, 'public input 0'),
    input1: scalar128(input1, 'public input 1'),
  });
}

export function computeDirectV2ExactMsm(verificationKey, input0, input1) {
  const key = normalizeVerificationKey(verificationKey);
  let state = createDirectV2MsmInitialState(input0, input1);
  const states = [state];
  for (const window of DIRECT_V2_MSM_WINDOWS) {
    state = runWindow(key, state, window.start, window.end);
    states.push(state);
  }
  const folded = addDirectV2Affine(state, key.ic0);
  const output = canonicalizeDirectV2Jacobian(folded);
  return Object.freeze({
    input0: state.input0,
    input1: state.input1,
    states: Object.freeze(states),
    folded,
    output,
  });
}

const encodeUnsigned = (value, bytes, label) => {
  const maximum = 1n << BigInt(bytes * 8);
  if (value < 0n || value >= maximum) fail(`${label} exceeds ${bytes} bytes`);
  const hex = value.toString(16).padStart(bytes * 2, '0');
  return Buffer.from(hex, 'hex');
};

export function encodeDirectV2MsmState(value) {
  const point = jacobianPoint(value, 'MSM state');
  const input0 = scalar128(value.input0, 'MSM state input0');
  const input1 = scalar128(value.input1, 'MSM state input1');
  return Buffer.concat([
    encodeUnsigned(point.x, FIELD_BYTES, 'MSM state x'),
    encodeUnsigned(point.y, FIELD_BYTES, 'MSM state y'),
    encodeUnsigned(point.z, FIELD_BYTES, 'MSM state z'),
    encodeUnsigned(input0, SCALAR_BYTES, 'MSM state input0'),
    encodeUnsigned(input1, SCALAR_BYTES, 'MSM state input1'),
  ]);
}

const decodeUnsigned = (bytes) =>
  bytes.length === 0 ? 0n : BigInt(`0x${Buffer.from(bytes).toString('hex')}`);

export function decodeDirectV2MsmState(value) {
  if (!(value instanceof Uint8Array) || value.length !== DIRECT_V2_MSM_STATE_BYTES) {
    fail(`MSM state must contain exactly ${DIRECT_V2_MSM_STATE_BYTES} bytes`);
  }
  const bytes = Buffer.from(value);
  return Object.freeze({
    ...jacobianPoint({
      x: decodeUnsigned(bytes.subarray(0, 32)),
      y: decodeUnsigned(bytes.subarray(32, 64)),
      z: decodeUnsigned(bytes.subarray(64, 96)),
    }, 'MSM state'),
    input0: scalar128(
      decodeUnsigned(bytes.subarray(96, 112)),
      'MSM state input0',
    ),
    input1: scalar128(
      decodeUnsigned(bytes.subarray(112, 128)),
      'MSM state input1',
    ),
  });
}

export function directV2PacketDigestPublicInputs(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) {
    fail('packet digest must contain exactly 32 bytes');
  }
  const bytes = Buffer.from(value);
  return Object.freeze([
    decodeUnsigned(bytes.subarray(0, 16)),
    decodeUnsigned(bytes.subarray(16, 32)),
  ]);
}

export function parseDirectV2VerificationKeyJson(value) {
  let decoded;
  try {
    decoded = typeof value === 'string'
      ? JSON.parse(value)
      : JSON.parse(Buffer.from(value).toString('utf8'));
  } catch (error) {
    fail(`verification key is not JSON: ${error.message}`);
  }
  normalizeVerificationKey(decoded);
  return Object.freeze(decoded);
}

export function directV2MsmStateHex(value) {
  const encoded = encodeDirectV2MsmState(value).toString('hex');
  if (!HEX_32.test(encoded.slice(0, 64))) {
    fail('internal MSM state encoding failed');
  }
  return encoded;
}
