/** Goldilocks field helpers for V2 STARK. */

export const GOLDILOCKS_P = 0xffffffff00000001n;

export function fe(value) {
  const v = typeof value === 'bigint' ? value : BigInt(value);
  let r = v % GOLDILOCKS_P;
  if (r < 0n) r += GOLDILOCKS_P;
  return r;
}

export function feAdd(a, b) {
  return fe(fe(a) + fe(b));
}

export function feMul(a, b) {
  return fe(fe(a) * fe(b));
}

export function feFromBytesBE(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 8) {
    throw new Error('feFromBytesBE expects 8 bytes');
  }
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  if (v >= GOLDILOCKS_P) throw new Error('non-canonical Goldilocks limb');
  return v;
}

export function feToBytesBE(value) {
  let v = fe(value);
  const out = new Uint8Array(8);
  for (let i = 7; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function hex32FromBytes(bytes) {
  return Buffer.from(bytes).toString('hex');
}

export function bytesFromHex(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-f]*$/i.test(hex) || hex.length % 2) {
    throw new Error('invalid hex');
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function assertGDig32Hex(hex, label = 'gdig32') {
  if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`${label} must be 64 lowercase hex chars`);
  }
  const bytes = bytesFromHex(hex);
  for (let i = 0; i < 4; i += 1) {
    feFromBytesBE(bytes.subarray(i * 8, i * 8 + 8));
  }
  return hex;
}
