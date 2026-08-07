import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export const FRI_PRODUCTION_FLOOR = Object.freeze({
  blowup: 2048,
  queries: 8,
  grindBits: 24,
  fold: 8,
  maskDeg: 64,
  // Vendor pin uses 25: 4*25=100-bit collision resistance (plan: smallest width calculator proves sufficient)
  merkleHashBytes: 25,
  extNonres: 7,
  field: 'goldilocks',
  scheme: 'deep-ali-fri-stark',
  securityTargetBits: 100,
});

export class FriParamsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'FriParamsError';
    this.code = code;
  }
}

export function securityBits({ blowup, queries, grindBits }) {
  if (!Number.isInteger(blowup) || blowup < 2 || (blowup & (blowup - 1)) !== 0) {
    throw new FriParamsError('INVALID_BLOWUP', 'blowup power of two');
  }
  return queries * (Math.log2(blowup) - 1) + grindBits;
}

export function assertProductionFloor(params, { eligibility = 'final' } = {}) {
  const p = params ?? {};
  const floor = FRI_PRODUCTION_FLOOR;
  if (eligibility === 'development-only') {
    if (p.field !== floor.field || p.scheme !== floor.scheme) {
      throw new FriParamsError('DEV_IDENTITY', 'must remain goldilocks deep-ali-fri-stark');
    }
    return;
  }
  if (p.field !== floor.field) throw new FriParamsError('FIELD', 'goldilocks');
  if (p.scheme !== floor.scheme) throw new FriParamsError('SCHEME', 'deep-ali');
  if (p.blowup < floor.blowup) throw new FriParamsError('BLOWUP_FLOOR', `${p.blowup}<${floor.blowup}`);
  if (p.queries < floor.queries) throw new FriParamsError('QUERIES_FLOOR', `${p.queries}<${floor.queries}`);
  if (p.grindBits < floor.grindBits) throw new FriParamsError('GRIND_FLOOR', `${p.grindBits}<${floor.grindBits}`);
  if (p.maskDeg < 4 * p.queries) throw new FriParamsError('MASK_FLOOR', 'maskDeg');
  if (4 * p.merkleHashBytes < p.securityTargetBits) {
    throw new FriParamsError('MERKLE', `4*merkleHashBytes=${4 * p.merkleHashBytes} < target ${p.securityTargetBits}`);
  }
  if (p.merkleHashBytes > 32) throw new FriParamsError('MERKLE', 'exceeds SHA-256 output');
  if (p.extNonres !== floor.extNonres) throw new FriParamsError('EXT', '7');
  if (securityBits(p) < p.securityTargetBits) throw new FriParamsError('BITS', 'security');
}

export function productionFriParams() {
  // Prefer vendor config if available
  const py = path.join(ROOT, 'packages/prove/python/pool_prove.py');
  if (existsSync(py)) {
    const r = spawnSync('python3', [py, 'params'], { encoding: 'utf8', cwd: ROOT, timeout: 30_000 });
    if (r.status === 0) {
      try {
        const j = JSON.parse(r.stdout);
        return {
          blowup: j.blowup,
          queries: j.queries,
          grindBits: j.grindBits,
          fold: j.fold,
          maskDeg: j.maskDeg,
          merkleHashBytes: j.merkleHashBytes,
          extNonres: j.extNonres,
          field: j.field,
          scheme: j.scheme,
          securityTargetBits: j.securityTargetBits,
        };
      } catch { /* fall through */ }
    }
  }
  return { ...FRI_PRODUCTION_FLOOR };
}

export function friParamId(params) {
  assertProductionFloor(params);
  const body = {
    blowup: params.blowup,
    queries: params.queries,
    grindBits: params.grindBits,
    fold: params.fold,
    maskDeg: params.maskDeg,
    merkleHashBytes: params.merkleHashBytes,
    extNonres: params.extNonres,
    field: params.field,
    scheme: params.scheme,
    securityTargetBits: params.securityTargetBits,
  };
  return createHash('sha256').update(`SKFRI1${JSON.stringify(body)}`).digest('hex');
}
