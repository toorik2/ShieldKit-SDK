// Lane-local adapter for the validated DEFER_MOD_VARIANT=inner source transform.
// The shared arithmetic generator remains read-only; only the generated lane
// body is rewritten for this explicit opt-in entrypoint.
import * as base from '../../../../build/chunked/pairing/gen_miller_gb3_9k7.mjs';

const fold1Base = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int kye0,int kye1,int kxe2,int kxe3, int ex4,int ex5) returns (int) {
    return (pf * ((c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5) % Pm)) % Pm; }`;
const fold1Inner = `function fold1(int Pm, int pf, int c0a,int c0b,int c1a,int c1b,int c2a,int c2b, int kye0,int kye1,int kxe2,int kxe3, int ex4,int ex5) returns (int) {
    return (pf * (c2a*kye0 + c2b*kye1 + c1a*kxe2 + c1b*kxe3 + c0a*ex4 + c0b*ex5)) % Pm; }`;

const deferInner = (source) => {
  const count = source.split(fold1Base).length - 1;
  if (count !== 1) throw new Error(`deferred fold source occurrence=${count}, expected 1`);
  return source.replace(fold1Base, fold1Inner);
};

export const genChunkGB = (...args) => deferInner(base.genChunkGB(...args));
export const SHARED = deferInner(base.SHARED);
export const inBlobGB = base.inBlobGB;
export const outBlobGB = base.outBlobGB;
export const STATE_BYTES = base.STATE_BYTES;
export const MODE_SCHEDULE = base.MODE_SCHEDULE;
export const cdatStep = base.cdatStep;
export const wdatStep = base.wdatStep;
export const stateW = base.stateW;
export const stateVal = base.stateVal;
