import { adaptSnarkjsGroth16 } from './groth16.mjs';

export const V2_DIRECT_GROTH16_ADAPTER_SCHEMA =
  'shieldkit-v2-direct-groth16-adapter-v1';

/**
 * Convert pinned snarkjs Groth16 material into the V2 Direct adapter document.
 * This is development-proof transport evidence only: it neither builds a BCH
 * verifier nor makes setup, standardness, VM, or production claims.
 */
export async function adaptV2DirectGroth16(records) {
  const converted = await adaptSnarkjsGroth16(records);
  return Object.freeze({
    ...converted,
    schema: V2_DIRECT_GROTH16_ADAPTER_SCHEMA,
    qualification: 'local V2 Direct development-proof conversion only; not a verifier bundle, profile, setup, BCH VM, standardness, or deployment result; canonical infinity IC0 is valid source material but is rejected by the V2 Direct verifier-input gate without substitution',
    byteOrder: Object.freeze({
      scalars: 'canonical unsigned base-10 JSON strings; the V2 Direct verifier input gate converts to its existing VM-number representation',
      g1: 'snarkjs affine [x,y,1] maps directly to Ax/Ay and Cx/Cy',
      g2: 'snarkjs affine [[x.c0,x.c1],[y.c0,y.c1],[1,0]] maps directly to Bxa/Bxb/Bya/Byb; no component reversal',
    }),
  });
}
