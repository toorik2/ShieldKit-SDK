/**
 * @shieldkit/prove — Groth16 adapters for ShieldKit-Groth (PF10).
 * Legacy seven-carrier authority helpers live under designs/pf10/research/v1-seven-carrier/.
 */

export { adaptSnarkjsGroth16 } from './groth16.mjs';
export {
  adaptV2DirectGroth16,
  V2_DIRECT_GROTH16_ADAPTER_SCHEMA,
} from './v2-direct-groth16-adapter.mjs';
