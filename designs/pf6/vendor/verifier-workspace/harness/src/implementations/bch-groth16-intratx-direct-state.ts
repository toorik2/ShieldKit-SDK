// BCH-native BN254 Groth16 verifier - hardened direct-state boundary, portable profile.
// The strict fixed-deployment sibling is persisted under artifacts/; this entry removes
// deployment-only UTXO value/sequence pins so the stock intra-tx benchmark context applies.
import { readFileSync } from 'node:fs';
import { hexToBin } from '@bitauth/libauth';

import type { Implementation, Step } from '../harness/types.js';

interface RawStep {
  label: string;
  locking: string;
  unlocking: string;
  checkpoint?: string;
}

interface Vectors {
  steps: RawStep[];
  extraValidProofs?: RawStep[][];
  worstCaseProof?: RawStep[];
  invalid?: RawStep[][];
}

const vectors = JSON.parse(readFileSync('src/bch/groth16-intratx-direct-state-vectors.json', 'utf8')) as Vectors;

const toRun = (raw: RawStep[]): Step[] => {
  const inputs = raw.map((step) => ({
    lockingBytecode: hexToBin(step.locking),
    unlockingBytecode: hexToBin(step.unlocking),
  }));
  return raw.map((step, index) => ({
    label: step.label,
    lockingBytecode: inputs[index]!.lockingBytecode,
    unlockingBytecode: inputs[index]!.unlockingBytecode,
    checkpoint: step.checkpoint,
    intraTx: { index, inputs },
  }));
};

export const bchGroth16IntratxDirectState: Implementation = {
  id: 'bch-groth16-intratx-direct-state',
  name: 'BCH Groth16 intra-tx direct-state boundary (portable hardened profile)',
  proofSystem: 'Groth16',
  field: 'BN254',
  structure: 'single-tx',
  proofBinding: 'runtime',
  source:
    'BCH-native CashScript: ten P2SH32 inputs in one intra-transaction-linked BN254 verifier. ' +
    'The hardened direct-state boundary binds every executor and boundary source role by exact ' +
    'locking-byte equality, binds each boundary carrier length, enforces nonnegative canonical ' +
    'public/input coordinates, and carries the computed interior state directly in scored witness ' +
    'bytes. The portable benchmark profile omits only the strict fixed-deployment value/sequence ' +
    'pins so it runs under the stock verifier-bench synthetic intra-tx context. The vectors include ' +
    'four valid proofs, a dense worst-case proof, and one full-run witness mutation per input.',
  load: async () => ({
    valid: toRun(vectors.steps),
    extraValidProofs: (vectors.extraValidProofs ?? []).map(toRun),
    worstCaseProof: vectors.worstCaseProof ? toRun(vectors.worstCaseProof) : undefined,
    invalid: (vectors.invalid ?? []).map(toRun),
  }),
};
