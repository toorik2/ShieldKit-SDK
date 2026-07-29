import { poseidon1 } from 'poseidon-lite/poseidon1';
import { poseidon2 } from 'poseidon-lite/poseidon2';
import { poseidon3 } from 'poseidon-lite/poseidon3';
import { poseidon4 } from 'poseidon-lite/poseidon4';
import { poseidon5 } from 'poseidon-lite/poseidon5';
import { poseidon6 } from 'poseidon-lite/poseidon6';
import { poseidon7 } from 'poseidon-lite/poseidon7';
import { poseidon8 } from 'poseidon-lite/poseidon8';
import { poseidon9 } from 'poseidon-lite/poseidon9';
import { poseidon10 } from 'poseidon-lite/poseidon10';
import { poseidon11 } from 'poseidon-lite/poseidon11';
import { poseidon12 } from 'poseidon-lite/poseidon12';
import { poseidon13 } from 'poseidon-lite/poseidon13';
import { poseidon14 } from 'poseidon-lite/poseidon14';
import { poseidon15 } from 'poseidon-lite/poseidon15';
import { poseidon16 } from 'poseidon-lite/poseidon16';
import { FR_MODULUS } from '../constants.mjs';
import { assertFr } from './fr.mjs';

const implementations = [
  null,
  poseidon1, poseidon2, poseidon3, poseidon4,
  poseidon5, poseidon6, poseidon7, poseidon8,
  poseidon9, poseidon10, poseidon11, poseidon12,
  poseidon13, poseidon14, poseidon15, poseidon16,
];

/**
 * Domain-separated Poseidon over BN254 Fr.
 * First argument is the domain tag; remaining are field elements.
 */
export function poseidon(tag, ...values) {
  const inputs = [assertFr(tag, 'domain'), ...values.map((v, i) => assertFr(v, `input[${i}]`))];
  const impl = implementations[inputs.length];
  if (!impl) {
    throw new Error(`Poseidon arity ${inputs.length} is unsupported`);
  }
  const out = impl(inputs);
  if (typeof out !== 'bigint' || out < 0n || out >= FR_MODULUS) {
    throw new Error('Poseidon output is noncanonical');
  }
  return out;
}

/** Poseidon sponge over 128-bit limbs (record commitment). */
export function poseidonSponge(domain, limbs) {
  if (!Array.isArray(limbs) || limbs.length === 0) {
    throw new Error('poseidonSponge requires at least one limb');
  }
  let state = poseidon(domain, limbs[0]);
  for (let i = 1; i < limbs.length; i += 1) {
    state = poseidon(domain, state, limbs[i]);
  }
  return state;
}
