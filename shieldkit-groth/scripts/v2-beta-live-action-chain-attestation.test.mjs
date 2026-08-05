import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import { encodeTokenPrefix } from '@bitauth/libauth';

import {
  attestV2BetaLiveActionChainReadback,
  inspectV2BetaLiveActionChainAttestation,
  V2BetaLiveActionChainAttestationError,
} from './v2-beta-live-action-chain-attestation.mjs';

const H = (byte) => byte.repeat(64);
const CHIPNET = '000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const txidOf = (raw) => createHash('sha256').update(createHash('sha256').update(Buffer.from(raw, 'hex')).digest()).digest().reverse().toString('hex');
const le64 = (value) => Buffer.from(Uint8Array.from({ length: 8 }, (_, index) => Number((BigInt(value) >> BigInt(index * 8)) & 0xffn))).toString('hex');
const output = (valueSats, contentsHex) => `${le64(valueSats)}${(contentsHex.length / 2).toString(16).padStart(2, '0')}${contentsHex}`;
const rawWithOneInput = (outputs) => `0200000001${Buffer.from(H('f'), 'hex').reverse().toString('hex')}0000000000ffffffff${outputs.length.toString(16).padStart(2, '0')}${outputs.join('')}00000000`;

function fixture() {
  const instanceId = H('1');
  const commitment = H('2').repeat(4);
  const prefix = Buffer.from(encodeTokenPrefix({
    category: Uint8Array.from(Buffer.from(instanceId, 'hex').reverse()), amount: 0n,
    nft: { capability: 'mutable', commitment: Uint8Array.from(Buffer.from(commitment, 'hex')) },
  })).toString('hex');
  const raw = rawWithOneInput([output('546', `${prefix}51`)]);
  const transactionId = txidOf(raw);
  const action = {
    transactionId,
    readback: {
      rawTransactionSha256: sha256(Buffer.from(raw, 'hex')),
      stateOutpoint: { txid: transactionId, vout: 0 },
      stateCategoryWire: Buffer.from(instanceId, 'hex').reverse().toString('hex'),
      stateCommitmentSha256: sha256(Buffer.from(commitment, 'hex')),
    },
  };
  const rpc = {
    backend: 'layer1-bchn-chipnet', genesis: CHIPNET,
    async getrawtransaction() { return { txid: transactionId, hex: raw }; },
    async gettxout() { return { valueSatoshis: '546', scriptPubKey: { hex: '51' }, tokenData: { category: Buffer.from(instanceId, 'hex').reverse().toString('hex'), amount: '0', nft: { capability: 'mutable', commitment } } }; },
  };
  return { action, instanceId, rpc };
}

test('independent action attestation records its direct-node backend and binds raw bytes, token state, value, and locking bytecode', async () => {
  const subject = fixture();
  const attestation = await attestV2BetaLiveActionChainReadback({
    rpc: subject.rpc, action: subject.action, expectedInstanceId: subject.instanceId,
  });
  assert.equal(attestation.backend, 'layer1-bchn-chipnet');
  assert.equal(attestation.genesis, CHIPNET);
  assert.equal(attestation.stateValueSatoshis, '546');
  assert.deepEqual(inspectV2BetaLiveActionChainAttestation(attestation, {
    action: subject.action, expectedInstanceId: subject.instanceId,
  }), attestation);
});

test('independent action attestation records a public provider backend rather than calling it BCHN', async () => {
  const subject = fixture();
  subject.rpc.backend = 'public-chipnet-fulcrum-tls';
  const attestation = await attestV2BetaLiveActionChainReadback({
    rpc: subject.rpc, action: subject.action, expectedInstanceId: subject.instanceId,
  });
  assert.equal(attestation.backend, 'public-chipnet-fulcrum-tls');
});

test('independent action attestation rejects a non-product capability and output-script substitution', async () => {
  const subject = fixture();
  await assert.rejects(() => attestV2BetaLiveActionChainReadback({
    rpc: { ...subject.rpc, genesis: H('0') }, action: subject.action, expectedInstanceId: subject.instanceId,
  }), (error) => error instanceof V2BetaLiveActionChainAttestationError && error.code === 'ACTION_CHAIN_ATTESTATION_RPC_REQUIRED');
  const swapped = { ...subject.rpc, async gettxout() { return { valueSatoshis: '546', scriptPubKey: { hex: '52' }, tokenData: { category: Buffer.from(subject.instanceId, 'hex').reverse().toString('hex'), amount: '0', nft: { capability: 'mutable', commitment: H('2').repeat(4) } } }; } };
  await assert.rejects(() => attestV2BetaLiveActionChainReadback({
    rpc: swapped, action: subject.action, expectedInstanceId: subject.instanceId,
  }), (error) => error instanceof V2BetaLiveActionChainAttestationError && error.code === 'ACTION_CHAIN_ATTESTATION_STATE_INVALID');
});
