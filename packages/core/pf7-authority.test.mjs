import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  PF7_CARRIER_ROLES,
  PF7_CARRIER_SOURCE_ENCODING,
  Pf7AuthorityError,
  derivePf7SettlementKernelAuthority,
  encodeCanonicalPf7CarrierSourceSet,
  parsePf7CarrierAuthority,
} from './pf7-authority.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest();
const sha256d = (value) => sha256(sha256(value));

function fixture() {
  const scripts = PF7_CARRIER_ROLES.map((name, index) => {
    const redeem = Buffer.from([0x51, index + 1]);
    const lock = Buffer.concat([Buffer.of(0xaa, 0x20), sha256d(redeem), Buffer.of(0x87)]);
    return {
      lockingBytecodeHex: lock.toString('hex'),
      name,
      redeemBytecodeHex: redeem.toString('hex'),
      sourceValueSatoshis: String(1_000 + index),
    };
  });
  const serialization = encodeCanonicalPf7CarrierSourceSet(scripts);
  const carriers = scripts.map((script) => ({
    role: script.name,
    lockingBytecode: Buffer.from(script.lockingBytecodeHex, 'hex'),
    valueSatoshis: BigInt(script.sourceValueSatoshis),
  }));
  return {
    schema: 'shield.cash/bch-verifier-set/v1',
    scripts,
    settlementKernel: derivePf7SettlementKernelAuthority(carriers).artifact,
    sourceSet: {
      carrierCount: 7,
      encoding: PF7_CARRIER_SOURCE_ENCODING,
      sha256: `sha256:${sha256(serialization).toString('hex')}`,
    },
  };
}

test('authenticates the exact canonical seven-output PF7 authority', () => {
  const record = fixture();
  const parsed = parsePf7CarrierAuthority(record);
  assert.equal(parsed.carriers.length, 7);
  assert.equal(parsed.serialization[0], 7);
  assert.equal(parsed.sha256, record.sourceSet.sha256);
  assert.equal(parsed.carriers[6].role, 'terminal');
});

test('rejects stale encoding, source hash, P2SH32 redeem, role, and value', () => {
  const mutations = [
    (record) => { record.sourceSet.encoding = 'libauth-transaction-outputs-hex-v1'; },
    (record) => { record.sourceSet.sha256 = `sha256:${'00'.repeat(32)}`; },
    (record) => { record.scripts[0].redeemBytecodeHex = '52'; },
    (record) => { record.scripts[1].name = 'exec0'; },
    (record) => { record.scripts[2].sourceValueSatoshis = '0'; },
    (record) => { record.scripts[3].sourceValueSatoshis = String(2n ** 64n); },
    (record) => { record.settlementKernel.constants.stateCarrierBaseSatoshis = '1000'; },
  ];
  for (const mutate of mutations) {
    const record = structuredClone(fixture());
    mutate(record);
    assert.throws(() => parsePf7CarrierAuthority(record), Pf7AuthorityError);
  }
});
