import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it } from 'node:test';

const here = path.dirname(fileURLToPath(import.meta.url));
const cash = readFileSync(path.join(here, 'ShieldStateV2Direct.cash'), 'utf8');

describe('ShieldStateV2Direct.cash draft (structural)', () => {
  it('pins SDA2/SKS2 magics and V2 offsets', () => {
    assert.match(cash, /SDA2|0x53444132/);
    assert.match(cash, /SKS2|0x534b5332/);
    assert.match(cash, /0x4d2802/); // push 552
    assert.match(cash, /packetUnlock\.length == 555/);
    assert.match(cash, /10000000/); // denomination
    assert.match(cash, /nftCommitment == pre/);
    assert.match(cash, /nftCommitment == post/);
    // kind branches
    assert.match(cash, /kind == 0x01/);
    assert.match(cash, /kind == 0x02/);
    assert.match(cash, /kind == 0x03/);
  });

  it('does not reintroduce prep/sponsor/batch paths', () => {
    assert.doesNotMatch(cash, /sponsor|batcher|preparation|faucet/i);
  });
});
