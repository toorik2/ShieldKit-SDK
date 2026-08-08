import assert from 'node:assert/strict';
import test from 'node:test';

const profile = { SZ_ALLAFF: '1', L17SEL: '1' };

test('PairFold generator binds genesis and terminal to one mixed transcript', async () => {
  const previous = Object.fromEntries(Object.keys(profile).map((name) => [name, process.env[name]]));
  Object.assign(process.env, profile);
  try {
    const [math, generator, route] = await Promise.all([
      import(new URL('../src/c7/mixed-szmath.mjs?pairfold-mixed-transcript=1', import.meta.url).href),
      import(new URL('../src/c7/mixed-sz.mjs?pairfold-mixed-transcript=1', import.meta.url).href),
      import(new URL('../src/c7/composed-window-szmath.mjs?pairfold-mixed-transcript=1', import.meta.url).href),
    ]);
    const trace = route.mixedGenesisTrajectory();
    const pushed = generator.pushedArgs(0, 1, true, false);
    const gammaIndex = 10 + 12 + 12;
    assert.equal(pushed[gammaIndex], trace.gamma);
    assert.equal(pushed[gammaIndex + 1], trace.z);
    assert.equal(generator.closePushedArgsC().length, trace.bigQ.length + 4);

    const gammaTag = Buffer.from(math.hash256(math.TAG_GAMMA)).toString('hex');
    const zTag = Buffer.from(math.TAG_Z).toString('hex');
    assert.match(generator.genChunk(0, 1, false, true), new RegExp(`0x${gammaTag}`));
    assert.match(generator.genCloseChunk(null, { compress: true, loop: true }), new RegExp(`0x${zTag}`));
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});
