// test/covenant.mjs — the covenant dialect is recognized + refuses in-place emit.
//
// Uses a SYNTHETIC covenant-shaped bytecode (a HASH256…EQUALVERIFY self-commitment prologue
// followed by a trivial define) — no competitive artifact. Asserts (1) auto-detection picks the
// covenant-wrapped dialect, and (2) the emit-safety classifier refuses because the body is
// hash-committed. Also asserts a plain cashc-standard program is NOT misdetected as covenant.
import { autoDetect } from '../dialect/index.mjs';
import { classifyEmitSafety, looksCovenant } from '../dialect/covenant-wrapped.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
let fails = 0;
const ok = (c, m) => { if (c) console.log(`✓ ${m}`); else { console.error(`✗ ${m}`); fails++; } };

// synthetic covenant: OP_DROP OP_DUP OP_HASH256 <32B> OP_EQUALVERIFY  <body-push> OP_1 OP_DEFINE  OP_1
const commit = Array.from({ length: 32 }, (_, i) => i & 0xff);
const cov = Uint8Array.from([
  0x75, 0x76, 0xaa, 0x20, ...commit, 0x88,   // DROP DUP HASH256 PUSH32<commit> EQUALVERIFY
  0x01, 0x51, 0x51, 0x89,                     // PUSHBYTES_1 0x51 (body) OP_1 (id) OP_DEFINE
  0x51,                                        // OP_1 (main)
]);

ok(looksCovenant(cov), 'synthetic covenant bytecode is recognized (HASH256…EQUALVERIFY prologue)');
ok(autoDetect(cov).name === 'covenant-wrapped', 'auto-detect selects the covenant-wrapped dialect');
const safety = classifyEmitSafety(cov);
ok(safety.safe === false, 'emit-safety: covenant refuses in-place emit');
ok(/hash-committed|commitment/i.test(safety.reason), `refusal reason cites the hash commitment: "${safety.reason.slice(0, 60)}…"`);

// a plain cashc-standard program (the toy) must NOT be misdetected as covenant
const toy = Uint8Array.from(Buffer.from(readFileSync(join(HERE, 'fixtures', 'toy-in.hex'), 'utf8').trim(), 'hex'));
ok(!looksCovenant(toy), 'plain cashc-standard program is NOT misdetected as covenant');
ok(autoDetect(toy).name === 'cashc-standard', 'auto-detect selects cashc-standard for a plain program');

if (fails) { console.error(`\n${fails} covenant test FAILURE(s)`); process.exit(1); }
console.log('\nall covenant tests passed');
