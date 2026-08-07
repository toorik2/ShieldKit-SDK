// Self-test for the reality gate. Proves it (a) passes a real accepting input,
// (b) THROWS on a zero-fill placeholder, (c) THROWS on a real-but-rejecting input.
// Run: npx tsx src/harness/realTx.selftest.ts
import { assertAllInputsReal, looksPlaceholder } from './realTx.js';

const bytes = (...xs: number[]) => Uint8Array.from(xs);
const OP_EQUAL = 0x87;
const OP_7 = 0x57; // minimal push of 7 (MINIMALDATA-clean)
const OP_8 = 0x58; // minimal push of 8

let pass = 0;
let fail = 0;
const check = (name: string, cond: boolean, extra = '') => {
  if (cond) {
    pass++;
    console.log('  ok   ', name);
  } else {
    fail++;
    console.log('  FAIL ', name, extra);
  }
};

// (1) a REAL accepting input passes: unlocking pushes 7 then 7; locking OP_EQUAL -> 1.
try {
  const r = assertAllInputsReal(
    [{ lockingBytecode: bytes(OP_EQUAL), unlockingBytecode: bytes(OP_7, OP_7) }],
    { label: 'selftest-accept' },
  );
  check('real accepting input -> ok', r.ok === true && r.scoreBytesRaw === 3);
} catch (e) {
  check('real accepting input -> ok', false, String(e).slice(0, 140));
}

// (2) a ZERO-FILL placeholder input THROWS.
try {
  assertAllInputsReal([{ lockingBytecode: bytes(OP_EQUAL), unlockingBytecode: new Uint8Array(40) }], { label: 'selftest-zerofill' });
  check('zero-fill placeholder -> THROWS', false, 'did not throw');
} catch {
  check('zero-fill placeholder -> THROWS', true);
}

// (3) a REAL-but-REJECTING input THROWS: pushes 7 then 8; OP_EQUAL -> 0 (false).
try {
  assertAllInputsReal([{ lockingBytecode: bytes(OP_EQUAL), unlockingBytecode: bytes(OP_7, OP_8) }], { label: 'selftest-reject' });
  check('real-but-rejects -> THROWS', false, 'did not throw');
} catch {
  check('real-but-rejects -> THROWS', true);
}

// (4) advisory heuristic: empty/all-zero flagged; a moderate constant run is NOT (false-positive fix).
check('empty flagged filler', looksPlaceholder(new Uint8Array(0)).placeholder === true);
check('all-zero flagged filler', looksPlaceholder(new Uint8Array(40)).placeholder === true);
check('64-byte run NOT auto-flagged (real narrowed witness)', looksPlaceholder(new Uint8Array(64).fill(0xab)).placeholder === false);

// (5) CRITICAL false-negative fix: a VM-ACCEPTING input that LOOKS like filler must PASS, not throw.
// Unlocking = OP_PUSHBYTES_75 <75 zero bytes> then OP_2DROP-free real check. Build a locking that
// accepts a long low-entropy push: push256-run then OP_SIZE <len> OP_EQUAL is fiddly; instead use a
// long push the VM accepts as a single item and a locking that drops it and returns 1.
{
  const OP_DROP = 0x75, OP_1 = 0x51;
  // OP_PUSHDATA2 300 <300×0xab> — a 300-byte constant run trips the >=256 advisory threshold.
  const longPush = Uint8Array.from([0x4d, 0x2c, 0x01, ...new Array(300).fill(0xab)]);
  const locking = bytes(OP_DROP, OP_1); // drop the (filler-looking) item, push 1 -> VM accepts
  try {
    const r = assertAllInputsReal([{ lockingBytecode: locking, unlockingBytecode: longPush }], { label: 'selftest-accepting-filler' });
    check('VM-accepting filler-looking input -> PASSES (not thrown), warned', r.ok === true && r.warnings.length === 1);
  } catch (e) {
    check('VM-accepting filler-looking input -> PASSES (not thrown), warned', false, String(e).slice(0, 140));
  }
}

console.log(`\nrealTx reality-gate self-test: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
