// Self-test for runForgeBattery: drive it against a REAL deployed verifier — the
// frozen BN254 native crown (artifacts/bn254-native-standard/170366-patha) — and
// confirm it reproduces a known A1-green accept + known tamper-rejects.
//
//   NODE_PATH=<repo>/node_modules <tsx> forgeBattery.selftest.ts
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hexToBin } from '@bitauth/libauth';
import { runForgeBattery, witnessTamper, formatForgeSummary, type Tamper, type ForgeChunk } from './forgeBattery.js';

const CROWN = fileURLToPath(new URL('../../../artifacts/bn254-native-standard/170366-patha/chunks.json', import.meta.url));
const raw = JSON.parse(readFileSync(CROWN, 'utf8')) as Array<{
  name: string; inCommit: string; outCommit: string | null; lockingHex: string; unlockingHex: string;
}>;
const CATEGORY = new Uint8Array(32).fill(0xcd);

// Build harness Steps from the crown chunks: each non-terminal chunk is threaded
// as a covenant hand-off to the next chunk's locking (exactly the deployed shape).
const chunks: ForgeChunk[] = raw
  .map((c, i) => ({ c, i }))
  .filter(({ c }) => c.outCommit !== null) // non-terminal, fully covenant-pinned chunks
  .map(({ c, i }) => ({
    label: c.name,
    lockingBytecode: hexToBin(c.lockingHex),
    unlockingBytecode: hexToBin(c.unlockingHex),
    covenant: {
      category: CATEGORY,
      capability: 'mutable' as const,
      inCommitment: hexToBin(c.inCommit),
      outCommitment: hexToBin(c.outCommit!),
      outLockingBytecode: hexToBin(raw[i + 1]!.lockingHex),
    },
  }));

const flip = (bin: Uint8Array, idx: number) => { const b = bin.slice(); b[idx]! ^= 0x01; return b; };

// A cross-chunk tamper expressed through the general Tamper interface: reroute the
// covenant output to OP_1 — the successor-pin must reject (A1 class C, thread-escape).
const threadEscape: Tamper = {
  name: 'thread-escape[op1]',
  forge: ({ chunk }) =>
    chunk.covenant === undefined
      ? undefined
      : { ...chunk, covenant: { ...chunk.covenant, outLockingBytecode: Uint8Array.from([0x51]) } },
};

// covIn splice: flip a byte of the spent-UTXO commitment — covIn hash-binding rejects
// a chunk spliced onto a wrong predecessor (A1 class F).
const covInSplice: Tamper = {
  name: 'covIn-splice',
  forge: ({ chunk }) =>
    chunk.covenant === undefined
      ? undefined
      : { ...chunk, covenant: { ...chunk.covenant, inCommitment: flip(chunk.covenant.inCommitment, 5) } },
};

const result = runForgeBattery(chunks, [witnessTamper(0), threadEscape, covInSplice]);
console.log(formatForgeSummary(result));
console.log(`\nchunks under test: ${chunks.length} (crown non-terminal, covenant-pinned)`);
console.log(`honest accept sample: ${chunks[0]!.label} -> ${result.rows.find((r) => r.tamper === 'honest')!.accepted ? 'ACCEPT' : 'REJECT'} (op=${result.rows[0]!.operationCost})`);
const oneReject = result.rows.find((r) => r.tamper !== 'honest')!;
console.log(`tamper reject sample: ${oneReject.tamper} on ${oneReject.chunk} -> ${oneReject.accepted ? 'ACCEPT (BAD)' : 'REJECT (good)'}`);

// Self-test invariants: must ACCEPT every honest control, REJECT every forgery,
// and must actually have exercised forgeries (not a vacuous pass).
const ok =
  result.pass &&
  result.honestControls === chunks.length &&
  result.honestFailures === 0 &&
  result.acceptingForgeries === 0 &&
  result.forgeriesTested >= chunks.length * 3;
console.log(`\nSELF-TEST: ${ok ? 'PASS' : 'FAIL'}  (honest ${result.honestControls - result.honestFailures}/${result.honestControls}, forgeries rejected ${result.forgeriesTested - result.acceptingForgeries}/${result.forgeriesTested})`);
process.exit(ok ? 0 : 1);
