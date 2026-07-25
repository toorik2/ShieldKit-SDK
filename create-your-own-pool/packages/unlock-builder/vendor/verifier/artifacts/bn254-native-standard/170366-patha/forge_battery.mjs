// A1 FORGE BATTERY against the FROZEN BN254 crown (170,366 B) — real BCH-2026 consensus VM.
// Reads ONLY the frozen artifact chunks.json + @bitauth/libauth. For each deployed chunk it first
// confirms the HONEST program accepts, then mutates the covenant surface and asserts REJECT:
//   A  witness-tamper : flip the last witness byte (immediately before the redeem push) in EVERY chunk
//   B  hashpin-tamper : flip a redeem byte (breaks P2SH32 hash256 pin) in EVERY chunk
//   C  thread-escape  : reroute output[0] to OP_1 / attacker-P2SH32 / wrong-P2SH32, or append an extra
//                       output, on every non-terminal (pinned) chunk  -> successor-pin must reject
//   D  covOut-tamper  : flip a byte of output[0] token nftCommitment (covOut) on every non-terminal chunk
//   E  category-swap  : output[0] token category cd->ee on every non-terminal chunk (continuity)
//   F  splice/covIn   : flip a byte of the input utxo token nftCommitment (inCommit) in EVERY chunk
//                       -> covIn hash-binding rejects a chunk spliced onto a wrong predecessor
// A single accepting forgery = A1 FAIL (exit 1).
//   node forge_battery.mjs [chunks.json]
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  hexToBin, binToHex, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  createVirtualMachineBch2026,
} from '@bitauth/libauth';

const HERE = dirname(fileURLToPath(import.meta.url));
const chunksPath = process.argv[2] ?? join(HERE, 'chunks.json');
const chunks = JSON.parse(readFileSync(chunksPath, 'utf8'));
const CATEGORY = new Uint8Array(32).fill(0xcd);
const vm = createVirtualMachineBch2026(false);

const tok = (commitment, cat = CATEGORY, cap = 'mutable') => ({ amount: 0n, category: cat, nft: { capability: cap, commitment } });
const flip = (bin, idx) => { const b = bin.slice(); b[idx] ^= 0x01; return b; };

function baseProgram(idx, over = {}) {
  const c = chunks[idx];
  const isTerminal = c.outCommit === null;
  const succLock = hexToBin(isTerminal ? c.lockingHex : chunks[idx + 1].lockingHex);
  const inTokenCommit = over.inCommit ?? hexToBin(c.inCommit);
  const outputs = over.outputs ?? [{ lockingBytecode: over.succLock ?? succLock, valueSatoshis: 1000n, ...(isTerminal ? {} : { token: tok(over.outCommit ?? hexToBin(c.outCommit), over.outCat ?? CATEGORY) }) }];
  return {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: hexToBin(c.lockingHex), valueSatoshis: 1000n, token: tok(inTokenCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: over.unlocking ?? hexToBin(c.unlockingHex) }],
      outputs, locktime: 0,
    },
  };
}
function accepts(program) {
  const st = vm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, err: st.error, op: st.metrics.operationCost };
}
// redeem push length (so we can locate the witness tail = byte just before the redeem push)
function rpushLen(redeem) {
  const R = redeem.length;
  if (R <= 75) return 1 + R;
  if (R <= 255) return 2 + R;
  if (R <= 65535) return 3 + R;
  return 5 + R;
}

const rows = [];
let accForge = 0, honestFail = 0;
const attackerP2sh = encodeLockingBytecodeP2sh32(new Uint8Array(32).fill(0x11));
const wrongP2sh = encodeLockingBytecodeP2sh32(hash256(Uint8Array.from([0x52])));
const p2pkh = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xab), 0x88, 0xac]);

function expect(tag, chunkName, program, wantAccept) {
  const r = accepts(program);
  const ok = r.accepted === wantAccept;
  if (wantAccept && !r.accepted) honestFail++;
  if (!wantAccept && r.accepted) accForge++;
  rows.push({ tag, chunk: chunkName, accepted: r.accepted, expect: wantAccept, ok, op: r.op, err: r.err ? String(r.err).slice(0, 60) : null });
  return ok;
}

for (let i = 0; i < chunks.length; i++) {
  const c = chunks[i];
  const isTerminal = c.outCommit === null;
  const unlocking = hexToBin(c.unlockingHex);
  const redeem = hexToBin(c.redeemHex);

  // honest control
  expect('honest', c.name, baseProgram(i), true);

  // A  witness-tamper (last witness byte, immediately before the redeem push)
  {
    const wIdx = unlocking.length - rpushLen(redeem) - 1;
    expect('A:witness-tamper', c.name, baseProgram(i, { unlocking: flip(unlocking, wIdx) }), false);
  }
  // B  hashpin-tamper (flip a redeem byte -> P2SH32 hash mismatch). Rebuild unlocking with tampered
  //    redeem push so the scriptSig still parses; the OP_HASH256<pin>OP_EQUAL must reject.
  {
    const bad = flip(redeem, Math.floor(redeem.length / 2));
    const head = unlocking.slice(0, unlocking.length - rpushLen(redeem));
    const badUnlock = Uint8Array.from([...head, ...encodeDataPush(bad)]);
    expect('B:hashpin-tamper', c.name, baseProgram(i, { unlocking: badUnlock }), false);
  }
  // F  splice/covIn: wrong input-utxo commitment (chunk spliced onto a wrong predecessor's covOut)
  {
    const badIn = flip(hexToBin(c.inCommit), 5);
    expect('F:covIn-splice', c.name, baseProgram(i, { inCommit: badIn }), false);
  }

  if (!isTerminal) {
    // C  thread-escape: reroute output[0].lockingBytecode (keep honest token) -> successor-pin rejects
    expect('C:escape-op1', c.name, baseProgram(i, { succLock: Uint8Array.from([0x51]) }), false);
    expect('C:escape-attackerP2SH', c.name, baseProgram(i, { succLock: attackerP2sh }), false);
    expect('C:escape-wrongP2SH', c.name, baseProgram(i, { succLock: wrongP2sh }), false);
    // extra output appended after the honest successor (value 0 so txValid holds) -> output-count pin rejects
    {
      const succLock = hexToBin(chunks[i + 1].lockingHex);
      const outs = [{ lockingBytecode: succLock, valueSatoshis: 1000n, token: tok(hexToBin(c.outCommit)) }, { lockingBytecode: p2pkh, valueSatoshis: 0n }];
      expect('C:escape-extra-output', c.name, baseProgram(i, { outputs: outs }), false);
    }
    // D  covOut-tamper: flip a byte of the successor token commitment
    expect('D:covOut-tamper', c.name, baseProgram(i, { outCommit: flip(hexToBin(c.outCommit), 7) }), false);
    // E  category-swap on the successor token
    expect('E:category-swap', c.name, baseProgram(i, { outCat: new Uint8Array(32).fill(0xee) }), false);
  }
}

// summary
const byTag = {};
for (const r of rows) { const k = r.tag.split(':')[0] + ':' + r.tag.split(':').slice(1).join(':'); (byTag[r.tag] ??= { n: 0, ok: 0 }); byTag[r.tag].n++; if (r.ok) byTag[r.tag].ok++; }
console.log('=== FORGE BATTERY (frozen crown, real BCH-2026 consensus VM) ===');
for (const [tag, v] of Object.entries(byTag)) console.log(`  ${tag.padEnd(24)} ${v.ok}/${v.n} as-expected`);
console.log(`\nhonest controls: ${rows.filter(r => r.tag === 'honest').length} (failures: ${honestFail})`);
console.log(`accepting forgeries: ${accForge}  (MUST be 0)`);
console.log(`\n=== RESULT: ${accForge === 0 && honestFail === 0 ? 'PASS — every forgery REJECTS, every honest control ACCEPTS' : '*** A1 FAIL: ' + accForge + ' accepting forgeries, ' + honestFail + ' honest failures ***'} ===`);
process.exit(accForge === 0 && honestFail === 0 ? 0 : 1);
