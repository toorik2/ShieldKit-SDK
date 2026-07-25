// RE-VERIFY covenant-thread-escape is CLOSED on the PATCHED build.
// Builds an identity chunk from the REAL production covIn/covOut helpers, in TWO variants:
//   PINNED   = covOut(names, succSpk)  -> patched NON-terminal chunk (self-pin present)
//   UNPINNED = covOut(names)           -> pre-patch / terminal-tail chunk (no pin)
// For each variant it drives the deployed P2SH32 scheme (redeem-in-scriptSig) through the
// real BCH-2026 VM (libauth) for honest + escape scenarios, and writes wire tx+srcouts hex
// per scenario (prefix /tmp/rv_<variant>_<scenario>) for the LeanBCH second oracle.
import { writeFileSync } from 'node:fs';
import { covIn, covOut, commitBin, CATEGORY, compileBytecodeRaw, decl } from './_millermath.mjs';
import {
  binToHex, bigIntToVmNumber, hash256, encodeLockingBytecodeP2sh32, encodeDataPush,
  numberToBinUint16LE, encodeTransaction, encodeTransactionOutputs, createVirtualMachineBch2026,
} from '@bitauth/libauth';

const realVm = createVirtualMachineBch2026(false);
const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const pushInt = (n) => encodeDataPush(bigIntToVmNumber(BigInt(n)));
const TARGET_UNLOCK = 10_000;
const padPush = (argLen, target) => { const N = target - argLen - 3; return Uint8Array.from([0x4d, ...numberToBinUint16LE(N), ...new Uint8Array(N)]); };

const names = ['a', 'b'];

// ---- build a successor chunk (its P2SH32 spk is what the pinned chunk commits to) ----
const succSrc =
  'pragma cashscript ^0.14.0;\ncontract Thread(){\n' +
  `    function spend(${decl(names)}, bytes unused zeroPadding){\n` +
  covIn(names) + '\n' + covOut(names) + '\n    }\n}\n';
const succRedeem = Uint8Array.from([...compileBytecodeRaw(succSrc)]);
const succSpk = encodeLockingBytecodeP2sh32(hash256(succRedeem)); // 35-byte committed-successor spk
const succSpkHex = binToHex(succSpk);

// a DIFFERENT but well-formed P2SH32 (attacker's own successor script) — value != succSpk
const attackerP2sh = encodeLockingBytecodeP2sh32(new Uint8Array(32).fill(0x11));
// yet another valid P2SH32 that is NOT the committed successor (wrong-but-real next chunk)
const wrongP2sh = encodeLockingBytecodeP2sh32(hash256(Uint8Array.from([0x52])));

function buildChunk(pinned) {
  const src =
    'pragma cashscript ^0.14.0;\ncontract Thread(){\n' +
    `    function spend(${decl(names)}, bytes unused zeroPadding){\n` +
    covIn(names) + '\n' + (pinned ? covOut(names, succSpkHex) : covOut(names)) + '\n    }\n}\n';
  const redeem = Uint8Array.from([...compileBytecodeRaw(src)]);
  const locking = encodeLockingBytecodeP2sh32(hash256(redeem)); // P2SH32 of the chunk
  return { redeem, locking, rpush: encodeDataPush(redeem) };
}

// introspection-op tally on the redeem (proves the pin opcodes are/aren't present)
function tally(buf) {
  let i = 0, t = {};
  while (i < buf.length) { const op = buf[i];
    if (op >= 0x01 && op <= 0x4b) i += 1 + op;
    else if (op === 0x4c) i += 2 + buf[i + 1];
    else if (op === 0x4d) i += 3 + (buf[i + 1] | (buf[i + 2] << 8));
    else if (op === 0x4e) i += 5 + (buf[i + 1] | (buf[i + 2] << 8) | (buf[i + 3] << 16) | (buf[i + 4] << 24));
    else { if (op >= 0xc0 && op <= 0xd3) t[op] = (t[op] || 0) + 1; i += 1; } }
  return t;
}

const a = 12345678901234567890n % P, b = 98765432109876543210n % P;
const inCommit = commitBin([a, b]);
const outCommit = commitBin([a % P, b % P]);   // reduced outgoing state (what covOut commits)
const argb = Uint8Array.from([...[a, b]].reverse().flatMap((c) => [...pushInt(c)]));

const tok = (commitment, cat = CATEGORY) => ({ amount: 0n, category: cat, nft: { capability: 'mutable', commitment } });

function run(variant, scenario, chunk, outputs, expectAccept) {
  const unlocking = Uint8Array.from([...padPush(argb.length + chunk.rpush.length, TARGET_UNLOCK), ...argb, ...chunk.rpush]);
  const program = {
    inputIndex: 0,
    sourceOutputs: [{ lockingBytecode: chunk.locking, valueSatoshis: 1000n, token: tok(inCommit) }],
    transaction: {
      version: 2,
      inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }],
      outputs, locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  const accepted = st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1;
  const pfx = `/tmp/rv_${variant}_${scenario}`;
  writeFileSync(pfx + '_tx.hex', binToHex(encodeTransaction(program.transaction)));
  writeFileSync(pfx + '_srcouts.hex', binToHex(encodeTransactionOutputs(program.sourceOutputs)));
  const ok = accepted === expectAccept;
  console.log(`[libauth] ${variant}/${scenario}: accepted=${accepted} expect=${expectAccept} ${ok ? 'OK' : '*** MISMATCH ***'} err=${st.error ?? 'none'} pfx=${pfx}`);
  return { variant, scenario, accepted, expectAccept, ok, pfx };
}

const results = [];
const p2pkh = Uint8Array.from([0x76, 0xa9, 0x14, ...new Uint8Array(20).fill(0xab), 0x88, 0xac]);
const opret = Uint8Array.from([0x6a]);

// ===================== PINNED (patched non-terminal) chunk =====================
const pin = buildChunk(true);
const tPin = tally(pin.redeem);
console.log('\nPINNED redeem introspection ops:', Object.entries(tPin).map(([k, v]) => '0x' + (+k).toString(16) + 'x' + v).join(', '));
console.log('  OP_OUTPUTBYTECODE(0xcd) present:', !!tPin[0xcd], '| OP_TXOUTPUTCOUNT(0xc4) present:', !!tPin[0xc4]);

// honest: single output routed to the COMMITTED successor spk, correct token -> ACCEPT
results.push(run('pin', 'honest', pin, [{ lockingBytecode: succSpk, valueSatoshis: 1000n, token: tok(outCommit) }], true));
// escape to OP_1 (trivial/attacker successor), correct token -> REJECT
results.push(run('pin', 'escape_op1', pin, [{ lockingBytecode: Uint8Array.from([0x51]), valueSatoshis: 1000n, token: tok(outCommit) }], false));
// escape to attacker's own P2SH32 successor, correct token -> REJECT
results.push(run('pin', 'escape_attacker_p2sh', pin, [{ lockingBytecode: attackerP2sh, valueSatoshis: 1000n, token: tok(outCommit) }], false));
// escape to a DIFFERENT valid P2SH32 != committed next-chunk spk, correct token -> REJECT
results.push(run('pin', 'escape_wrong_p2sh', pin, [{ lockingBytecode: wrongP2sh, valueSatoshis: 1000n, token: tok(outCommit) }], false));
// escape via extra outputs: output[0] honest (succSpk) BUT a 2nd output added -> REJECT (outputs.length==1)
// extra output valueSatoshis=0 so total out (1000) == total in (1000): txValid stays TRUE, isolating the covenant pin as the sole rejecter
results.push(run('pin', 'escape_extra_after_honest', pin, [
  { lockingBytecode: succSpk, valueSatoshis: 1000n, token: tok(outCommit) },
  { lockingBytecode: p2pkh, valueSatoshis: 0n },
], false));
// escape via extra outputs AND steal: output[0]=OP_1, plus extras -> REJECT
results.push(run('pin', 'escape_steal_plus_extra', pin, [
  { lockingBytecode: Uint8Array.from([0x51]), valueSatoshis: 1000n, token: tok(outCommit) },
  { lockingBytecode: opret, valueSatoshis: 0n },
], false));

// ===================== UNPINNED (pre-patch / terminal) chunk — reproduces the ORIGINAL forgery =====================
const unp = buildChunk(false);
const tUnp = tally(unp.redeem);
console.log('\nUNPINNED redeem introspection ops:', Object.entries(tUnp).map(([k, v]) => '0x' + (+k).toString(16) + 'x' + v).join(', ') || '(none)');
console.log('  OP_OUTPUTBYTECODE(0xcd) present:', !!tUnp[0xcd], '| OP_TXOUTPUTCOUNT(0xc4) present:', !!tUnp[0xc4]);

results.push(run('unpin', 'honest', unp, [{ lockingBytecode: succSpk, valueSatoshis: 1000n, token: tok(outCommit) }], true));
// the ORIGINAL forgery: route state NFT to OP_1 -> pre-patch code ACCEPTED
results.push(run('unpin', 'escape_op1', unp, [{ lockingBytecode: Uint8Array.from([0x51]), valueSatoshis: 1000n, token: tok(outCommit) }], true));
// original: route to attacker P2SH32 -> ACCEPTED
results.push(run('unpin', 'escape_attacker_p2sh', unp, [{ lockingBytecode: attackerP2sh, valueSatoshis: 1000n, token: tok(outCommit) }], true));
// original: extra outputs (extra value=0 so txValid holds) -> full ACCEPT (clean forgery)
results.push(run('unpin', 'escape_extra', unp, [
  { lockingBytecode: Uint8Array.from([0x51]), valueSatoshis: 1000n, token: tok(outCommit) },
  { lockingBytecode: p2pkh, valueSatoshis: 0n },
], true));

// controls: token continuity must ALWAYS reject regardless of pin (sanity)
results.push(run('pin', 'ctrl_wrong_category', pin, [{ lockingBytecode: succSpk, valueSatoshis: 1000n, token: tok(outCommit, new Uint8Array(32).fill(0xee)) }], false));
results.push(run('pin', 'ctrl_wrong_commit', pin, [{ lockingBytecode: succSpk, valueSatoshis: 1000n, token: tok(commitBin([a + 1n, b])) }], false));

const allOk = results.every((r) => r.ok);
console.log('\nLIBAUTH SUMMARY: allExpectationsMet =', allOk);
writeFileSync('/tmp/rv_scenarios.json', JSON.stringify(results.map(r => ({ variant: r.variant, scenario: r.scenario, accepted: r.accepted, expect: r.expectAccept, ok: r.ok, pfx: r.pfx })), null, 2));
console.log('succSpkHex =', succSpkHex);
console.log('wrote /tmp/rv_scenarios.json + per-scenario /tmp/rv_*_tx.hex /_srcouts.hex');
