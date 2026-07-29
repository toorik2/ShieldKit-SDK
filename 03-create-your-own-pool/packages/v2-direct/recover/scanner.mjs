/**
 * Genesis-lineage recovery scanner for V2 Direct.
 * Never picks highest-sequence unrelated candidate; follows spent-state lineage.
 */
import { decodeActionPacketV2 } from '../packet.mjs';
import { decodePoolStateV2 } from '../state.mjs';
import { ACTION_PACKET_BYTES, POOL_STATE_BYTES } from '../constants.mjs';

export class RecoveryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RecoveryError';
  }
}

const fail = (m) => {
  throw new RecoveryError(m);
};

/**
 * @param {object} args
 * @param {{txid:string,vout:number,commitment:Uint8Array,category:string}} args.genesisStateOutpoint
 * @param {Array<{txid:string,vin:Array,vout:Array,packetHex?:string}>} args.chainTxs
 *   Ordered chain of txs that spend the state lineage (confirmed).
 */
export function recoverFromGenesisLineage({
  genesisStateOutpoint,
  chainTxs,
  instanceCategory,
}) {
  if (!genesisStateOutpoint?.txid || genesisStateOutpoint.vout === undefined) {
    fail('genesis outpoint required');
  }
  let current = {
    txid: genesisStateOutpoint.txid,
    vout: genesisStateOutpoint.vout,
  };
  const states = [];
  const packets = [];

  if (genesisStateOutpoint.commitment) {
    states.push(decodePoolStateV2(genesisStateOutpoint.commitment));
  }

  for (const tx of chainTxs) {
    // Must spend current state outpoint
    const spends = (tx.vin || []).some(
      (input) => input.txid === current.txid && Number(input.vout) === Number(current.vout),
    );
    if (!spends) {
      fail(`lineage break: tx ${tx.txid} does not spend state ${current.txid}:${current.vout}`);
    }
    // Find successor state output (vout 0 by topology)
    const stateOut = (tx.vout || []).find((o) => o.n === 0) || (tx.vout || [])[0];
    if (!stateOut?.commitment) fail(`missing state commitment on ${tx.txid}`);
    if (stateOut.category && instanceCategory && stateOut.category !== instanceCategory) {
      fail('state category mismatch on lineage');
    }
    if (stateOut.commitment.length !== POOL_STATE_BYTES) {
      fail('state commitment length invalid');
    }
    const state = decodePoolStateV2(stateOut.commitment);
    states.push(state);

    if (tx.packetHex) {
      const packet = Buffer.from(tx.packetHex, 'hex');
      if (packet.length !== ACTION_PACKET_BYTES) fail('packet length invalid in recovery');
      const decoded = decodeActionPacketV2(packet);
      packets.push(decoded);
    }

    current = { txid: tx.txid, vout: stateOut.n ?? 0 };
  }

  // Reject highest-sequence unrelated candidate heuristic: we only accept the chain above.
  return Object.freeze({
    tipOutpoint: current,
    states: Object.freeze(states),
    packets: Object.freeze(packets),
    tipState: states[states.length - 1] || null,
  });
}

/**
 * Apply reorg undo: drop last `depth` confirmed actions; if depth > 100, wipe.
 */
export function applyReorgUndo(recovered, depth, { maxUndo = 100 } = {}) {
  if (depth > maxUndo) {
    return Object.freeze({ wiped: true, reason: 'reorg deeper than undo journal' });
  }
  if (depth <= 0) return Object.freeze({ wiped: false, states: recovered.states, packets: recovered.packets });
  const states = recovered.states.slice(0, Math.max(1, recovered.states.length - depth));
  const packets = recovered.packets.slice(0, Math.max(0, recovered.packets.length - depth));
  return Object.freeze({
    wiped: false,
    states,
    packets,
    tipState: states[states.length - 1] || null,
  });
}
