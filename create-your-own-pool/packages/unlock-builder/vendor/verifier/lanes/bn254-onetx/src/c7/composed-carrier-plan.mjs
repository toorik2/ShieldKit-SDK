// Byte-exact carrier allocation for the standard P2SH transition.
//
// The old direct locks held part of the fixed-G2 tables and the terminal
// verifier. After standardizing locks those bytes must live in scriptSigs.
// The composed windows free enough record space, but executor zero cannot
// hold its whole table. This plan shards one global table bundle across the
// five executor inBlobs and uses the remaining suffixes for terminal code.

export const LEGACY_EXECUTOR_TRANSPORT = Object.freeze([
  { unlocking: 10_000, witness: 6_144, fixedTableWitness: 0 },
  { unlocking: 9_215, witness: 6_080, fixedTableWitness: 1_536 },
  { unlocking: 9_104, witness: 6_080, fixedTableWitness: 2_460 },
  { unlocking: 9_071, witness: 6_080, fixedTableWitness: 2_427 },
  { unlocking: 8_052, witness: 5_184, fixedTableWitness: 2_304 },
]);

const sum = (values) => values.reduce((total, value) => total + value, 0);

const cat = (parts) => Uint8Array.from(parts.flatMap((part) => [...part]));

// Map the one authenticated global table bundle onto the table prefixes of the
// five [table || terminal] carriers.  The returned segments are deliberately
// expressed in raw unlocking-bytecode offsets by the caller: this layer owns
// only payload bytes, so it cannot accidentally hide a push header or redeem
// suffix in a table slice.
export const layoutComposedTableCarriers = ({ tableParts, rows }) => {
  if (!Array.isArray(tableParts) || !tableParts.length || tableParts.some((part) => !(part instanceof Uint8Array))) {
    throw new Error('table carrier layout requires nonempty byte-array table parts');
  }
  if (!Array.isArray(rows) || !rows.length || rows.some((row) => !Number.isInteger(row?.tableBytes) || row.tableBytes < 0)) {
    throw new Error('table carrier layout requires non-negative row table capacities');
  }
  const table = cat(tableParts);
  const capacity = sum(rows.map((row) => row.tableBytes));
  if (capacity !== table.length) {
    throw new Error(`table carrier capacity ${capacity} does not equal table bundle ${table.length}`);
  }

  let cursor = 0;
  const carriers = rows.map((row, carrierIndex) => {
    const bytes = table.slice(cursor, cursor + row.tableBytes);
    const out = { carrierIndex, tableOffset: cursor, bytes };
    cursor += bytes.length;
    return out;
  });

  let tableOffset = 0;
  const roles = tableParts.map((part, roleIndex) => {
    const end = tableOffset + part.length;
    const segments = carriers.flatMap((carrier) => {
      const carrierEnd = carrier.tableOffset + carrier.bytes.length;
      const start = Math.max(tableOffset, carrier.tableOffset);
      const stop = Math.min(end, carrierEnd);
      return start < stop ? [{
        carrierIndex: carrier.carrierIndex,
        // This offset is inside the carrier's table prefix, before any
        // terminal suffix. The assembler adds its canonical PUSHDATA2 offset.
        payloadOffset: start - carrier.tableOffset,
        tableOffset: start - tableOffset,
        length: stop - start,
      }] : [];
    });
    if (sum(segments.map((segment) => segment.length)) !== part.length) {
      throw new Error(`table role ${roleIndex} is not fully covered by carriers`);
    }
    const out = { roleIndex, tableOffset, length: part.length, segments };
    tableOffset = end;
    return out;
  });

  return { table, carriers, roles };
};

export const reconstructComposedTableRole = ({ carrierPayloads, role }) => {
  if (!Array.isArray(carrierPayloads) || carrierPayloads.some((payload) => !(payload instanceof Uint8Array))) {
    throw new Error('table reconstruction requires carrier payload byte arrays');
  }
  if (!role || !Array.isArray(role.segments) || !Number.isInteger(role.length) || role.length < 0) {
    throw new Error('table reconstruction requires a carrier role layout');
  }
  const parts = role.segments.map((segment) => {
    const payload = carrierPayloads[segment.carrierIndex];
    if (!(payload instanceof Uint8Array) || segment.payloadOffset + segment.length > payload.length) {
      throw new Error(`carrier ${segment.carrierIndex} cannot supply table role ${role.roleIndex}`);
    }
    return payload.slice(segment.payloadOffset, segment.payloadOffset + segment.length);
  });
  const table = cat(parts);
  if (table.length !== role.length) throw new Error(`table role ${role.roleIndex} reconstructed to an unexpected length`);
  return table;
};

export const planComposedP2shCarriers = ({
  witnessBytes,
  tableBytes,
  terminalBodyBytes,
  executorRedeemBytes = 122,
  carrierPushBytes = 3,
  minimumTerminalFragment = 256,
  legacy = LEGACY_EXECUTOR_TRANSPORT,
}) => {
  if (!Array.isArray(witnessBytes) || witnessBytes.length !== legacy.length || witnessBytes.some((value) => !Number.isInteger(value) || value < 0)) {
    throw new Error('carrier plan requires one non-negative composed witness size per executor');
  }
  if (!Number.isInteger(tableBytes) || tableBytes < 0 || !Number.isInteger(terminalBodyBytes) || terminalBodyBytes < minimumTerminalFragment * legacy.length) {
    throw new Error('carrier plan received an invalid table or terminal size');
  }
  if (!Number.isInteger(executorRedeemBytes) || executorRedeemBytes < 0
      || !Number.isInteger(carrierPushBytes) || carrierPushBytes < 1
      || !Number.isInteger(minimumTerminalFragment) || minimumTerminalFragment < 1) {
    throw new Error('carrier plan received an invalid redeem or fragment size');
  }
  const rows = legacy.map((old, index) => {
    const fixedBase = old.unlocking - old.witness - old.fixedTableWitness;
    const fixedUnlock = fixedBase + witnessBytes[index] + executorRedeemBytes;
    // The sharded [table || terminal] carrier is an additional canonical
    // PUSHDATA2 item in every scriptSig. Its three-byte opcode/length header
    // is scored and must be reserved before allocating any live payload.
    const capacity = 10_000 - fixedUnlock - carrierPushBytes;
    if (capacity < minimumTerminalFragment) throw new Error(`executor ${index} cannot carry a terminal fragment`);
    return { index, fixedBase, witnessBytes: witnessBytes[index], fixedUnlock, capacity, tableBytes: 0, terminalBytes: minimumTerminalFragment };
  });

  let terminalRemaining = terminalBodyBytes - minimumTerminalFragment * rows.length;
  for (let index = rows.length - 1; index >= 0 && terminalRemaining > 0; index -= 1) {
    const room = rows[index].capacity - rows[index].terminalBytes;
    const take = Math.min(room, terminalRemaining);
    rows[index].terminalBytes += take;
    terminalRemaining -= take;
  }
  if (terminalRemaining !== 0) throw new Error(`terminal body exceeds carrier capacity by ${terminalRemaining} bytes`);

  let tableRemaining = tableBytes;
  for (const row of rows) {
    const room = row.capacity - row.terminalBytes;
    const take = Math.min(room, tableRemaining);
    row.tableBytes = take;
    tableRemaining -= take;
  }
  if (tableRemaining !== 0) throw new Error(`fixed table exceeds carrier capacity by ${tableRemaining} bytes`);
  for (const row of rows) row.payloadBytes = row.tableBytes + row.terminalBytes;
  return {
    rows,
    tableBytes,
    terminalBodyBytes,
    carrierPushBytes,
    payloadBytes: sum(rows.map((row) => row.payloadBytes)),
    capacityBytes: sum(rows.map((row) => row.capacity)),
    slackBytes: sum(rows.map((row) => row.capacity - row.payloadBytes)),
  };
};
