import test from 'node:test';
import { runStrictCodecQualification } from './strict-codec-qualification.mjs';
import { actionPacketPublicLimbs, decodeActionPacket, digestActionPacket, encodeActionPacket } from './packet.mjs';
import { decodeStateNftCommitment, encodeStateNftCommitment } from './state.mjs';

test('frozen V2 JS codec qualification exhausts every alternate state and packet byte', () => {
  const evidence = runStrictCodecQualification({
    name: 'javascript', decodeState: decodeStateNftCommitment, encodeState: encodeStateNftCommitment,
    decodePacket: decodeActionPacket, encodePacket: encodeActionPacket,
    digestPacket: digestActionPacket, packetLimbs: actionPacketPublicLimbs,
  });
  console.log(`V2_STRICT_CODEC_QUALIFICATION=${JSON.stringify(evidence)}`);
});
