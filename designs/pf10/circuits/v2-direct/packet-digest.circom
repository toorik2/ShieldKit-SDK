pragma circom 2.2.0;

include "common.circom";
include "../../../../node_modules/circomlib/circuits/sha256/sha256.circom";

// SHA-256 of the exact 552-byte SDA2 packet. Packet bytes enter SHA-256 in
// network bit order. Circomlib exposes the final digest in standard
// most-significant-bit-first word order; the final loops form two BE u128s.
template PacketDigest552() {
    signal input packet[552];
    signal output publicInput0;
    signal output publicInput1;
    signal output packetBits[552][8];

    component byteBits[552];
    component digest = Sha256(4416);

    for (var byte = 0; byte < 552; byte++) {
        byteBits[byte] = ByteToBits();
        byteBits[byte].in <== packet[byte];
        for (var bit = 0; bit < 8; bit++) {
            packetBits[byte][bit] <== byteBits[byte].bits[bit];
            digest.in[byte * 8 + bit] <== byteBits[byte].bits[7 - bit];
        }
    }

    var first = 0;
    var second = 0;
    for (var byte = 0; byte < 16; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            var digestBit = (byte \ 4) * 32 + (byte % 4) * 8 + bit;
            first += digest.out[digestBit] * (1 << (127 - byte * 8 - bit));
        }
    }
    for (var byte = 16; byte < 32; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            var digestBit = (byte \ 4) * 32 + (byte % 4) * 8 + bit;
            second += digest.out[digestBit] * (1 << (255 - byte * 8 - bit));
        }
    }

    publicInput0 <== first;
    publicInput1 <== second;
}
