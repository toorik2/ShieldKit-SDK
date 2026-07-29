pragma circom 2.2.0;

include "../../../node_modules/circomlib/circuits/aliascheck.circom";
include "../../../node_modules/circomlib/circuits/bitify.circom";
include "../../../node_modules/circomlib/circuits/comparators.circom";
include "../../../node_modules/circomlib/circuits/compconstant.circom";

template AssertBoolean() {
    signal input in;
    in * (in - 1) === 0;
}

template AssertZeroIfDisabled() {
    signal input enabled;
    signal input value;

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;
    value * (1 - enabled) === 0;
}

template ForceEqualIfEnabledV2() {
    signal input enabled;
    signal input left;
    signal input right;

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;
    (left - right) * enabled === 0;
}

template ByteToBits() {
    signal input in;
    signal output bits[8];

    component split = Num2Bits(8);
    split.in <== in;
    for (var bit = 0; bit < 8; bit++) {
        bits[bit] <== split.out[bit];
    }
}

// Decode already range-constrained little-endian byte bits. These cores let
// the final relation reuse PacketDigest552's one canonical byte split.
template ByteBitsBEToU128() {
    signal input byteBits[16][8];
    signal output out;

    var coefficient = 1;
    var sum = 0;
    for (var reverse = 0; reverse < 16; reverse++) {
        var index = 15 - reverse;
        for (var bit = 0; bit < 8; bit++) {
            sum += byteBits[index][bit] * coefficient * (1 << bit);
        }
        coefficient *= 256;
    }
    out <== sum;
}

template ByteBitsLEToU32() {
    signal input byteBits[4][8];
    signal output out;

    var coefficient = 1;
    var sum = 0;
    for (var index = 0; index < 4; index++) {
        for (var bit = 0; bit < 8; bit++) {
            sum += byteBits[index][bit] * coefficient * (1 << bit);
        }
        coefficient *= 256;
    }
    out <== sum;
}

template ByteBitsLEToU64() {
    signal input byteBits[8][8];
    signal output out;

    var coefficient = 1;
    var sum = 0;
    for (var index = 0; index < 8; index++) {
        for (var bit = 0; bit < 8; bit++) {
            sum += byteBits[index][bit] * coefficient * (1 << bit);
        }
        coefficient *= 256;
    }
    out <== sum;
}

// Decode one canonical 32-byte big-endian BN254 Fr encoding. The two unused
// high bits are explicitly zero and AliasCheck rejects every value >= Fr.
template ByteBitsBEToFr() {
    signal input byteBits[32][8];
    signal output out;
    signal bits[254];

    byteBits[0][7] === 0;
    byteBits[0][6] === 0;

    for (var bit = 0; bit < 254; bit++) {
        var byteFromEnd = bit \ 8;
        var bitInByte = bit % 8;
        bits[bit] <== byteBits[31 - byteFromEnd][bitInByte];
    }

    component decoded = Bits2Num_strict();
    for (var bit = 0; bit < 254; bit++) {
        decoded.in[bit] <== bits[bit];
    }
    out <== decoded.out;
}

// Raw-byte wrappers remain the standalone-test ABI. Each wrapper creates one
// canonical byte split and delegates all endian/canonicality rules to the same
// bit-input core used by the final relation.
template BytesBEToU128() {
    signal input bytes[16];
    signal output out;

    component byteBits[16];
    component decoded = ByteBitsBEToU128();
    for (var index = 0; index < 16; index++) {
        byteBits[index] = ByteToBits();
        byteBits[index].in <== bytes[index];
        for (var bit = 0; bit < 8; bit++) {
            decoded.byteBits[index][bit] <== byteBits[index].bits[bit];
        }
    }
    out <== decoded.out;
}

template BytesLEToU32() {
    signal input bytes[4];
    signal output out;

    component byteBits[4];
    component decoded = ByteBitsLEToU32();
    for (var index = 0; index < 4; index++) {
        byteBits[index] = ByteToBits();
        byteBits[index].in <== bytes[index];
        for (var bit = 0; bit < 8; bit++) {
            decoded.byteBits[index][bit] <== byteBits[index].bits[bit];
        }
    }
    out <== decoded.out;
}

template BytesLEToU64() {
    signal input bytes[8];
    signal output out;

    component byteBits[8];
    component decoded = ByteBitsLEToU64();
    for (var index = 0; index < 8; index++) {
        byteBits[index] = ByteToBits();
        byteBits[index].in <== bytes[index];
        for (var bit = 0; bit < 8; bit++) {
            decoded.byteBits[index][bit] <== byteBits[index].bits[bit];
        }
    }
    out <== decoded.out;
}

template BytesBEToFr() {
    signal input bytes[32];
    signal output out;

    component byteBits[32];
    component decoded = ByteBitsBEToFr();
    for (var index = 0; index < 32; index++) {
        byteBits[index] = ByteToBits();
        byteBits[index].in <== bytes[index];
        for (var bit = 0; bit < 8; bit++) {
            decoded.byteBits[index][bit] <== byteBits[index].bits[bit];
        }
    }
    out <== decoded.out;
}

template NumToBits32() {
    signal input in;
    signal output bits[32];

    component split = Num2Bits(32);
    split.in <== in;
    for (var bit = 0; bit < 32; bit++) {
        bits[bit] <== split.out[bit];
    }
}

template NumToBits64() {
    signal input in;
    signal output bits[64];

    component split = Num2Bits(64);
    split.in <== in;
    for (var bit = 0; bit < 64; bit++) {
        bits[bit] <== split.out[bit];
    }
}

// Both inputs are little-endian bit arrays. This comparator works at 254 bits,
// avoiding circomlib's 252-bit LessThan limit.
template BitsLessThan(n) {
    signal input left[n];
    signal input right[n];
    signal output less;

    signal prefixEqual[n + 1];
    signal prefixLess[n + 1];
    signal sameBit[n];
    signal mayBecomeLess[n];
    prefixEqual[0] <== 1;
    prefixLess[0] <== 0;

    for (var step = 0; step < n; step++) {
        var bit = n - 1 - step;
        sameBit[step] <==
            1 - left[bit] - right[bit] + 2 * left[bit] * right[bit];
        mayBecomeLess[step] <== prefixEqual[step] * (1 - left[bit]);
        prefixLess[step + 1] <==
            prefixLess[step]
            + mayBecomeLess[step] * right[bit];
        prefixEqual[step + 1] <==
            prefixEqual[step] * sameBit[step];
    }

    less <== prefixLess[n];
}

template AssertNonZero() {
    signal input in;

    component zero = IsZero();
    zero.in <== in;
    zero.out === 0;
}

// A private BabyJub scalar is a nonzero integer strictly below the subgroup
// order, not merely a BN254 field element.
template BabyJubScalarBits() {
    signal input scalar;
    signal output bits[251];

    component nonzero = AssertNonZero();
    nonzero.in <== scalar;

    component split = Num2Bits(253);
    split.in <== scalar;

    component atMostOrderMinusOne =
        CompConstant(2736030358979909402780800718157159386076813972158567259200215660948447373040);
    for (var bit = 0; bit < 253; bit++) {
        atMostOrderMinusOne.in[bit] <== split.out[bit];
    }
    atMostOrderMinusOne.in[253] <== 0;
    atMostOrderMinusOne.out === 0;

    // The subgroup order is 251 bits. The comparison above forces these high
    // bits to zero; expose only the bits accepted by EscalarMulAny.
    split.out[251] === 0;
    split.out[252] === 0;
    for (var bit = 0; bit < 251; bit++) {
        bits[bit] <== split.out[bit];
    }
}
