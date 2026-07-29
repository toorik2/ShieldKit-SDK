pragma circom 2.2.0;

include "common.circom";

// Parse and validate the exact native 128-byte SKS2 NFT commitment. This
// component validates all protocol-wide state invariants independently for
// both the pre-state and post-state.
template PoolStateV2FromBits() {
    signal input bytes[128];
    signal input byteBits[128][8];

    signal output profileId[2];
    signal output noteRoot;
    signal output nullifierRoot;
    signal output noteCount;
    signal output nullifierCount;
    signal output maximumLiveNotes;
    signal output reserveSats;
    signal output actionSequence;
    signal output liveNoteCount;

    bytes[0] === 0x53;
    bytes[1] === 0x4b;
    bytes[2] === 0x53;
    bytes[3] === 0x32;

    component profileHigh = ByteBitsBEToU128();
    component profileLow = ByteBitsBEToU128();
    for (var index = 0; index < 16; index++) {
        for (var bit = 0; bit < 8; bit++) {
            profileHigh.byteBits[index][bit] <== byteBits[4 + index][bit];
            profileLow.byteBits[index][bit] <== byteBits[20 + index][bit];
        }
    }
    profileId[0] <== profileHigh.out;
    profileId[1] <== profileLow.out;

    component noteRootDecoder = ByteBitsBEToFr();
    component nullifierRootDecoder = ByteBitsBEToFr();
    for (var index = 0; index < 32; index++) {
        for (var bit = 0; bit < 8; bit++) {
            noteRootDecoder.byteBits[index][bit] <==
                byteBits[36 + index][bit];
            nullifierRootDecoder.byteBits[index][bit] <==
                byteBits[68 + index][bit];
        }
    }
    noteRoot <== noteRootDecoder.out;
    nullifierRoot <== nullifierRootDecoder.out;

    component noteCountDecoder = ByteBitsLEToU32();
    component nullifierCountDecoder = ByteBitsLEToU32();
    component maximumDecoder = ByteBitsLEToU32();
    for (var index = 0; index < 4; index++) {
        for (var bit = 0; bit < 8; bit++) {
            noteCountDecoder.byteBits[index][bit] <==
                byteBits[100 + index][bit];
            nullifierCountDecoder.byteBits[index][bit] <==
                byteBits[104 + index][bit];
            maximumDecoder.byteBits[index][bit] <==
                byteBits[108 + index][bit];
        }
    }
    noteCount <== noteCountDecoder.out;
    nullifierCount <== nullifierCountDecoder.out;
    maximumLiveNotes <== maximumDecoder.out;

    component reserveDecoder = ByteBitsLEToU64();
    component sequenceDecoder = ByteBitsLEToU64();
    for (var index = 0; index < 8; index++) {
        for (var bit = 0; bit < 8; bit++) {
            reserveDecoder.byteBits[index][bit] <==
                byteBits[112 + index][bit];
            sequenceDecoder.byteBits[index][bit] <==
                byteBits[120 + index][bit];
        }
    }
    reserveSats <== reserveDecoder.out;
    actionSequence <== sequenceDecoder.out;

    component nullifiersWithinNotes = LessEqThan(32);
    nullifiersWithinNotes.in[0] <== nullifierCount;
    nullifiersWithinNotes.in[1] <== noteCount;
    nullifiersWithinNotes.out === 1;

    liveNoteCount <== noteCount - nullifierCount;

    component nonzeroMaximum = AssertNonZero();
    nonzeroMaximum.in <== maximumLiveNotes;
    component maximumMoneyBound = LessEqThan(32);
    maximumMoneyBound.in[0] <== maximumLiveNotes;
    maximumMoneyBound.in[1] <== 210000000;
    maximumMoneyBound.out === 1;

    component liveWithinMaximum = LessEqThan(32);
    liveWithinMaximum.in[0] <== liveNoteCount;
    liveWithinMaximum.in[1] <== maximumLiveNotes;
    liveWithinMaximum.out === 1;

    reserveSats === liveNoteCount * 10000000;
    component reserveMoneyBound = LessEqThan(64);
    reserveMoneyBound.in[0] <== reserveSats;
    reserveMoneyBound.in[1] <== 2100000000000000;
    reserveMoneyBound.out === 1;

    component nullifierProtocolBound = LessEqThan(32);
    nullifierProtocolBound.in[0] <== nullifierCount;
    nullifierProtocolBound.in[1] <== 0xfffffffe;
    nullifierProtocolBound.out === 1;

    component noteWithinSequence = LessEqThan(33);
    noteWithinSequence.in[0] <== noteCount;
    noteWithinSequence.in[1] <== actionSequence;
    noteWithinSequence.out === 1;

    component nullifierWithinSequence = LessEqThan(33);
    nullifierWithinSequence.in[0] <== nullifierCount;
    nullifierWithinSequence.in[1] <== actionSequence;
    nullifierWithinSequence.out === 1;

    component sequenceWithinCounterSum = LessEqThan(33);
    sequenceWithinCounterSum.in[0] <== actionSequence;
    sequenceWithinCounterSum.in[1] <== noteCount + nullifierCount;
    sequenceWithinCounterSum.out === 1;
}

template PoolStateV2() {
    signal input bytes[128];

    signal output profileId[2];
    signal output noteRoot;
    signal output nullifierRoot;
    signal output noteCount;
    signal output nullifierCount;
    signal output maximumLiveNotes;
    signal output reserveSats;
    signal output actionSequence;
    signal output liveNoteCount;

    component byteBits[128];
    component parsed = PoolStateV2FromBits();
    for (var byte = 0; byte < 128; byte++) {
        byteBits[byte] = ByteToBits();
        byteBits[byte].in <== bytes[byte];
        parsed.bytes[byte] <== bytes[byte];
        for (var bit = 0; bit < 8; bit++) {
            parsed.byteBits[byte][bit] <== byteBits[byte].bits[bit];
        }
    }

    profileId[0] <== parsed.profileId[0];
    profileId[1] <== parsed.profileId[1];
    noteRoot <== parsed.noteRoot;
    nullifierRoot <== parsed.nullifierRoot;
    noteCount <== parsed.noteCount;
    nullifierCount <== parsed.nullifierCount;
    maximumLiveNotes <== parsed.maximumLiveNotes;
    reserveSats <== parsed.reserveSats;
    actionSequence <== parsed.actionSequence;
    liveNoteCount <== parsed.liveNoteCount;
}
