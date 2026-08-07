pragma circom 2.2.0;

include "packet-digest.circom";
include "state.circom";
include "notes.circom";

// Complete direct V2 relation. Only the two SHA-256 packet limbs are public.
// The network is a compile-time profile parameter; the first deployable main
// instantiation is Chipnet (2).
template PoolActionV2Direct(expectedNetworkId) {
    signal input publicInput0;
    signal input publicInput1;
    signal input packet[552];

    signal input spendSk;
    signal input spendIncomingViewX;
    signal input spendIncomingViewY;
    signal input spendIncomingViewQX;
    signal input spendIncomingViewQY;
    signal input spendRho;
    signal input spendR;
    signal input spendRecordTag;
    signal input spendNoteIndex;
    signal input spendNoteSiblings[32];

    signal input outputSpendX;
    signal input outputSpendY;
    signal input outputSpendQX;
    signal input outputSpendQY;
    signal input outputIncomingViewX;
    signal input outputIncomingViewY;
    signal input outputIncomingViewQX;
    signal input outputIncomingViewQY;
    signal input outputRhoBlind;
    signal input outputR;
    signal input outputEsk;
    signal input noteAppendSiblings[32];

    signal input nullifierPredecessorType;
    signal input nullifierPredecessorIndex;
    signal input nullifierPredecessorKey;
    signal input nullifierSuccessorIndex;
    signal input nullifierSuccessorKey;
    signal input nullifierPredecessorSiblings[32];
    signal input nullifierAppendSiblings[32];

    component packetDigest = PacketDigest552();
    for (var byte = 0; byte < 552; byte++) {
        packetDigest.packet[byte] <== packet[byte];
    }
    packetDigest.publicInput0 === publicInput0;
    packetDigest.publicInput1 === publicInput1;

    packet[0] === 0x53;
    packet[1] === 0x44;
    packet[2] === 0x41;
    packet[3] === 0x32;
    packet[4] === expectedNetworkId;
    packet[6] === 0;
    packet[7] === 0;

    component depositKind = IsEqual();
    component transferKind = IsEqual();
    component withdrawalKind = IsEqual();
    depositKind.in[0] <== packet[5];
    depositKind.in[1] <== 1;
    transferKind.in[0] <== packet[5];
    transferKind.in[1] <== 2;
    withdrawalKind.in[0] <== packet[5];
    withdrawalKind.in[1] <== 3;

    signal isDeposit;
    signal isTransfer;
    signal isWithdrawal;
    signal outputActive;
    signal spendActive;
    isDeposit <== depositKind.out;
    isTransfer <== transferKind.out;
    isWithdrawal <== withdrawalKind.out;
    isDeposit + isTransfer + isWithdrawal === 1;
    packet[5] === isDeposit + 2 * isTransfer + 3 * isWithdrawal;
    outputActive <== isDeposit + isTransfer;
    spendActive <== isTransfer + isWithdrawal;

    component instanceHigh = ByteBitsBEToU128();
    component instanceLow = ByteBitsBEToU128();
    for (var byte = 0; byte < 16; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            instanceHigh.byteBits[byte][bit] <==
                packetDigest.packetBits[8 + byte][bit];
            instanceLow.byteBits[byte][bit] <==
                packetDigest.packetBits[24 + byte][bit];
        }
    }
    signal instanceId[2];
    instanceId[0] <== instanceHigh.out;
    instanceId[1] <== instanceLow.out;

    component preState = PoolStateV2FromBits();
    component postState = PoolStateV2FromBits();
    for (var byte = 0; byte < 128; byte++) {
        preState.bytes[byte] <== packet[40 + byte];
        postState.bytes[byte] <== packet[168 + byte];
        for (var bit = 0; bit < 8; bit++) {
            preState.byteBits[byte][bit] <==
                packetDigest.packetBits[40 + byte][bit];
            postState.byteBits[byte][bit] <==
                packetDigest.packetBits[168 + byte][bit];
        }
    }
    preState.profileId[0] === postState.profileId[0];
    preState.profileId[1] === postState.profileId[1];
    preState.maximumLiveNotes === postState.maximumLiveNotes;

    component packetNullifier = ByteBitsBEToFr();
    component packetOutputLeaf = ByteBitsBEToFr();
    for (var byte = 0; byte < 32; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            packetNullifier.byteBits[byte][bit] <==
                packetDigest.packetBits[296 + byte][bit];
            packetOutputLeaf.byteBits[byte][bit] <==
                packetDigest.packetBits[328 + byte][bit];
        }
    }
    packetNullifier.out * (1 - spendActive) === 0;
    packetOutputLeaf.out * (1 - outputActive) === 0;
    for (var byte = 0; byte < 128; byte++) {
        packet[360 + byte] * (1 - outputActive) === 0;
    }
    for (var byte = 0; byte < 32; byte++) {
        packet[488 + byte] * (1 - isWithdrawal) === 0;
    }

    postState.noteCount === preState.noteCount + outputActive;
    postState.nullifierCount === preState.nullifierCount + spendActive;
    postState.actionSequence === preState.actionSequence + 1;
    postState.reserveSats ===
        preState.reserveSats
        + isDeposit * 10000000
        - isWithdrawal * 10000000;

    component noteHeadroom = LessThan(32);
    noteHeadroom.in[0] <== preState.noteCount;
    noteHeadroom.in[1] <== 0xffffffff;
    noteHeadroom.out * outputActive === outputActive;
    component nullifierHeadroom = LessThan(32);
    nullifierHeadroom.in[0] <== preState.nullifierCount;
    nullifierHeadroom.in[1] <== 0xfffffffe;
    nullifierHeadroom.out * spendActive === spendActive;
    component depositCapacity = LessThan(32);
    depositCapacity.in[0] <== preState.liveNoteCount;
    depositCapacity.in[1] <== preState.maximumLiveNotes;
    depositCapacity.out * isDeposit === isDeposit;
    component withdrawalLive = LessThan(32);
    withdrawalLive.in[0] <== 0;
    withdrawalLive.in[1] <== preState.liveNoteCount;
    withdrawalLive.out * isWithdrawal === isWithdrawal;

    component outputNote = OutputNoteV2FromBits();
    outputNote.enabled <== outputActive;
    outputNote.profileId[0] <== preState.profileId[0];
    outputNote.profileId[1] <== preState.profileId[1];
    outputNote.instanceId[0] <== instanceId[0];
    outputNote.instanceId[1] <== instanceId[1];
    outputNote.postActionSequence <== postState.actionSequence;
    outputNote.packetOutputLeaf <== packetOutputLeaf.out;
    for (var byte = 0; byte < 128; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            outputNote.packetEncryptedRecordBits[byte][bit] <==
                packetDigest.packetBits[360 + byte][bit];
        }
    }
    outputNote.outputSpendX <== outputSpendX;
    outputNote.outputSpendY <== outputSpendY;
    outputNote.outputSpendQX <== outputSpendQX;
    outputNote.outputSpendQY <== outputSpendQY;
    outputNote.outputIncomingViewX <== outputIncomingViewX;
    outputNote.outputIncomingViewY <== outputIncomingViewY;
    outputNote.outputIncomingViewQX <== outputIncomingViewQX;
    outputNote.outputIncomingViewQY <== outputIncomingViewQY;
    outputNote.outputRhoBlind <== outputRhoBlind;
    outputNote.outputR <== outputR;
    outputNote.outputEsk <== outputEsk;

    component spendNote = SpendNoteV2();
    spendNote.enabled <== spendActive;
    spendNote.profileId[0] <== preState.profileId[0];
    spendNote.profileId[1] <== preState.profileId[1];
    spendNote.instanceId[0] <== instanceId[0];
    spendNote.instanceId[1] <== instanceId[1];
    spendNote.preNoteRoot <== preState.noteRoot;
    spendNote.preNoteCount <== preState.noteCount;
    spendNote.packetNullifier <== packetNullifier.out;
    spendNote.spendSk <== spendSk;
    spendNote.spendIncomingViewX <== spendIncomingViewX;
    spendNote.spendIncomingViewY <== spendIncomingViewY;
    spendNote.spendIncomingViewQX <== spendIncomingViewQX;
    spendNote.spendIncomingViewQY <== spendIncomingViewQY;
    spendNote.spendRho <== spendRho;
    spendNote.spendR <== spendR;
    spendNote.spendRecordTag <== spendRecordTag;
    spendNote.spendNoteIndex <== spendNoteIndex;
    for (var level = 0; level < 32; level++) {
        spendNote.spendNoteSiblings[level] <== spendNoteSiblings[level];
    }

    component noteAppend = NoteAppendV2();
    noteAppend.enabled <== outputActive;
    noteAppend.preRoot <== preState.noteRoot;
    noteAppend.postRoot <== postState.noteRoot;
    noteAppend.outputLeaf <== packetOutputLeaf.out;
    noteAppend.appendIndex <== preState.noteCount;
    component inactiveNoteAppendSiblings[32];
    for (var level = 0; level < 32; level++) {
        noteAppend.siblings[level] <== noteAppendSiblings[level];
        inactiveNoteAppendSiblings[level] = AssertZeroIfDisabled();
        inactiveNoteAppendSiblings[level].enabled <== outputActive;
        inactiveNoteAppendSiblings[level].value <== noteAppendSiblings[level];
    }
    (postState.noteRoot - preState.noteRoot) * (1 - outputActive) === 0;

    signal nullifierAppendIndex;
    nullifierAppendIndex <==
        spendActive * (preState.nullifierCount + 2)
        + (1 - spendActive) * 2;

    component inactiveNullifierFields[5];
    inactiveNullifierFields[0] = AssertZeroIfDisabled();
    inactiveNullifierFields[0].enabled <== spendActive;
    inactiveNullifierFields[0].value <== nullifierPredecessorType;
    inactiveNullifierFields[1] = AssertZeroIfDisabled();
    inactiveNullifierFields[1].enabled <== spendActive;
    inactiveNullifierFields[1].value <== nullifierPredecessorIndex;
    inactiveNullifierFields[2] = AssertZeroIfDisabled();
    inactiveNullifierFields[2].enabled <== spendActive;
    inactiveNullifierFields[2].value <== nullifierPredecessorKey;
    inactiveNullifierFields[3] = AssertZeroIfDisabled();
    inactiveNullifierFields[3].enabled <== spendActive;
    inactiveNullifierFields[3].value <== nullifierSuccessorIndex;
    inactiveNullifierFields[4] = AssertZeroIfDisabled();
    inactiveNullifierFields[4].enabled <== spendActive;
    inactiveNullifierFields[4].value <== nullifierSuccessorKey;
    component inactiveNullifierPredecessorSiblings[32];
    component inactiveNullifierAppendSiblings[32];
    for (var level = 0; level < 32; level++) {
        inactiveNullifierPredecessorSiblings[level] = AssertZeroIfDisabled();
        inactiveNullifierPredecessorSiblings[level].enabled <== spendActive;
        inactiveNullifierPredecessorSiblings[level].value <==
            nullifierPredecessorSiblings[level];
        inactiveNullifierAppendSiblings[level] = AssertZeroIfDisabled();
        inactiveNullifierAppendSiblings[level].enabled <== spendActive;
        inactiveNullifierAppendSiblings[level].value <==
            nullifierAppendSiblings[level];
    }

    component nullifierInsertion = IndexedNullifierInsertionV2();
    nullifierInsertion.enabled <== spendActive;
    nullifierInsertion.preRoot <== preState.nullifierRoot;
    nullifierInsertion.postRoot <== postState.nullifierRoot;
    nullifierInsertion.nullifier <== packetNullifier.out;
    nullifierInsertion.appendIndex <== nullifierAppendIndex;
    nullifierInsertion.predecessorType <== nullifierPredecessorType;
    nullifierInsertion.predecessorIndex <== nullifierPredecessorIndex;
    nullifierInsertion.predecessorKey <== nullifierPredecessorKey;
    nullifierInsertion.predecessorSuccessorIndex <== nullifierSuccessorIndex;
    nullifierInsertion.predecessorSuccessorKey <== nullifierSuccessorKey;
    for (var level = 0; level < 32; level++) {
        nullifierInsertion.predecessorPath[level] <==
            nullifierPredecessorSiblings[level];
        nullifierInsertion.appendPath[level] <==
            nullifierAppendSiblings[level];
    }
    (postState.nullifierRoot - preState.nullifierRoot)
        * (1 - spendActive) === 0;
}
