pragma circom 2.2.0;

include "babyjub-strict.circom";
include "merkle.circom";
include "../../../node_modules/circomlib/circuits/poseidon.circom";

// Private spend witness. The authenticated record tag is leaf-bound, but the
// ciphertext need not be decrypted again: valid record creation is inductive
// from the empty genesis and every accepted output relation.
template SpendNoteV2() {
    signal input enabled;
    signal input profileId[2];
    signal input instanceId[2];
    signal input preNoteRoot;
    signal input preNoteCount;
    signal input packetNullifier;

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

    signal output inputLeaf;
    signal output derivedNullifier;

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;

    // Eliminate inactive witness freedom. Selected dummies remain valid for
    // all unconditional arithmetic components.
    component inactiveSk = AssertZeroIfDisabled();
    inactiveSk.enabled <== enabled;
    inactiveSk.value <== spendSk;
    component inactiveVx = AssertZeroIfDisabled();
    inactiveVx.enabled <== enabled;
    inactiveVx.value <== spendIncomingViewX;
    component inactiveVy = AssertZeroIfDisabled();
    inactiveVy.enabled <== enabled;
    inactiveVy.value <== spendIncomingViewY;
    component inactiveVqx = AssertZeroIfDisabled();
    inactiveVqx.enabled <== enabled;
    inactiveVqx.value <== spendIncomingViewQX;
    component inactiveVqy = AssertZeroIfDisabled();
    inactiveVqy.enabled <== enabled;
    inactiveVqy.value <== spendIncomingViewQY;
    component inactiveRho = AssertZeroIfDisabled();
    inactiveRho.enabled <== enabled;
    inactiveRho.value <== spendRho;
    component inactiveR = AssertZeroIfDisabled();
    inactiveR.enabled <== enabled;
    inactiveR.value <== spendR;
    component inactiveIndex = AssertZeroIfDisabled();
    inactiveIndex.enabled <== enabled;
    inactiveIndex.value <== spendNoteIndex;
    component inactiveRecordTag = AssertZeroIfDisabled();
    inactiveRecordTag.enabled <== enabled;
    inactiveRecordTag.value <== spendRecordTag;
    component inactiveSiblings[32];
    for (var level = 0; level < 32; level++) {
        inactiveSiblings[level] = AssertZeroIfDisabled();
        inactiveSiblings[level].enabled <== enabled;
        inactiveSiblings[level].value <== spendNoteSiblings[level];
    }

    signal selectedSk;
    signal selectedVx;
    signal selectedVy;
    signal selectedVqx;
    signal selectedVqy;
    signal selectedRho;
    signal selectedR;
    selectedSk <== spendSk + (1 - enabled);
    selectedVx <==
        spendIncomingViewX
        + (1 - enabled)
          * 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    selectedVy <==
        spendIncomingViewY
        + (1 - enabled)
          * 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    selectedVqx <==
        spendIncomingViewQX
        + (1 - enabled)
          * 14983708237372537934307712296172313237814584764465642185306010953083014944823;
    selectedVqy <==
        spendIncomingViewQY
        + (1 - enabled)
          * 2997955667916190954169357132153638145915367433663202014407885436612035056202;
    selectedRho <== spendRho;
    selectedR <== spendR + (1 - enabled);

    component incomingViewSubgroup = BabyJubPrimeSubgroupPointV2();
    incomingViewSubgroup.x <== selectedVx;
    incomingViewSubgroup.y <== selectedVy;
    incomingViewSubgroup.cofactorPreimageX <== selectedVqx;
    incomingViewSubgroup.cofactorPreimageY <== selectedVqy;

    component spendPublic = BabyJubFixedBaseMulV2();
    spendPublic.scalar <== selectedSk;

    component authority = Poseidon(9);
    authority.inputs[0] <==
        0x174c18c76e6b8e7e9035476f0419293d25aabb87220e613924e58345d11914df;
    authority.inputs[1] <== profileId[0];
    authority.inputs[2] <== profileId[1];
    authority.inputs[3] <== instanceId[0];
    authority.inputs[4] <== instanceId[1];
    authority.inputs[5] <== spendPublic.x;
    authority.inputs[6] <== spendPublic.y;
    authority.inputs[7] <== selectedVx;
    authority.inputs[8] <== selectedVy;

    component nonzeroR = AssertNonZero();
    nonzeroR.in <== selectedR;
    component commitment = Poseidon(9);
    commitment.inputs[0] <==
        0x194fd66837e146a0a8dddfcc309eb8bc1a51deb31924e089b8960ae102c7c349;
    commitment.inputs[1] <== profileId[0];
    commitment.inputs[2] <== profileId[1];
    commitment.inputs[3] <== instanceId[0];
    commitment.inputs[4] <== instanceId[1];
    commitment.inputs[5] <== 10000000;
    commitment.inputs[6] <== authority.out;
    commitment.inputs[7] <== selectedRho;
    commitment.inputs[8] <== selectedR;

    component leaf = Poseidon(3);
    leaf.inputs[0] <==
        0x0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a;
    leaf.inputs[1] <== commitment.out;
    leaf.inputs[2] <== spendRecordTag;
    inputLeaf <== leaf.out;

    component nullifier = Poseidon(8);
    nullifier.inputs[0] <==
        0x23358847ffca5391ad471ef321c12099073bff6145a867d14700e8e976377460;
    nullifier.inputs[1] <== profileId[0];
    nullifier.inputs[2] <== profileId[1];
    nullifier.inputs[3] <== instanceId[0];
    nullifier.inputs[4] <== instanceId[1];
    nullifier.inputs[5] <== selectedSk;
    nullifier.inputs[6] <== selectedRho;
    nullifier.inputs[7] <== commitment.out;
    derivedNullifier <== nullifier.out;
    (derivedNullifier - packetNullifier) * enabled === 0;

    component occupiedIndex = LessThan(32);
    occupiedIndex.in[0] <== spendNoteIndex;
    occupiedIndex.in[1] <== preNoteCount;
    occupiedIndex.out * enabled === enabled;

    component membership = NoteMembershipV2();
    membership.enabled <== enabled;
    membership.expectedRoot <== preNoteRoot;
    membership.leaf <== inputLeaf;
    membership.index <== spendNoteIndex;
    for (var level = 0; level < 32; level++) {
        membership.siblings[level] <== spendNoteSiblings[level];
    }
}

template OutputNoteV2FromBits() {
    signal input enabled;
    signal input profileId[2];
    signal input instanceId[2];
    signal input postActionSequence;
    signal input packetOutputLeaf;
    signal input packetEncryptedRecordBits[128][8];

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

    signal output noteCommitment;
    signal output derivedOutputLeaf;

    component enabledBit = AssertBoolean();
    enabledBit.in <== enabled;

    component inactiveWitness[11];
    inactiveWitness[0] = AssertZeroIfDisabled();
    inactiveWitness[0].enabled <== enabled;
    inactiveWitness[0].value <== outputSpendX;
    inactiveWitness[1] = AssertZeroIfDisabled();
    inactiveWitness[1].enabled <== enabled;
    inactiveWitness[1].value <== outputSpendY;
    inactiveWitness[2] = AssertZeroIfDisabled();
    inactiveWitness[2].enabled <== enabled;
    inactiveWitness[2].value <== outputSpendQX;
    inactiveWitness[3] = AssertZeroIfDisabled();
    inactiveWitness[3].enabled <== enabled;
    inactiveWitness[3].value <== outputSpendQY;
    inactiveWitness[4] = AssertZeroIfDisabled();
    inactiveWitness[4].enabled <== enabled;
    inactiveWitness[4].value <== outputIncomingViewX;
    inactiveWitness[5] = AssertZeroIfDisabled();
    inactiveWitness[5].enabled <== enabled;
    inactiveWitness[5].value <== outputIncomingViewY;
    inactiveWitness[6] = AssertZeroIfDisabled();
    inactiveWitness[6].enabled <== enabled;
    inactiveWitness[6].value <== outputIncomingViewQX;
    inactiveWitness[7] = AssertZeroIfDisabled();
    inactiveWitness[7].enabled <== enabled;
    inactiveWitness[7].value <== outputIncomingViewQY;
    inactiveWitness[8] = AssertZeroIfDisabled();
    inactiveWitness[8].enabled <== enabled;
    inactiveWitness[8].value <== outputRhoBlind;
    inactiveWitness[9] = AssertZeroIfDisabled();
    inactiveWitness[9].enabled <== enabled;
    inactiveWitness[9].value <== outputR;
    inactiveWitness[10] = AssertZeroIfDisabled();
    inactiveWitness[10].enabled <== enabled;
    inactiveWitness[10].value <== outputEsk;

    signal selectedSpendX;
    signal selectedSpendY;
    signal selectedSpendQX;
    signal selectedSpendQY;
    signal selectedViewX;
    signal selectedViewY;
    signal selectedViewQX;
    signal selectedViewQY;
    signal selectedRhoBlind;
    signal selectedR;
    signal selectedEsk;

    selectedSpendX <==
        outputSpendX
        + (1 - enabled)
          * 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    selectedSpendY <==
        outputSpendY
        + (1 - enabled)
          * 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    selectedSpendQX <==
        outputSpendQX
        + (1 - enabled)
          * 14983708237372537934307712296172313237814584764465642185306010953083014944823;
    selectedSpendQY <==
        outputSpendQY
        + (1 - enabled)
          * 2997955667916190954169357132153638145915367433663202014407885436612035056202;
    selectedViewX <==
        outputIncomingViewX
        + (1 - enabled)
          * 5299619240641551281634865583518297030282874472190772894086521144482721001553;
    selectedViewY <==
        outputIncomingViewY
        + (1 - enabled)
          * 16950150798460657717958625567821834550301663161624707787222815936182638968203;
    selectedViewQX <==
        outputIncomingViewQX
        + (1 - enabled)
          * 14983708237372537934307712296172313237814584764465642185306010953083014944823;
    selectedViewQY <==
        outputIncomingViewQY
        + (1 - enabled)
          * 2997955667916190954169357132153638145915367433663202014407885436612035056202;
    selectedRhoBlind <== outputRhoBlind + (1 - enabled);
    selectedR <== outputR + (1 - enabled);
    selectedEsk <== outputEsk + (1 - enabled);

    component spendSubgroup = BabyJubPrimeSubgroupPointV2();
    spendSubgroup.x <== selectedSpendX;
    spendSubgroup.y <== selectedSpendY;
    spendSubgroup.cofactorPreimageX <== selectedSpendQX;
    spendSubgroup.cofactorPreimageY <== selectedSpendQY;
    component viewSubgroup = BabyJubPrimeSubgroupPointV2();
    viewSubgroup.x <== selectedViewX;
    viewSubgroup.y <== selectedViewY;
    viewSubgroup.cofactorPreimageX <== selectedViewQX;
    viewSubgroup.cofactorPreimageY <== selectedViewQY;

    component rhoBlindNonzero = AssertNonZero();
    rhoBlindNonzero.in <== selectedRhoBlind;
    component rNonzero = AssertNonZero();
    rNonzero.in <== selectedR;

    component authority = Poseidon(9);
    authority.inputs[0] <==
        0x174c18c76e6b8e7e9035476f0419293d25aabb87220e613924e58345d11914df;
    authority.inputs[1] <== profileId[0];
    authority.inputs[2] <== profileId[1];
    authority.inputs[3] <== instanceId[0];
    authority.inputs[4] <== instanceId[1];
    authority.inputs[5] <== selectedSpendX;
    authority.inputs[6] <== selectedSpendY;
    authority.inputs[7] <== selectedViewX;
    authority.inputs[8] <== selectedViewY;

    component rho = Poseidon(7);
    rho.inputs[0] <==
        0x0d166c9d3f0e891e85bb4a502a6ec7303938d7bfc56f1b6e6e443fa8793f8a82;
    rho.inputs[1] <== profileId[0];
    rho.inputs[2] <== profileId[1];
    rho.inputs[3] <== instanceId[0];
    rho.inputs[4] <== instanceId[1];
    rho.inputs[5] <== postActionSequence;
    rho.inputs[6] <== selectedRhoBlind;

    component commitment = Poseidon(9);
    commitment.inputs[0] <==
        0x194fd66837e146a0a8dddfcc309eb8bc1a51deb31924e089b8960ae102c7c349;
    commitment.inputs[1] <== profileId[0];
    commitment.inputs[2] <== profileId[1];
    commitment.inputs[3] <== instanceId[0];
    commitment.inputs[4] <== instanceId[1];
    commitment.inputs[5] <== 10000000;
    commitment.inputs[6] <== authority.out;
    commitment.inputs[7] <== rho.out;
    commitment.inputs[8] <== selectedR;
    noteCommitment <== commitment.out;

    component ephemeral = BabyJubFixedBaseMulV2();
    ephemeral.scalar <== selectedEsk;
    component shared = BabyJubVariableBaseMulV2();
    shared.scalar <== selectedEsk;
    shared.baseX <== selectedViewX;
    shared.baseY <== selectedViewY;
    component ephemeralOnCurve = BabyCheck();
    ephemeralOnCurve.x <== ephemeral.x;
    ephemeralOnCurve.y <== ephemeral.y;
    component sharedOnCurve = BabyCheck();
    sharedOnCurve.x <== shared.x;
    sharedOnCurve.y <== shared.y;
    component ephemeralNonidentity = AssertNonZero();
    ephemeralNonidentity.in <== ephemeral.x;
    component sharedNonidentity = AssertNonZero();
    sharedNonidentity.in <== shared.x;

    component rhoMask = Poseidon(9);
    rhoMask.inputs[0] <==
        0x0ddef22b3c03788145c0aed1bfba5a211f13466c813c0a5d9ed2e92ab173f966;
    rhoMask.inputs[1] <== profileId[0];
    rhoMask.inputs[2] <== profileId[1];
    rhoMask.inputs[3] <== instanceId[0];
    rhoMask.inputs[4] <== instanceId[1];
    rhoMask.inputs[5] <== shared.x;
    rhoMask.inputs[6] <== shared.y;
    rhoMask.inputs[7] <== ephemeral.x;
    rhoMask.inputs[8] <== ephemeral.y;

    component rMask = Poseidon(9);
    rMask.inputs[0] <==
        0x1af24bc8a85aa4b05369756d4f60843ff6dc26f886999d215ed61e38a4ae2db0;
    rMask.inputs[1] <== profileId[0];
    rMask.inputs[2] <== profileId[1];
    rMask.inputs[3] <== instanceId[0];
    rMask.inputs[4] <== instanceId[1];
    rMask.inputs[5] <== shared.x;
    rMask.inputs[6] <== shared.y;
    rMask.inputs[7] <== ephemeral.x;
    rMask.inputs[8] <== ephemeral.y;

    component encryptedRhoDecoder = ByteBitsBEToFr();
    component encryptedRDecoder = ByteBitsBEToFr();
    component tagDecoder = ByteBitsBEToFr();
    for (var byte = 0; byte < 32; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            encryptedRhoDecoder.byteBits[byte][bit] <==
                packetEncryptedRecordBits[32 + byte][bit];
            encryptedRDecoder.byteBits[byte][bit] <==
                packetEncryptedRecordBits[64 + byte][bit];
            tagDecoder.byteBits[byte][bit] <==
                packetEncryptedRecordBits[96 + byte][bit];
        }
    }
    (encryptedRhoDecoder.out - rho.out - rhoMask.out) * enabled === 0;
    (encryptedRDecoder.out - selectedR - rMask.out) * enabled === 0;

    component tag = Poseidon(12);
    tag.inputs[0] <==
        0x03db9f4bbae24de0b96466001641dc5753651feaa55a8541ededbcaf2bb2da7e;
    tag.inputs[1] <== profileId[0];
    tag.inputs[2] <== profileId[1];
    tag.inputs[3] <== instanceId[0];
    tag.inputs[4] <== instanceId[1];
    tag.inputs[5] <== shared.x;
    tag.inputs[6] <== shared.y;
    tag.inputs[7] <== ephemeral.x;
    tag.inputs[8] <== ephemeral.y;
    tag.inputs[9] <== commitment.out;
    tag.inputs[10] <== encryptedRhoDecoder.out;
    tag.inputs[11] <== encryptedRDecoder.out;
    (tagDecoder.out - tag.out) * enabled === 0;

    component packedEphemeral = PackBabyJubPointV2();
    packedEphemeral.x <== ephemeral.x;
    packedEphemeral.y <== ephemeral.y;
    for (var byte = 0; byte < 32; byte++) {
        for (var bit = 0; bit < 8; bit++) {
            (packetEncryptedRecordBits[byte][bit]
                - packedEphemeral.bits[byte * 8 + bit]) * enabled === 0;
        }
    }

    component leaf = Poseidon(3);
    leaf.inputs[0] <==
        0x0765f493bd374585f9ab5c4a1efe55f4d400a1bc1c876506ef8c7644145f370a;
    leaf.inputs[1] <== commitment.out;
    leaf.inputs[2] <== tag.out;
    derivedOutputLeaf <== leaf.out;
    (derivedOutputLeaf - packetOutputLeaf) * enabled === 0;
}

template OutputNoteV2() {
    signal input enabled;
    signal input profileId[2];
    signal input instanceId[2];
    signal input postActionSequence;
    signal input packetOutputLeaf;
    signal input packetEncryptedRecord[128];

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

    signal output noteCommitment;
    signal output derivedOutputLeaf;

    component relation = OutputNoteV2FromBits();
    relation.enabled <== enabled;
    relation.profileId[0] <== profileId[0];
    relation.profileId[1] <== profileId[1];
    relation.instanceId[0] <== instanceId[0];
    relation.instanceId[1] <== instanceId[1];
    relation.postActionSequence <== postActionSequence;
    relation.packetOutputLeaf <== packetOutputLeaf;
    relation.outputSpendX <== outputSpendX;
    relation.outputSpendY <== outputSpendY;
    relation.outputSpendQX <== outputSpendQX;
    relation.outputSpendQY <== outputSpendQY;
    relation.outputIncomingViewX <== outputIncomingViewX;
    relation.outputIncomingViewY <== outputIncomingViewY;
    relation.outputIncomingViewQX <== outputIncomingViewQX;
    relation.outputIncomingViewQY <== outputIncomingViewQY;
    relation.outputRhoBlind <== outputRhoBlind;
    relation.outputR <== outputR;
    relation.outputEsk <== outputEsk;

    component byteBits[128];
    for (var byte = 0; byte < 128; byte++) {
        byteBits[byte] = ByteToBits();
        byteBits[byte].in <== packetEncryptedRecord[byte];
        for (var bit = 0; bit < 8; bit++) {
            relation.packetEncryptedRecordBits[byte][bit] <==
                byteBits[byte].bits[bit];
        }
    }

    noteCommitment <== relation.noteCommitment;
    derivedOutputLeaf <== relation.derivedOutputLeaf;
}
