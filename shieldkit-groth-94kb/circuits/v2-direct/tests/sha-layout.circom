pragma circom 2.2.0;

include "../packet-digest.circom";

template ShaLayout() {
    signal input publicInput0;
    signal input publicInput1;
    signal input packet[552];

    component digest = PacketDigest552();
    for (var index = 0; index < 552; index++) {
        digest.packet[index] <== packet[index];
    }
    digest.publicInput0 === publicInput0;
    digest.publicInput1 === publicInput1;
}

component main {public [publicInput0, publicInput1]} = ShaLayout();
