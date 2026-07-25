pragma circom 2.0.0;

template TwoPublic() {
    signal input in0;
    signal input in1;
    signal input witness;
    witness === in0 * in1;
}

component main {public [in0, in1]} = TwoPublic();
