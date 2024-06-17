pragma circom 2.1.9;

template EUVerifier() {
    signal input a;
    signal output a_squared;

    a_squared <== a * a;
}

component main { public [a] } = EUVerifier();