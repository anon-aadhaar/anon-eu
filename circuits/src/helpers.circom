pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/sha256/sha256.circom";

template ByteArrayToWordArray (l,n,k) {
    signal input in[l];
    signal output out[k];

    component num2bits[l];
    for (var i = 0 ; i < l ; i++){
        num2bits[i] = Num2Bits(8);
        num2bits[i].in <== in[i];
    }
    component bits2num[k];
    for (var i = 0 ; i < k ; i++){
        bits2num[i] = Bits2Num(n);
        for(var j = 0 ; j < n ; j++){
            if(i*n + j >=  8 * l){
                bits2num[i].in[j] <==  0;
            }
            else{
                bits2num[i].in[j] <== num2bits[l - (( i * n + j) \ 8) - 1].out[ ((i * n + j) % 8)];
            }
        }
    }
    for( var i = 0 ; i< k ; i++){
    out[i] <== bits2num[i].out;
    }
}

// Static length sha256 bytes, adapted from zk-email
template Sha256BytesStatic(max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal output out[256];

    // num_bits: num of bits in max_num_bytes
    var num_bits = max_num_bytes * 8;

    // sha: component used to hash all bits from input signal
    component sha = Sha256(num_bits);

    // bytes: list of component used to convert bytes from input signal to bits
    component bytes[max_num_bytes];

    // for each bytes iterate and set bytes from input signal inside the component
    for (var i = 0; i < max_num_bytes; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== in_padded[i];

        // for each bits int bytes iterate again and set the bits from each bytes from reverse order inside sha256 component
        for (var j = 0; j < 8; j++) {
            sha.in[i*8+j] <== bytes[i].out[7-j];
        }
    }

    for (var i = 0; i < 256; i++) {
        out[i] <== sha.out[i];
    }
}