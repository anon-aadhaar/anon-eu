pragma circom 2.1.9;

template ASN1Parser() {
    signal input tbsBytes;
    var index = 0;

    template getLength() {
        signal input tbsBytes;
        signal output length:

        var tempLength <== tbsBytes[index++];
        if (length & 0x80) {
            var lengthOfLength = length & 0x7f;
            var length = 0;
            for (var i = 0; i < lengthOfLength; i++) {
                length <== (length << 8) | tbsBytes[index++];
            }
        }

        length <== tempLength
    }


}

component main { public [tbs] } = ASN1Parser();