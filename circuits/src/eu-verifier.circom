pragma circom 2.1.9;

include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "./asn1-parser.circom";

// To do:
// 

template EUVerifier(sod_n, sod_k, csca_n, csca_k, sodMaxDataLength, tbsMaxDataLength) {
    // Signature of the document signer certificate
    signal input DSSignature[csca_k];
    // Country Signing public key
    signal input CSCApubKey[csca_k];
    // To-be-signed data signed by CSCApubKey
    signal input tbsCertificateBytesPadded[tbsMaxDataLength];
    signal input tbsCertificateBytesPaddedLength;
    // Document data signed by the DS public key
    signal input SODSignedDataDataPadded[sodMaxDataLength];
    signal input SODSignedDataDataPaddedLength;
    // SOD signature
    signal input SODSignature[sod_k];
    // Start index of the DS public key in the TBS data
    signal input pkStartIndex;

    // Hash the TBS certificate bytes and verify RSA signature
    component shaHasher = Sha256Bytes(tbsMaxDataLength);
    shaHasher.paddedIn <== tbsCertificateBytesPadded;
    shaHasher.paddedInLength <== tbsCertificateBytesPaddedLength;
    signal sha[256];
    sha <== shaHasher.out;

    component rsa = RSAVerifier65537(csca_n, csca_k);
    var rsaMsgLength = (256 + csca_n) \ csca_n;
    component rsaBaseMsg[rsaMsgLength];
    for (var i = 0; i < rsaMsgLength; i++) {
      rsaBaseMsg[i] = Bits2Num(csca_n);
    }
    for (var i = 0; i < 256; i++) {
      rsaBaseMsg[i \ csca_n].in[i % csca_n] <== sha[255 - i];
    }
    for (var i = 256; i < csca_n * rsaMsgLength; i++) {
      rsaBaseMsg[i \ csca_n].in[i % csca_n] <== 0;
    }

    for (var i = 0; i < rsaMsgLength; i++) {
      rsa.message[i] <== rsaBaseMsg[i].out;
    }
    for (var i = rsaMsgLength; i < csca_k; i++) {
      rsa.message[i] <== 0;
    }

	rsa.modulus <== CSCApubKey;
	rsa.signature <== DSSignature;

    // Extract the public key from the TBS
    component subArraySelector = SelectSubArray(tbsMaxDataLength, 256);
    subArraySelector.in <== tbsCertificateBytesPadded;
    subArraySelector.startIndex <== pkStartIndex;
    subArraySelector.length <== 256;

    // Turn modulus into words array
    component modulusBytesToWords = ByteArrayToWordArray(256, sod_n, sod_k);
    modulusBytesToWords.in <== subArraySelector.out;

    signal dsPublicKey[sod_k] <== modulusBytesToWords.out;

    // Verify the signature of the document
    // Hash SOD content
    component sodShaHasher = Sha256Bytes(sodMaxDataLength);
    sodShaHasher.paddedIn <== SODSignedDataDataPadded;
    sodShaHasher.paddedInLength <== SODSignedDataDataPaddedLength;
    signal sodSha[256];
    sodSha <== sodShaHasher.out;

    // Verify RSA signature of the SOD
    component sodRsa = RSAVerifier65537(sod_n, sod_k);
    var sodRsaMsgLength = (256 + sod_n) \ sod_n;
    component sodRsaBaseMsg[sodRsaMsgLength];
    for (var i = 0; i < sodRsaMsgLength; i++) {
      sodRsaBaseMsg[i] = Bits2Num(sod_n);
    }
    for (var i = 0; i < 256; i++) {
      sodRsaBaseMsg[i \ sod_n].in[i % sod_n] <== sodSha[255 - i];
    }
    for (var i = 256; i < sod_n * sodRsaMsgLength; i++) {
      sodRsaBaseMsg[i \ sod_n].in[i % sod_n] <== 0;
    }

    for (var i = 0; i < sodRsaMsgLength; i++) {
      sodRsa.message[i] <== sodRsaBaseMsg[i].out;
    }
    for (var i = sodRsaMsgLength; i < sod_k; i++) {
      sodRsa.message[i] <== 0;
    }

	sodRsa.modulus <== dsPublicKey;
	sodRsa.signature <== SODSignature;
}

component main { public [CSCApubKey] } = EUVerifier(121, 17, 121, 34, 512, 512 * 2);