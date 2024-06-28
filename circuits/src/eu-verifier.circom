pragma circom 2.1.9;

include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "circomlib/circuits/bitify.circom";
include "./helpers.circom";

template EUVerifier(sod_n, sod_k, csca_n, csca_k, sodMaxDataLength, tbsMaxDataLength) {
    // Signature of the document signer certificate
    signal input DSSignature[csca_k];
    // Country Signing public key
    signal input CSCApubKey[csca_k];
    // To-be-signed data signed by CSCApubKey
    signal input tbsCertificateBytesPadded[tbsMaxDataLength];
    signal input tbsCertificateBytesPaddedLength;
    // Document data signed by the DS public key
    signal input SODSignedDataPadded[sodMaxDataLength];
    signal input SODSignedDataPaddedLength;
    // SOD signature
    signal input SODSignature[sod_k];
    // Start index of the DS public key in the TBS data
    signal input pkStartIndex;
    signal input mrz[95];
    signal input eContentInfoBytesPadded[512];
    signal input eContentInfoBytesPaddedLength;

    // Hash the TBS certificate bytes and verify RSA signature
    signal tbsShaHash[256] <== Sha256Bytes(tbsMaxDataLength)(tbsCertificateBytesPadded, tbsCertificateBytesPaddedLength);

    component rsa = RSAVerifier65537(csca_n, csca_k);
    var rsaMsgLength = (256 + csca_n) \ csca_n;
    component rsaBaseMsg[rsaMsgLength];
    for (var i = 0; i < rsaMsgLength; i++) {
      rsaBaseMsg[i] = Bits2Num(csca_n);
    }
    for (var i = 0; i < 256; i++) {
      rsaBaseMsg[i \ csca_n].in[i % csca_n] <== tbsShaHash[255 - i];
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
    signal dsPublicKeyBytes[256] <== SelectSubArray(tbsMaxDataLength, 256)(tbsCertificateBytesPadded, pkStartIndex, 256);

    // Turn modulus into words array
    signal dsPublicKey[sod_k] <== ByteArrayToWordArray(256, sod_n, sod_k)(dsPublicKeyBytes);

    // Verify the signature of the document
    // Hash SOD content
    signal sodSha[256] <== Sha256Bytes(sodMaxDataLength)(SODSignedDataPadded, SODSignedDataPaddedLength);

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

  // Verify the presence of the mrz in the signed data
  signal mrzShaHash[256] <== Sha256BytesStatic(95)(mrz);

  component mrzShaHashBytes[32];
  for (var i = 0; i < 32; i++) {
      mrzShaHashBytes[i] = Bits2Num(8);
      for (var j = 0; j < 8; j++) {
        mrzShaHashBytes[i].in[7 - j] <== mrzShaHash[i * 8 + j];
      }
  }

  for (var i = 0; i < 32; i++) {
      eContentInfoBytesPadded[31 + i] === mrzShaHashBytes[i].out;
  }

  // Verify the presence of the eContent hash in the signed data
  signal eContentHash[256] <== Sha256Bytes(512)(eContentInfoBytesPadded, eContentInfoBytesPaddedLength);

  component eContentHashBytes[32];
  for (var i = 0; i < 32; i++) {
      eContentHashBytes[i] = Bits2Num(8);
      for (var j = 0; j < 8; j++) {
        eContentHashBytes[i].in[7 - j] <== eContentHash[i * 8 + j];
      }
  }

  var startIndex = 152 - 32; 
  for (var i = 0; i < 32; i++) {
    SODSignedDataPadded[startIndex + i] === eContentHashBytes[i].out;
  }
}

component main { public [CSCApubKey] } = EUVerifier(121, 17, 121, 34, 512, 512 * 2);