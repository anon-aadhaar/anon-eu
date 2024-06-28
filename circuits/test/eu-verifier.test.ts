/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require("circom_tester/wasm/tester");

import path from "path";
import { sha256Pad } from "@zk-email/helpers/dist/sha-utils";
import {
  bufferToHex,
  Uint8ArrayToCharArray,
} from "@zk-email/helpers/dist/binary-format";
import crypto, { subtle } from "crypto";
import assert from "assert";
import {
  findSubarrayIndices,
  getPublicKey,
  getPublicKeyFromSignedData,
  parseSOD,
  splitToWords,
} from "./util";
import { Certificate } from "pkijs";
import { isEqualBuffer } from "pvutils";
import { X509Certificate } from "@peculiar/x509";
import { AsnParser, AsnConvert } from "@peculiar/asn1-schema";
import { Certificate as x509Certificate } from "@peculiar/asn1-x509";
import fs from "fs";
import { findPublicKeyIndex } from "./asn1Parser";
// import { bytesToIntChunks, padArrayWithZeros, bigIntsToString } from "./util";
// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();

let EUSODData: string;
let base64Mrz: string;
if (typeof process.env.EU_SOD_DATA === "string") {
  EUSODData = process.env.EU_SOD_DATA;
  base64Mrz = process.env.BASE64_MRZ!;
} else {
  throw Error(
    "You must set .env var EUSODData and base64Mrz when using real data."
  );
}

async function getCSCApublicKey(EUSODData: string) {
  const signedData = await parseSOD(EUSODData);

  await getSignatureData(EUSODData);

  if (!signedData.certificates) throw new Error("Missing cert in signedData");
  const signerCert = signedData.certificates[0];

  // Load the CSCA certificate from file
  // Publicly available at https://ants.gouv.fr/csca
  const importedPem = fs
    .readFileSync(path.join(__dirname, "..", "assets", "french.pem"))
    .toString();
  const cscaCert = new X509Certificate(importedPem);

  const jwk = await crypto.subtle.exportKey(
    "jwk",
    await cscaCert.publicKey.export()
  );
  const CSCApublicKey = BigInt(
    "0x" + bufferToHex(Buffer.from(jwk.n as string, "base64url"))
  );

  // Extract the TBS (to-be-signed) portion of the DS certificate
  const asn1Cert = AsnParser.parse(
    signerCert.toSchema().toBER(),
    x509Certificate
  );

  const tbsCertificate = AsnConvert.serialize(asn1Cert.tbsCertificate);

  const dsCert = new X509Certificate(signerCert.toSchema().toBER());
  // Extract the signature from the DS certificate
  const dsSignature = dsCert.signature;

  return { tbsCertificate, CSCApublicKey, dsSignature };
}

export const getSignatureData = async (
  sodData: string
): Promise<{
  signature: Uint8Array;
  signedData: ArrayBuffer;
  publicKey: CryptoKey;
  eContentInfoBytes: Uint8Array;
}> => {
  const signedData = await parseSOD(sodData);

  if (!signedData.certificates) throw Error("Missing cert in signedData");
  const signerCert = signedData.certificates[0];

  let publicKey: CryptoKey;
  if (signerCert instanceof Certificate) {
    publicKey = await getPublicKeyFromSignedData(
      signerCert.subjectPublicKeyInfo
    );
  } else {
    publicKey = await getPublicKey();
  }

  if (!signedData.signerInfos[0].signedAttrs?.attributes)
    throw Error("Signed data has no attributes object!");

  if (!signedData.encapContentInfo.eContent)
    throw Error("Signed data has no eContent object!");

  const signedDataBuffer = signedData.signerInfos[0].signedAttrs.encodedValue;

  const signatureValue =
    signedData.signerInfos[0].signature.valueBlock.valueHexView;

  const eContentInfoBytes = new Uint8Array(
    signedData.encapContentInfo.eContent.getValue()
  );

  return {
    signature: signatureValue,
    signedData: signedDataBuffer,
    publicKey,
    eContentInfoBytes,
  };
};

// Function to extract the public key from the TBS portion
function extractPublicKeyFromTBS(tbsCertificate: ArrayBuffer) {
  const tbsCertAsn1 = AsnParser.parse(tbsCertificate, Certificate);
  const publicKeyInfo = tbsCertAsn1.subjectPublicKeyInfo;

  const publicKeyBytes = AsnConvert.serialize(publicKeyInfo);
  return publicKeyBytes;
}

describe("Verify EU signature", function () {
  it.only("Verifies that the MRZ hash is part of the signed data", async () => {
    // Parse SOD data to get the signed certificate
    const signedData = await parseSOD(EUSODData);

    if (!signedData.encapContentInfo.eContent)
      throw Error("eContent not found in signed data.");

    const eContentInfoBytes = new Uint8Array(
      Buffer.from(signedData.encapContentInfo.eContent.getValue())
    );

    const mrzHash = await subtle.digest(
      "SHA-256",
      Buffer.from(base64Mrz, "base64")
    );

    const mrzHashBytes = new Uint8Array(mrzHash);

    const { start, end } = findSubarrayIndices(eContentInfoBytes, mrzHashBytes);

    assert.equal(
      isEqualBuffer(mrzHash, eContentInfoBytes.subarray(start, end)),
      true
    );

    if (!signedData.signerInfos[0].signedAttrs)
      throw Error("signedAttrs not found in signed data.");

    const signedDataBytes = new Uint8Array(
      Buffer.from(signedData.signerInfos[0].signedAttrs.encodedValue)
    );

    const eContentHash = await subtle.digest("SHA-256", eContentInfoBytes);
    const eContentHashBytes = new Uint8Array(eContentHash);

    assert.equal(
      isEqualBuffer(eContentHashBytes, signedDataBytes.slice(-32)),
      true
    );
  });

  it("Extract and verify public key from DS certificate", async () => {
    // Parse SOD data to get the signed certificate
    const signedData = await parseSOD(EUSODData);

    if (!signedData.certificates) throw new Error("Missing cert in signedData");
    const signerCert = signedData.certificates[0];

    // Create an X509Certificate instance for the DS certificate
    const dsCert = new X509Certificate(signerCert.toSchema().toBER());

    // Load the CSCA certificate from file
    // Publicly available at https://ants.gouv.fr/csca
    const importedPem = fs
      .readFileSync(path.join(__dirname, "..", "assets", "french.pem"))
      .toString();
    const cscaCert = new X509Certificate(importedPem);

    // Extract the signature from the DS certificate
    const dsSignature = dsCert.signature;
    // console.log("DS Signature:", dsSignature);

    // Extract the TBS (to-be-signed) portion of the DS certificate
    const asn1Cert = AsnParser.parse(dsCert.rawData, x509Certificate);
    const tbsCertificate = AsnConvert.serialize(asn1Cert.tbsCertificate);

    const CSCAPublicKey = await cscaCert.publicKey.export();

    const isSignatureValid = await subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      CSCAPublicKey,
      dsSignature,
      tbsCertificate
    );

    if (isSignatureValid) {
      console.log(
        "The DS certificate's signature is valid using the CSCA public key."
      );

      // The public key from the DS certificate is verified and can be trusted
      //   console.log("Verified Public Key from DS Certificate:", dsPublicKey);
    } else {
      console.log("The DS certificate's signature verification failed.");
    }
  });

  it("Verify SOD signature with subtle", async () => {
    const signedData = await parseSOD(EUSODData);

    if (!signedData.certificates) throw Error("Missing cert in signedData");
    const signerCert = signedData.certificates[0];

    let publicKey: CryptoKey;
    if (signerCert instanceof Certificate) {
      // Extracting the public key stored in the DS ceritificate of the SOD data group
      publicKey = await getPublicKeyFromSignedData(
        signerCert.subjectPublicKeyInfo
      );
    } else {
      publicKey = await getPublicKey();
    }

    if (!signedData.signerInfos[0].signedAttrs?.attributes) return;

    let messageDigestValue: any;
    for (const attribute of signedData.signerInfos[0].signedAttrs?.attributes) {
      if (attribute.type === "1.2.840.113549.1.9.3") {
        // console.log(attribute);
      }

      if (attribute.type === "1.2.840.113549.1.9.4") {
        messageDigestValue = attribute.values[0].valueBlock.valueHex;
      }
    }

    if (!signedData.encapContentInfo.eContent) return;

    const messageDigest = await subtle.digest(
      "SHA-256",
      new Uint8Array(signedData.encapContentInfo.eContent.getValue())
    );

    // Verify that the signed data correspond to the hash of the eContent
    assert.equal(isEqualBuffer(messageDigest, messageDigestValue), true);

    const signedDataBuffer = signedData.signerInfos[0].signedAttrs.encodedValue;

    const signatureValue =
      signedData.signerInfos[0].signature.valueBlock.valueHexView;

    const isValid = await subtle.verify(
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      publicKey,
      signatureValue,
      signedDataBuffer
    );

    assert.equal(isValid, true);
  });
});

async function prepareTestData() {
  const { signature, signedData, publicKey, eContentInfoBytes } =
    await getSignatureData(EUSODData);

  const { tbsCertificate, CSCApublicKey, dsSignature } = await getCSCApublicKey(
    EUSODData
  );

  const [SODDataPadded, SODDataPaddedLen] = sha256Pad(
    new Uint8Array(signedData),
    512
  );

  const [tbsCertificateBytesPadded, tbsCertificateBytesPaddedLength] =
    sha256Pad(new Uint8Array(tbsCertificate), 512 * 2);

  const index = findPublicKeyIndex(new Uint8Array(tbsCertificate), 0);

  const [eContentInfoBytesPadded, eContentInfoBytesPaddedLength] = sha256Pad(
    new Uint8Array(eContentInfoBytes),
    512
  );

  console.log("Length of signed data: ", new Uint8Array(signedData));
  console.log("Length of inserted signed data: ", SODDataPadded.slice(152));
  console.log("Padded length: ", SODDataPaddedLen);

  const inputs = {
    SODSignedDataPadded: Uint8ArrayToCharArray(SODDataPadded),
    SODSignedDataPaddedLength: SODDataPaddedLen,
    DSSignature: splitToWords(
      BigInt("0x" + bufferToHex(Buffer.from(dsSignature)).toString()),
      BigInt(121),
      BigInt(34)
    ),
    SODSignature: splitToWords(
      BigInt("0x" + bufferToHex(Buffer.from(signature)).toString()),
      BigInt(121),
      BigInt(17)
    ),
    CSCApubKey: splitToWords(CSCApublicKey, BigInt(121), BigInt(34)),
    tbsCertificateBytesPadded: Uint8ArrayToCharArray(tbsCertificateBytesPadded),
    tbsCertificateBytesPaddedLength: tbsCertificateBytesPaddedLength,
    mrz: Uint8ArrayToCharArray(Buffer.from(base64Mrz, "base64")),
    eContentInfoBytesPadded: Uint8ArrayToCharArray(eContentInfoBytesPadded),
    eContentInfoBytesPaddedLength: eContentInfoBytesPaddedLength,
    pkStartIndex: index + 7,
  };

  return {
    inputs,
  };
}

describe("EUVerifier", function () {
  this.timeout(0);

  let circuit: any;

  this.beforeAll(async () => {
    const pathToCircuit = path.join(__dirname, "../src", "eu-verifier.circom");
    circuit = await circom_tester(pathToCircuit, {
      recompile: true,
      // output: path.join(__dirname, '../build'),
      include: [path.join(__dirname, "../node_modules")],
    });
  });

  it.only("should generate witness for circuit with Sha256RSA signature", async () => {
    const { inputs } = await prepareTestData();

    await circuit.calculateWitness(inputs);
  });
});
