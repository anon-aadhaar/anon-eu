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
  getPublicKey,
  getPublicKeyFromSignedData,
  parseSOD,
  splitToWords,
} from "./util";
import { Certificate } from "pkijs";
import { isEqualBuffer } from "pvutils";
// import { bytesToIntChunks, padArrayWithZeros, bigIntsToString } from "./util";
// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();

let EUSODData: string;
if (typeof process.env.EU_SOD_DATA === "string") {
  EUSODData = process.env.EU_SOD_DATA;
} else {
  throw Error("You must set .env var EU_SOD_DATA when using real data.");
}

const getSignatureData = async (
  sodData: string
): Promise<{
  signature: Uint8Array;
  signedData: ArrayBuffer;
  publicKey: CryptoKey;
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

  return {
    signature: signatureValue,
    signedData: signedDataBuffer,
    publicKey,
  };
};

describe("Verify EU signature", function () {
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
  const { signature, signedData, publicKey } = await getSignatureData(
    EUSODData
  );

  const [qrDataPadded, qrDataPaddedLen] = sha256Pad(
    new Uint8Array(signedData),
    512
  );

  const sig = BigInt("0x" + bufferToHex(Buffer.from(signature)).toString());

  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  const pubKey = BigInt(
    "0x" + bufferToHex(Buffer.from(jwk.n as string, "base64url"))
  );

  const inputs = {
    SODSignedDataDataPadded: Uint8ArrayToCharArray(qrDataPadded),
    SODSignedDataDataPaddedLength: qrDataPaddedLen,
    signature: splitToWords(sig, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
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

  it("should generate witness for circuit with Sha256RSA signature", async () => {
    const { inputs } = await prepareTestData();

    await circuit.calculateWitness(inputs);
  });
});
