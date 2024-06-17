/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
// const circom_tester = require("circom_tester/wasm/tester");

import path from "path";
import { sha256Pad } from "@zk-email/helpers/dist/sha-utils";
import {
  bigIntToChunkedBytes,
  bufferToHex,
  Uint8ArrayToCharArray,
} from "@zk-email/helpers/dist/binary-format";
import fs from "fs";
import crypto, { subtle } from "crypto";
import assert from "assert";
import {
  getPublicKey,
  getPublicKeyFromSignedData,
  parseSOD,
  splitToWords,
} from "./util";
import pkijs, { Certificate } from "pkijs";
import pvutils, { isEqualBuffer } from "pvutils";
// import { bytesToIntChunks, padArrayWithZeros, bigIntsToString } from "./util";
// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();

let EUSODData: string;
if (typeof process.env.EU_SOD_DATA === "string") {
  EUSODData = process.env.EU_SOD_DATA;
} else {
  throw Error("You must set .env var EU_SOD_DATA when using real data.");
}

// function prepareTestData() {
//   const qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
//   const decodedData = decompressByteArray(qrDataBytes);

//   const signatureBytes = decodedData.slice(
//     decodedData.length - 256,
//     decodedData.length
//   );

//   const signedData = decodedData.slice(0, decodedData.length - 256);

//   const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3);

//   const delimiterIndices: number[] = [];
//   for (let i = 0; i < qrDataPadded.length; i++) {
//     if (qrDataPadded[i] === 255) {
//       delimiterIndices.push(i);
//     }
//     if (delimiterIndices.length === 18) {
//       break;
//     }
//   }

//   const signature = BigInt(
//     "0x" + bufferToHex(Buffer.from(signatureBytes)).toString()
//   );

//   const pkPem = fs.readFileSync(
//     path.join(__dirname, "../assets", getCertificate(testAadhaar))
//   );
//   const pk = crypto.createPublicKey(pkPem);

//   const pubKey = BigInt(
//     "0x" +
//       bufferToHex(
//         Buffer.from(pk.export({ format: "jwk" }).n as string, "base64url")
//       )
//   );

//   const inputs = {
//     qrDataPadded: Uint8ArrayToCharArray(qrDataPadded),
//     qrDataPaddedLength: qrDataPaddedLen,
//     delimiterIndices: delimiterIndices,
//     signature: splitToWords(signature, BigInt(121), BigInt(17)),
//     pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
//     nullifierSeed: 12345678,
//     signalHash: 1001,
//     revealGender: 0,
//     revealAgeAbove18: 0,
//     revealPinCode: 0,
//     revealState: 0,
//   };

//   return {
//     inputs,
//     qrDataPadded,
//     signedData,
//     decodedData,
//     pubKey,
//     qrDataPaddedLen,
//   };
// }

describe("Verify EU signature", function () {
  it.only("Verify SOD signature with subtle", async () => {
    const signedData = await parseSOD(EUSODData);

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

    assert.equal(
      isEqualBuffer(messageDigest, messageDigestValue),
      true,
      "Certificate must be verified successfully"
    );

    const signedDataBuffer = signedData.signerInfos[0].signedAttrs.encodedValue;

    const signatureValue =
      signedData.signerInfos[0].signature.valueBlock.valueHexView;

    const isValid = await subtle.verify(
      { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
      publicKey,
      signatureValue,
      signedDataBuffer
    );

    assert.equal(isValid, true, "Is signature valid?");
  });
});

// describe("EUVerifier", function () {
//   this.timeout(0);

//   let circuit: any;

//   this.beforeAll(async () => {
//     const pathToCircuit = path.join(
//       __dirname,
//       "../src",
//       "aadhaar-verifier.circom"
//     );
//     circuit = await circom_tester(pathToCircuit, {
//       recompile: true,
//       // output: path.join(__dirname, '../build'),
//       include: [
//         path.join(__dirname, "../node_modules"),
//         path.join(__dirname, "../../../node_modules"),
//       ],
//     });
//   });

//   it("should generate witness for circuit with Sha256RSA signature", async () => {
//     const { inputs } = prepareTestData();

//     await circuit.calculateWitness(inputs);
//   });
// });
