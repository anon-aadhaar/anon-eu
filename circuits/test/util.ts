import pkijs, {
  Certificate,
  ContentInfo,
  PublicKeyInfo,
  SignedData,
} from "pkijs";
import fs from "fs";
import path from "path";
import { subtle } from "crypto";
import { stringToArrayBuffer } from "pvutils";
import { fromBER } from "asn1js";

export function splitToWords(
  number: bigint,
  wordsize: bigint,
  numberElement: bigint
) {
  let t = number;
  const words: string[] = [];
  for (let i = BigInt(0); i < numberElement; ++i) {
    const baseTwo = BigInt(2);

    words.push(`${t % BigInt(Math.pow(Number(baseTwo), Number(wordsize)))}`);
    t = BigInt(t / BigInt(Math.pow(Number(BigInt(2)), Number(wordsize))));
  }
  if (!(t == BigInt(0))) {
    throw `Number ${number} does not fit in ${(
      wordsize * numberElement
    ).toString()} bits`;
  }
  return words;
}

export async function parseSOD(sodBase64: string): Promise<pkijs.SignedData> {
  const sodBuffer = Buffer.from(sodBase64, "base64").slice(4);
  const contentInfo = ContentInfo.fromBER(sodBuffer);
  const signedData = new SignedData({ schema: contentInfo.content });

  return signedData;
}

export function pemToDer(pem: string) {
  const pemHeader = "-----BEGIN CERTIFICATE-----";
  const pemFooter = "-----END CERTIFICATE-----";
  const pemContents = pem
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s/g, ""); // Remove newlines and spaces

  const binaryDer = Buffer.from(pemContents, "base64");
  return stringToArrayBuffer(binaryDer.toString("binary"));
}

// Will return the CSCA certificate public key
export async function getPublicKey() {
  const importedPem = fs
    .readFileSync(path.join(__dirname, "..", "assets", "french.pem"))
    .toString();
  const der = pemToDer(importedPem);
  const asn1 = fromBER(der);
  const certificate = new Certificate({ schema: asn1.result });

  const publicKey = await subtle.importKey(
    "spki",
    certificate.subjectPublicKeyInfo.toSchema().toBER(false),
    { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    true,
    ["verify"]
  );

  return publicKey;
}

export async function getPublicKeyFromSignedData(
  publicKeyInfo: PublicKeyInfo
): Promise<CryptoKey> {
  const publicKeyInfoBuffer = publicKeyInfo.toSchema().toBER(false);

  return subtle.importKey(
    "spki",
    publicKeyInfoBuffer,
    { name: "RSASSA-PKCS1-v1_5", hash: { name: "SHA-256" } },
    true,
    ["verify"]
  );
}
