import pkijs, {
  Certificate,
  ContentInfo,
  PublicKeyInfo,
  SignedData,
} from "pkijs";
import fs from "fs";
import path from "path";
import { subtle } from "crypto";
import pvutils from "pvutils";
import asn1js from "asn1js";

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
  return pvutils.stringToArrayBuffer(binaryDer.toString("binary"));
}

export async function getPublicKey() {
  const importedPem = fs
    .readFileSync(path.join(__dirname, "french.pem"))
    .toString();
  const der = pemToDer(importedPem);
  const asn1 = asn1js.fromBER(der);
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
