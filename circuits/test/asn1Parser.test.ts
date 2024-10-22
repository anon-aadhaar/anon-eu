import { getPublicKeyFromSignedData, parseSOD } from "./util";
import { AsnParser, AsnConvert } from "@peculiar/asn1-schema";
import { Certificate as x509Certificate } from "@peculiar/asn1-x509";
import { createSubarray, findPublicKeyIndex } from "./asn1Parser";
import { getSignatureData } from "./eu-verifier.test";
import { Certificate } from "pkijs";
import crypto from "crypto";
import assert from "assert";
import { isEqualBuffer } from "pvutils";
// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();

let EUSODData: string;
if (typeof process.env.EU_SOD_DATA === "string") {
  EUSODData = process.env.EU_SOD_DATA;
} else {
  throw Error("You must set .env var EU_SOD_DATA when using real data.");
}

describe("Verify EU signature", function () {
  it("Extract and verify public key from DS certificate", async () => {
    // Parse SOD data to get the signed certificate
    const signedData = await parseSOD(EUSODData);

    await getSignatureData(EUSODData);

    if (!signedData.certificates) throw new Error("Missing cert in signedData");
    const signerCert = signedData.certificates[0];

    let publicKeyFromPKIExtractor: ArrayBuffer;
    if (signerCert instanceof Certificate) {
      const publicKey = await getPublicKeyFromSignedData(
        signerCert.subjectPublicKeyInfo
      );
      const jwk = await crypto.subtle.exportKey("jwk", publicKey);
      publicKeyFromPKIExtractor = Buffer.from(jwk.n as string, "base64url");
    } else {
      throw Error("signerCert is not a Certificate");
    }

    // Extract the TBS (to-be-signed) portion of the DS certificate
    const asn1Cert = AsnParser.parse(
      signerCert.toSchema().toBER(),
      x509Certificate
    );

    const tbsCertificate = AsnConvert.serialize(asn1Cert.tbsCertificate);

    const index = findPublicKeyIndex(new Uint8Array(tbsCertificate), 0);

    const pkFromIndex = createSubarray(
      new Uint8Array(tbsCertificate),
      index + 7,
      index + 256 + 7
    );

    assert.equal(isEqualBuffer(pkFromIndex, publicKeyFromPKIExtractor), true);
  });
});
