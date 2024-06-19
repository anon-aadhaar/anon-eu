export type ParsedTBS = { tag: number; length: number; children: any[] };

export function parseASN1(data: Uint8Array) {
  // Helper function to parse ASN.1 DER-encoded data
  let index = 0;

  function getLength() {
    let length = data[index++];
    if (length & 0x80) {
      const lengthOfLength = length & 0x7f;
      length = 0;
      for (let i = 0; i < lengthOfLength; i++) {
        length = (length << 8) | data[index++];
      }
    }
    return length;
  }

  function parse(): ParsedTBS {
    const tag = data[index++];
    const length = getLength();
    const end = index + length;

    const children = [];
    if (tag & 0x20) {
      // Constructed type
      while (index < end) {
        children.push(parse());
      }
    } else {
      // Primitive type
      children.push(data.subarray(index, end));
      index = end;
    }

    return { tag, length, children };
  }

  return parse();
}

function printASN1Structure(node: ParsedTBS, indent = 0) {
  const padding = " ".repeat(indent);
  console.log(`${padding}Tag: ${node.tag}, Length: ${node.length}`);
  node.children.forEach((child, idx) => {
    if (child.tag !== undefined) {
      printASN1Structure(child, indent + 2);
    } else {
      console.log(`${padding}  [Primitive]: ${child}`);
    }
  });
}

export function extractPublicKeyFromTBS(tbs: ParsedTBS) {
  // Debugging: Print the structure of the parsed TBS
  console.log("Parsed TBS Structure:");
  // printASN1Structure(tbs);

  // The TBS certificate structure (simplified)
  // tbsCertificate ::= SEQUENCE {
  //   version         [0]  EXPLICIT Version DEFAULT v1,
  //   serialNumber         CertificateSerialNumber,
  //   signature            AlgorithmIdentifier,
  //   issuer               Name,
  //   validity             Validity,
  //   subject              Name,
  //   subjectPublicKeyInfo SubjectPublicKeyInfo,
  //   ...
  // }
  // SubjectPublicKeyInfo ::= SEQUENCE {
  //   algorithm            AlgorithmIdentifier,
  //   subjectPublicKey     BIT STRING
  // }

  // Ensure the TBS structure has the expected fields
  if (!tbs.children || tbs.children.length < 7) {
    throw new Error(
      `Unexpected TBS structure, # of children = ${tbs.children}`
    );
  }

  // Find the subjectPublicKeyInfo field in the parsed TBS structure
  const subjectPublicKeyInfo = tbs.children[6];

  // Extract the public key bytes from the subjectPublicKeyInfo
  const subjectPublicKey = subjectPublicKeyInfo.children[1].children[0];

  return subjectPublicKey;
}

// // Sample data: Replace with actual TBS ArrayBuffer
// const tbsArrayBuffer = new Uint8Array([
//   0x30, 0x82, 0x03, 0x75, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x10, 0xda,
//   0x0e, 0x7d, 0xd2, 0x9d, 0x9d, 0xb0, 0xe9, 0x31, 0xd9, 0x13, 0xf1, 0x8b, 0xee,
//   0x99, 0xf3, 0x74, 0xc2, 0xcd, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
//   0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x32, 0x31, 0x0b, 0x30, 0x09,
//   0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x46, 0x52, 0x31, 0x0d, 0x30, 0x0b,
//   0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x04, 0x47, 0x6f, 0x75, 0x76, 0x31, 0x14,
//   0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x43, 0x53, 0x43, 0x41,
//   0x2d, 0x46, 0x52, 0x41, 0x4e, 0x43, 0x45, 0x30, 0x1e,
//   // more bytes...
// ]);

// // Parse the TBS
// const parsedTBS = parseASN1(tbsArrayBuffer);

// // Extract the public key
// const publicKey = extractPublicKeyFromTBS(parsedTBS);

// console.log("Extracted Public Key:", publicKey);
