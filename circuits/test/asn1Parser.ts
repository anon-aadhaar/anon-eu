// function extractPublicKey(bitString: Uint8Array) {
//   bitString = bitString.slice(1);
//   // Check if the bitString starts with the BIT STRING tag (0x30)
//   if (bitString[0] !== 0x30) {
//     throw new Error("Invalid BIT STRING tag");
//   }

//   // Read length bytes
//   let length;
//   let index = 1;
//   if (bitString[1] & 0x80) {
//     // Long form length
//     const lengthOfLength = bitString[1] & 0x7f;
//     length = 0;
//     for (let i = 0; i < lengthOfLength; i++) {
//       length = (length << 8) | bitString[index + 1 + i];
//     }
//     index += lengthOfLength + 1;
//   } else {
//     // Short form length
//     length = bitString[1];
//     index += 1;
//   }

//   // Skip padding bits (usually one byte)
//   if (bitString[index] !== 0x00) {
//     throw new Error("Expected padding bits");
//   }
//   index += 1;

//   // The rest is the actual key
//   return bitString.slice(index, index + 256);
// }

export function extractPublicKeyFromTBS(tbs: ParsedTBS) {
  // Debugging: Print the structure of the parsed TBS
  // console.log("Parsed TBS Structure:");
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

  //   console.log("Subject public key: ", subjectPublicKeyInfo);
  //   console.log(
  //     "Subject public key first child: ",
  //     subjectPublicKeyInfo.children[1]
  //   );
  //   console.log(
  //     "Subject public key second child: ",
  //     subjectPublicKeyInfo.children[1].children[0]
  //   );

  // Extract the public key bytes from the subjectPublicKeyInfo
  const subjectPublicKey = subjectPublicKeyInfo.children[1].children[0].slice(
    10,
    -5
  );

  return subjectPublicKey;
}

export function getPublicKeyIndexFromTBS(data: Uint8Array): number {
  function parseASN1DataWithCallback(
    data: Uint8Array,
    index: number,
    callback: (index: number) => void
  ): any[] {
    const tag = data[index];
    const tagIndex = index + 1;
    let [length, lengthIndex] = getLength(data, tagIndex);
    const end = lengthIndex + length;

    const parsed: ParsedTBS = { tag, length, children: [] };
    let childIndex = 0;

    if (tag & 0x20) {
      // Constructed
      while (lengthIndex < end) {
        const [parsedChild, newIndex] = parseASN1DataWithCallback(
          data,
          lengthIndex,
          callback
        );
        if (childIndex === 6) {
          // We are at the subjectPublicKeyInfo
          const subjectPublicKeyInfo = parsedChild.children;
          if (subjectPublicKeyInfo && subjectPublicKeyInfo.length > 1) {
            const subjectPublicKey = subjectPublicKeyInfo[1].children;
            console.log("subjectPublicKey from extractor: ", subjectPublicKey);
            if (subjectPublicKey && subjectPublicKey.length > 0) {
              callback(lengthIndex); // Capture the index of the BIT STRING
            }
          }
          return [parsedChild, end];
        }
        parsed.children[childIndex++] = parsedChild;
        lengthIndex = newIndex;
      }
    } else {
      // Primitive
      const [value, newIndex] = readPrimitive(data, lengthIndex, length);
      parsed.children[childIndex] = value;
      return [parsed, newIndex];
    }
    return [parsed, end];
  }

  let publicKeyIndex = -1;
  parseASN1DataWithCallback(data, 0, (index) => {
    publicKeyIndex = index + 1; // +1 to move past the BIT STRING tag
  });

  return publicKeyIndex;
}

export function createSubarray(
  data: Uint8Array,
  start: number,
  end: number
): Uint8Array {
  const result = new Uint8Array(end - start);
  for (let i = start; i < end; i++) {
    result[i - start] = data[i];
  }
  return result;
}

function addChild(children: any[], index: number, child: any): number {
  children[index] = child;
  return index + 1;
}

// function readMultipleLengthBytes(
//   data: Uint8Array,
//   index: number,
//   lengthOfLength: number
// ): number[] {
//   let length = 0;
//   for (let i = 0; i < lengthOfLength; i++) {
//     length = (length << 8) | data[index++];
//   }
//   return [length, index];
// }

// function getLength(data: Uint8Array, index: number): number[] {
//   const lengthByte = data[index];
//   const newIndex = index + 1;

//   if (lengthByte & 0x80) {
//     const lengthOfLength = lengthByte & 0x7f;
//     return readMultipleLengthBytes(data, newIndex, lengthOfLength);
//   }
//   return [lengthByte, newIndex];
// }

// function getLength(data: Uint8Array, index: number): number[] {
//   const lengthByte = data[index];
//   const newIndex = index + 1;

//   if (lengthByte & 0x80) {
//     const lengthOfLength = lengthByte & 0x7f;
//     let length = 0;
//     for (let i = 0; i < lengthOfLength; i++) {
//       length = (length << 8) | data[newIndex + i];
//     }
//     return [length, newIndex + lengthOfLength];
//   }
//   return [lengthByte, newIndex];
// }

function getLength(data: Uint8Array, index: number): [number, number] {
  const lengthByte = data[index];
  if (lengthByte & 0x80) {
    const lengthOfLength = lengthByte & 0x7f;
    let length = 0;
    for (let i = 0; i < lengthOfLength; i++) {
      length = (length << 8) | data[index + 1 + i];
    }
    return [length, index + 1 + lengthOfLength];
  }
  return [lengthByte, index + 1];
}

interface ParsedTBS {
  tag: number;
  length: number;
  children: any[];
}

function readPrimitive(data: Uint8Array, index: number, length: number): any[] {
  const value = createSubarray(data, index, index + length);
  return [value, index + length];
}

function parseConstructed(
  data: Uint8Array,
  index: number,
  end: number,
  children: any[],
  childIndex: number
): number[] {
  while (index < end) {
    const [parsed, newIndex] = parseASN1Data(data, index);
    childIndex = addChild(children, childIndex, parsed);
    index = newIndex;
  }
  return [childIndex, index];
}

export function parseASN1Data(data: Uint8Array, index: number): any[] {
  const tag = data[index];
  const tagIndex = index + 1;
  const [length, lengthIndex] = getLength(data, tagIndex);
  const end = lengthIndex + length;

  const parsed: ParsedTBS = { tag, length, children: [] };
  let childIndex = 0;

  if (tag & 0x20) {
    const [newChildIndex, newIndex] = parseConstructed(
      data,
      lengthIndex,
      end,
      parsed.children,
      childIndex
    );
    return [parsed, newIndex];
  } else {
    const [value, newIndex] = readPrimitive(data, lengthIndex, length);
    parsed.children[childIndex] = value;
    return [parsed, newIndex];
  }
}

export function parseASN1(data: Uint8Array): ParsedTBS {
  const [parsed] = parseASN1Data(data, 0);
  return parsed;
}

export function findPublicKeyIndex(data: Uint8Array, index: number): number {
  // Skip over the outer SEQUENCE tag and length
  const [tbsLength, tbsLengthIndex] = getLength(data, index + 1);
  let currentIndex = tbsLengthIndex;
  let childCount = 0;

  // Iterate through the children of the TBS structure
  while (currentIndex < tbsLengthIndex + tbsLength) {
    const childTag = data[currentIndex];
    const [childLength, childLengthIndex] = getLength(data, currentIndex + 1);
    const childEnd = childLengthIndex + childLength;

    // Check for the 7th child (subjectPublicKeyInfo)
    if (childCount === 6) {
      let spkiIndex = childLengthIndex;
      let spkiChildCount = 0;

      // Iterate through the children of subjectPublicKeyInfo
      while (spkiIndex < childEnd) {
        const spkiTag = data[spkiIndex];
        const [spkiLength, spkiLengthIndex] = getLength(data, spkiIndex + 1);
        const spkiEnd = spkiLengthIndex + spkiLength;

        // Check for the 2nd child (BIT STRING)
        if (spkiChildCount === 1) {
          // Skip BIT STRING tag, length, and unused bits byte
          const bitStringTagIndex = spkiLengthIndex;
          const [bitStringLength, bitStringLengthIndex] = getLength(
            data,
            bitStringTagIndex + 1
          );
          const unusedBitsIndex = bitStringLengthIndex;
          const publicKeyStartIndex = unusedBitsIndex + 1; // Skip the unused bits byte

          return publicKeyStartIndex;
        }

        spkiIndex = spkiEnd;
        spkiChildCount++;
      }
    }

    currentIndex = childEnd;
    childCount++;
  }

  throw new Error("Public key not found in TBS data.");
}
