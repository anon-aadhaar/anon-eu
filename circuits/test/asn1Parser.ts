function extractPublicKey(bitString: Uint8Array) {
  bitString = bitString.slice(1);
  // Check if the bitString starts with the BIT STRING tag (0x30)
  if (bitString[0] !== 0x30) {
    throw new Error("Invalid BIT STRING tag");
  }

  // Read length bytes
  let length;
  let index = 1;
  if (bitString[1] & 0x80) {
    // Long form length
    const lengthOfLength = bitString[1] & 0x7f;
    length = 0;
    for (let i = 0; i < lengthOfLength; i++) {
      length = (length << 8) | bitString[index + 1 + i];
    }
    index += lengthOfLength + 1;
  } else {
    // Short form length
    length = bitString[1];
    index += 1;
  }

  // Skip padding bits (usually one byte)
  if (bitString[index] !== 0x00) {
    throw new Error("Expected padding bits");
  }
  index += 1;

  // The rest is the actual key
  return bitString.slice(index, index + 256);
}

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

  // Extract the public key bytes from the subjectPublicKeyInfo
  const subjectPublicKey = subjectPublicKeyInfo.children[1].children[0].slice(
    10,
    -5
  );

  return subjectPublicKey;
}

function createSubarray(
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

function readLengthByte(data: Uint8Array, index: number): number[] {
  return [data[index], index + 1];
}

function readMultipleLengthBytes(
  data: Uint8Array,
  index: number,
  lengthOfLength: number
): number[] {
  let length = 0;
  for (let i = 0; i < lengthOfLength; i++) {
    length = (length << 8) | data[index++];
  }
  return [length, index];
}

function getLength(data: Uint8Array, index: number): number[] {
  const [lengthByte, newIndex] = readLengthByte(data, index);
  if (lengthByte & 0x80) {
    const lengthOfLength = lengthByte & 0x7f;
    return readMultipleLengthBytes(data, newIndex, lengthOfLength);
  }
  return [lengthByte, newIndex];
}

interface ParsedTBS {
  tag: number;
  length: number;
  children: any[];
}

function readTag(data: Uint8Array, index: number): number[] {
  return [data[index], index + 1];
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
  const [tag, tagIndex] = readTag(data, index);
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
