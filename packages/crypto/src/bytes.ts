export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  let totalLength = 0;

  for (const part of parts) {
    assertByteArray(part);
    totalLength += part.length;
    if (!Number.isSafeInteger(totalLength)) {
      throw new RangeError("Combined byte length exceeds the safe integer range");
    }
  }

  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }
  return combined;
}

export function asciiToBytes(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length);

  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit > 0x7f) {
      throw new TypeError("ASCII input contains a non-ASCII code unit");
    }
    bytes[index] = codeUnit;
  }

  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  assertByteArray(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new TypeError("Hex input must contain an even number of hexadecimal characters");
  }

  return Uint8Array.from(
    { length: hex.length / 2 },
    (_, index) => Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16),
  );
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  assertByteArray(left);
  assertByteArray(right);

  if (left.length !== right.length) {
    return false;
  }

  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function assertByteArray(value: unknown): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new TypeError("Expected a Uint8Array");
  }
}
