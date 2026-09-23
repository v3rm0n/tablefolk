export type CanonicalCborErrorCode = "MALFORMED" | "NON_CANONICAL" | "UNSUPPORTED_VALUE";

export class CanonicalCborError extends Error {
  readonly code: CanonicalCborErrorCode;

  constructor(code: CanonicalCborErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CanonicalCborError";
    this.code = code;
  }
}
