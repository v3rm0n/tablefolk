import {
  bytesEqual,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeCanonical,
  encodeCanonical,
  type CborValue,
} from "@p2pcards/encoding";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type EnvelopeMessageType,
  type GameId,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";

import { MAX_AUTHORED_HISTORY_PAGE_BYTES } from "./authored-history";

export interface EnvelopeContent {
  readonly round: number;
  readonly phase: string;
  readonly type: EnvelopeMessageType;
  readonly body: CborValue;
}

export interface AuthoredEnvelopeStore {
  /** Read only the durable head for this scope, without allocating a sequence or appending. */
  readAuthoredHead?(gameId: GameId, sender: IdentityPublicKey): Promise<EnvelopeArtifact | null>;
  /**
   * Atomically reads the durable chain head, invokes `create` exactly once, and
   * appends its result. Resolve only after the append transaction commits.
   */
  appendNext(
    gameId: GameId,
    sender: IdentityPublicKey,
    create: (head: EnvelopeArtifact | null) => EnvelopeArtifact,
  ): Promise<void>;
}

export class AuthoredEnvelopeStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "AuthoredEnvelopeStoreError";
  }
}

const ZERO_HASH = parseHash256(new Uint8Array(32));
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "length")!.get!;
const typedArrayByteLength = Object.getOwnPropertyDescriptor(typedArrayPrototype, "byteLength")!.get!;

export class PersistentEnvelopeAuthor {
  readonly #gameId: GameId;
  readonly #secretKey: Ed25519SecretKey;
  readonly #sender: IdentityPublicKey;
  readonly #store: AuthoredEnvelopeStore;
  #pending: Promise<void> = Promise.resolve();

  constructor(gameId: GameId, secretKey: Ed25519SecretKey, store: AuthoredEnvelopeStore) {
    if (typeof store !== "object" || store === null || typeof store.appendNext !== "function") {
      throw new TypeError("Authored envelope store must implement appendNext");
    }

    this.#gameId = parseGameId(gameId);
    this.#secretKey = importEd25519SecretKey(secretKey);
    this.#sender = parseIdentityPublicKey(deriveEd25519PublicKey(this.#secretKey));
    this.#store = store;
  }

  get gameId(): GameId {
    return parseGameId(this.#gameId);
  }

  get sender(): IdentityPublicKey {
    return parseIdentityPublicKey(this.#sender);
  }

  /** A queued, detached preflight snapshot, not a reservation for a later append. */
  async readHead(): Promise<EnvelopeArtifact | null> {
    const read = this.#store.readAuthoredHead;
    if (typeof read !== "function") {
      throw new AuthoredEnvelopeStoreError("Envelope store does not support readAuthoredHead");
    }
    const operation = this.#pending.then(async () => this.#validateStoredHead(
      await read.call(this.#store, parseGameId(this.#gameId), parseIdentityPublicKey(this.#sender)),
    ));
    this.#pending = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  author(
    content: EnvelopeContent,
    beforeSign?: (head: EnvelopeArtifact | null) => undefined,
  ): Promise<EnvelopeArtifact> {
    let snapshot: EnvelopeContent;
    try {
      if (beforeSign !== undefined && typeof beforeSign !== "function") {
        throw new TypeError("Envelope beforeSign guard must be a function");
      }
      snapshot = snapshotContent(content);
    } catch (cause) {
      return Promise.reject(cause);
    }

    const operation = this.#pending.then(() => this.#authorAndPersist(snapshot, beforeSign));
    this.#pending = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }

  async #authorAndPersist(
    content: EnvelopeContent,
    beforeSign?: (head: EnvelopeArtifact | null) => undefined,
  ): Promise<EnvelopeArtifact> {
    let created: EnvelopeArtifact | null = null;
    let creationAttempted = false;
    let creationOpen = true;
    let callbackFailed = false;
    let callbackError: unknown;
    try {
      await this.#store.appendNext(parseGameId(this.#gameId), parseIdentityPublicKey(this.#sender), (storedHead) => {
        if (!creationOpen || creationAttempted) {
          callbackFailed = true;
          callbackError = new AuthoredEnvelopeStoreError("Envelope author callback is closed or was invoked more than once");
          throw callbackError;
        }
        creationAttempted = true;
        try {
          const head = this.#validateStoredHead(storedHead);
          const seq = head === null ? 0 : nextSequence(head.envelope.seq);
          const unsigned: UnsignedEnvelope = {
            v: 1,
            game: this.#gameId,
            from: this.#sender,
            seq,
            prev: head === null ? parseHash256(ZERO_HASH) : parseHash256(head.hash),
            round: content.round,
            phase: content.phase,
            type: content.type,
            body: content.body,
          };
          if (beforeSign !== undefined) {
            const result: unknown = beforeSign(head === null ? null : decodeAndVerifyEnvelope(head.canonicalBytes));
            if (result !== undefined) {
              // Observe accidental async guard rejections without allowing signing.
              void Promise.resolve(result).catch(() => undefined);
              throw new TypeError("Envelope beforeSign guard must return undefined synchronously");
            }
          }
          const artifact = signEnvelope(unsigned, this.#secretKey);
          created = decodeAndVerifyEnvelope(artifact.canonicalBytes);
          return artifact;
        } catch (cause) {
          callbackFailed = true;
          callbackError = cause;
          throw cause;
        }
      });
    } catch (cause) {
      throw callbackFailed ? callbackError : cause;
    } finally {
      creationOpen = false;
    }

    if (callbackFailed) {
      throw callbackError;
    }
    if (created === null) {
      throw new AuthoredEnvelopeStoreError("Envelope store committed without creating an artifact");
    }
    return created;
  }

  #validateStoredHead(candidate: EnvelopeArtifact | null): EnvelopeArtifact | null {
    if (candidate === null) {
      return null;
    }

    let verified: EnvelopeArtifact;
    try {
      const source = candidate.canonicalBytes;
      if (!(source instanceof Uint8Array) || source.constructor !== Uint8Array) {
        throw new TypeError("Stored head must contain canonical envelope bytes");
      }
      const size = typedArrayLength.call(source) as number;
      if (typedArrayByteLength.call(source) !== size || !Number.isSafeInteger(size) || size < 1 || size > MAX_AUTHORED_HISTORY_PAGE_BYTES) {
        throw new RangeError("Stored head exceeds the byte limit or has an invalid byte view");
      }
      const bytes = new Uint8Array(size);
      bytes.set(source);
      verified = decodeAndVerifyEnvelope(bytes);
    } catch (cause) {
      throw new AuthoredEnvelopeStoreError("Envelope store returned an invalid chain head", {
        cause,
      });
    }
    if (!bytesEqual(verified.envelope.game, this.#gameId)) {
      throw new AuthoredEnvelopeStoreError("Envelope store returned a head for another game");
    }
    if (!bytesEqual(verified.envelope.from, this.#sender)) {
      throw new AuthoredEnvelopeStoreError("Envelope store returned a head for another sender");
    }
    return verified;
  }
}

function snapshotContent(content: EnvelopeContent): EnvelopeContent {
  if (typeof content !== "object" || content === null) {
    throw new TypeError("Envelope content must be an object");
  }
  return Object.freeze({
    round: content.round,
    phase: content.phase,
    type: content.type,
    body: decodeCanonical(encodeCanonical(content.body)),
  });
}

function nextSequence(current: number): number {
  if (!Number.isSafeInteger(current) || current < 0 || current === Number.MAX_SAFE_INTEGER) {
    throw new AuthoredEnvelopeStoreError("Stored envelope sequence cannot be advanced safely");
  }
  return current + 1;
}
