import {
  bytesEqual,
  importEd25519SecretKey,
  type Ed25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeAndVerifyHello,
  parseDtlsFingerprint,
  parseGameId,
  parseIdentityPublicKey,
  signHello,
  type DtlsFingerprint,
  type GameId,
  type HelloArtifact,
  type IdentityPublicKey,
} from "@p2pcards/protocol";

import {
  DATA_CHANNEL_ID,
  DATA_CHANNEL_LABEL,
} from "./full-mesh";
import {
  decodeDataFrame,
  FrameReassembler,
  MAX_FRAME_ID,
  type FrameReassemblerOptions,
} from "./frame";
import {
  sendFramedPayload,
  type FramedSendOptions,
} from "./framed-sender";

export const HELLO_FRAME_ID = 0;
export const FIRST_APPLICATION_FRAME_ID = 1;
export const DEFAULT_MAX_QUEUED_CHANNEL_MESSAGES = 256;
export const DEFAULT_CHANNEL_AUTHENTICATION_TIMEOUT_MS = 30_000;

export type ChannelAuthenticationErrorCode =
  | "AUTHENTICATION_TIMEOUT"
  | "CHANNEL_CLOSED"
  | "CHANNEL_FAILED"
  | "EXPECTED_HELLO"
  | "FINGERPRINT_MISMATCH"
  | "IDENTITY_MISMATCH"
  | "INVALID_FRAME"
  | "INVALID_HELLO"
  | "MESSAGE_HANDLER_FAILED"
  | "QUEUE_LIMIT"
  | "SEND_FAILED";

export class ChannelAuthenticationError extends Error {
  readonly code: ChannelAuthenticationErrorCode;

  constructor(
    code: ChannelAuthenticationErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "ChannelAuthenticationError";
    this.code = code;
  }
}

export interface AuthenticatedPeerChannelOptions {
  readonly channel: RTCDataChannel;
  readonly gameId: Uint8Array;
  readonly secretKey: Ed25519SecretKey;
  readonly remoteIdentity: Uint8Array;
  readonly localFingerprint: Uint8Array;
  readonly remoteFingerprint: Uint8Array;
  readonly maxQueuedMessages?: number;
  readonly authenticationTimeoutMs?: number;
  readonly reassembler?: FrameReassemblerOptions;
  readonly sender?: FramedSendOptions;
  readonly onAuthenticated?: (remote: IdentityPublicKey) => void;
  readonly onMessage: (payload: Uint8Array) => void;
  readonly onError?: (error: Error) => void;
}

type ChannelLifecycle = "new" | "authenticating" | "authenticated" | "closed";

export class AuthenticatedPeerChannel {
  readonly #channel: RTCDataChannel;
  readonly #gameId: GameId;
  readonly #remoteIdentity: IdentityPublicKey;
  readonly #localFingerprint: DtlsFingerprint;
  readonly #remoteFingerprint: DtlsFingerprint;
  readonly #localHello: HelloArtifact;
  readonly #reassembler: FrameReassembler;
  readonly #senderOptions: FramedSendOptions;
  readonly #maxQueuedMessages: number;
  readonly #authenticationTimeoutMs: number;
  readonly #onAuthenticated: ((remote: IdentityPublicKey) => void) | undefined;
  readonly #onMessage: (payload: Uint8Array) => void;
  readonly #onError: ((error: Error) => void) | undefined;
  #lifecycle: ChannelLifecycle = "new";
  #helloSendStarted = false;
  #helloSent = false;
  #remoteHelloVerified = false;
  #nextFrameId = FIRST_APPLICATION_FRAME_ID;
  #queuedMessages = 0;
  #receiveQueue: Promise<void> = Promise.resolve();
  #authentication: Promise<void> | null = null;
  #resolveAuthentication: (() => void) | null = null;
  #rejectAuthentication: ((error: Error) => void) | null = null;
  #failure: Error | null = null;
  #authenticationTimer: ReturnType<typeof globalThis.setTimeout> | null = null;

  readonly #handleOpen = (): void => {
    void this.#sendHello();
  };

  readonly #handleMessage = (event: MessageEvent<unknown>): void => {
    if (this.#lifecycle === "closed") {
      return;
    }
    if (this.#queuedMessages >= this.#maxQueuedMessages) {
      this.#fail(
        new ChannelAuthenticationError(
          "QUEUE_LIMIT",
          "Queued data-channel message limit exceeded",
        ),
      );
      return;
    }
    let bytes: Uint8Array;
    try {
      bytes = messageBytes(event.data);
    } catch (cause) {
      this.#fail(
        new ChannelAuthenticationError("INVALID_FRAME", "Data-channel frame is not binary", {
          cause,
        }),
      );
      return;
    }
    this.#queuedMessages += 1;
    const run = this.#receiveQueue.then(() => this.#processIncoming(bytes));
    this.#receiveQueue = run.then(
      () => {
        this.#queuedMessages -= 1;
      },
      (cause: unknown) => {
        this.#queuedMessages -= 1;
        this.#fail(asError(cause, "Data-channel receive failed"));
      },
    );
  };

  readonly #handleClose = (): void => {
    this.#fail(
      new ChannelAuthenticationError(
        "CHANNEL_CLOSED",
        "Data channel closed before transport shutdown",
      ),
      false,
    );
  };

  readonly #handleError = (): void => {
    this.#fail(new ChannelAuthenticationError("CHANNEL_FAILED", "Data channel failed"));
  };

  constructor(options: AuthenticatedPeerChannelOptions) {
    if (typeof options !== "object" || options === null) {
      throw new TypeError("Authenticated channel options are required");
    }
    requireProfileChannel(options.channel);
    this.#channel = options.channel;
    this.#gameId = parseGameId(options.gameId);
    this.#remoteIdentity = parseIdentityPublicKey(options.remoteIdentity);
    this.#localFingerprint = parseDtlsFingerprint(options.localFingerprint);
    this.#remoteFingerprint = parseDtlsFingerprint(options.remoteFingerprint);
    const secretKey = importEd25519SecretKey(options.secretKey);
    this.#localHello = signHello(
      this.#gameId,
      this.#localFingerprint,
      this.#remoteFingerprint,
      secretKey,
    );
    this.#maxQueuedMessages = positiveInteger(
      options.maxQueuedMessages ?? DEFAULT_MAX_QUEUED_CHANNEL_MESSAGES,
      "Maximum queued channel messages",
    );
    this.#authenticationTimeoutMs = positiveInteger(
      options.authenticationTimeoutMs ?? DEFAULT_CHANNEL_AUTHENTICATION_TIMEOUT_MS,
      "Channel authentication timeout",
    );
    this.#reassembler = new FrameReassembler({
      ...options.reassembler,
      scheduleExpiry: true,
    });
    this.#senderOptions = Object.freeze({ ...options.sender });
    this.#onAuthenticated = options.onAuthenticated;
    this.#onMessage = options.onMessage;
    this.#onError = options.onError;
    if (typeof this.#onMessage !== "function") {
      throw new TypeError("Authenticated channel message handler must be a function");
    }
  }

  get authenticated(): boolean {
    return this.#lifecycle === "authenticated";
  }

  get failure(): Error | null {
    return this.#failure;
  }

  start(): Promise<void> {
    if (this.#lifecycle === "closed") {
      return Promise.reject(
        this.#failure ??
          new ChannelAuthenticationError("CHANNEL_CLOSED", "Data channel is closed"),
      );
    }
    if (this.#authentication !== null) {
      return this.#authentication;
    }
    this.#lifecycle = "authenticating";
    this.#authentication = new Promise<void>((resolve, reject) => {
      this.#resolveAuthentication = resolve;
      this.#rejectAuthentication = reject;
    });
    this.#channel.binaryType = "arraybuffer";
    this.#channel.addEventListener("open", this.#handleOpen);
    this.#channel.addEventListener("message", this.#handleMessage);
    this.#channel.addEventListener("close", this.#handleClose);
    this.#channel.addEventListener("error", this.#handleError);
    this.#authenticationTimer = globalThis.setTimeout(() => {
      this.#authenticationTimer = null;
      this.#fail(
        new ChannelAuthenticationError(
          "AUTHENTICATION_TIMEOUT",
          "Reciprocal HELLO authentication timed out",
        ),
      );
    }, this.#authenticationTimeoutMs);
    if (this.#channel.readyState === "open") {
      void this.#sendHello();
    } else if (this.#channel.readyState !== "connecting") {
      this.#fail(
        new ChannelAuthenticationError(
          "CHANNEL_CLOSED",
          "Data channel is not open or connecting",
        ),
      );
    }
    return this.#authentication;
  }

  async send(payload: Uint8Array): Promise<void> {
    if (this.#lifecycle !== "authenticated") {
      throw new ChannelAuthenticationError(
        "EXPECTED_HELLO",
        "Application payload cannot be sent before reciprocal HELLO authentication",
      );
    }
    if (this.#nextFrameId > MAX_FRAME_ID) {
      throw new ChannelAuthenticationError("SEND_FAILED", "Data-channel frame IDs are exhausted");
    }
    const id = this.#nextFrameId;
    this.#nextFrameId += 1;
    try {
      await sendFramedPayload(this.#channel, payload, id, this.#senderOptions);
    } catch (cause) {
      const error = new ChannelAuthenticationError(
        "SEND_FAILED",
        "Authenticated data-channel send failed",
        { cause },
      );
      this.#fail(error);
      throw error;
    }
  }

  close(): void {
    if (this.#lifecycle === "closed") {
      return;
    }
    const error = new ChannelAuthenticationError(
      "CHANNEL_CLOSED",
      "Authenticated data channel was closed locally",
    );
    this.#lifecycle = "closed";
    this.#failure = error;
    this.#rejectAuthentication?.(error);
    this.#settleAuthentication();
    this.#cleanup();
    this.#channel.close();
  }

  async whenIdle(): Promise<void> {
    await this.#receiveQueue;
  }

  #processIncoming(encoded: Uint8Array): void {
    if (this.#lifecycle === "closed") {
      return;
    }
    let frame;
    try {
      frame = decodeDataFrame(encoded);
    } catch (cause) {
      throw new ChannelAuthenticationError("INVALID_FRAME", "Data-channel frame is invalid", {
        cause,
      });
    }
    if (!this.#remoteHelloVerified) {
      if (
        frame.id !== HELLO_FRAME_ID ||
        frame.index !== 0 ||
        frame.count !== 1
      ) {
        throw new ChannelAuthenticationError(
          "EXPECTED_HELLO",
          "The first remote frame must be the complete HELLO payload",
        );
      }
      this.#verifyRemoteHello(frame.bytes);
      this.#remoteHelloVerified = true;
      this.#completeAuthentication();
      return;
    }
    if (this.#lifecycle !== "authenticated") {
      throw new ChannelAuthenticationError(
        "EXPECTED_HELLO",
        "Application payload arrived before reciprocal HELLO authentication",
      );
    }
    if (frame.id === HELLO_FRAME_ID) {
      throw new ChannelAuthenticationError(
        "EXPECTED_HELLO",
        "HELLO frame ID cannot be reused for an application payload",
      );
    }
    const result = this.#reassembler.accept(frame);
    if (result.status === "rejected") {
      throw new ChannelAuthenticationError(
        "INVALID_FRAME",
        `Data-channel frame group was rejected: ${result.reason}`,
      );
    }
    if (result.status === "complete") {
      try {
        this.#onMessage(result.payload);
      } catch (cause) {
        throw new ChannelAuthenticationError(
          "MESSAGE_HANDLER_FAILED",
          "Authenticated channel message handler failed",
          { cause },
        );
      }
    }
  }

  #verifyRemoteHello(encoded: Uint8Array): void {
    let remote: HelloArtifact;
    try {
      remote = decodeAndVerifyHello(encoded, this.#gameId);
    } catch (cause) {
      throw new ChannelAuthenticationError("INVALID_HELLO", "Remote HELLO is invalid", {
        cause,
      });
    }
    if (!bytesEqual(remote.hello.pkId, this.#remoteIdentity)) {
      throw new ChannelAuthenticationError(
        "IDENTITY_MISMATCH",
        "Remote HELLO identity does not match the expected roster peer",
      );
    }
    if (
      !bytesEqual(remote.hello.localFingerprint, this.#remoteFingerprint) ||
      !bytesEqual(remote.hello.remoteFingerprint, this.#localFingerprint)
    ) {
      throw new ChannelAuthenticationError(
        "FINGERPRINT_MISMATCH",
        "Remote HELLO does not match the observed reciprocal DTLS fingerprints",
      );
    }
  }

  async #sendHello(): Promise<void> {
    if (this.#helloSendStarted || this.#lifecycle !== "authenticating") {
      return;
    }
    this.#helloSendStarted = true;
    try {
      await sendFramedPayload(
        this.#channel,
        this.#localHello.canonicalBytes,
        HELLO_FRAME_ID,
        this.#senderOptions,
      );
      if (this.#isClosed()) {
        return;
      }
      this.#helloSent = true;
      this.#completeAuthentication();
    } catch (cause) {
      this.#fail(
        new ChannelAuthenticationError("SEND_FAILED", "Failed to send local HELLO", {
          cause,
        }),
      );
    }
  }

  #completeAuthentication(): void {
    if (
      this.#lifecycle !== "authenticating" ||
      !this.#helloSent ||
      !this.#remoteHelloVerified
    ) {
      return;
    }
    this.#lifecycle = "authenticated";
    this.#clearAuthenticationTimer();
    try {
      this.#onAuthenticated?.(parseIdentityPublicKey(this.#remoteIdentity));
    } catch (cause) {
      this.#fail(asError(cause, "Authenticated channel observer failed"));
      return;
    }
    this.#resolveAuthentication?.();
    this.#settleAuthentication();
  }

  #fail(error: Error, closeChannel = true): void {
    if (this.#lifecycle === "closed") {
      return;
    }
    this.#lifecycle = "closed";
    this.#failure = error;
    this.#rejectAuthentication?.(error);
    this.#settleAuthentication();
    this.#cleanup();
    if (closeChannel && this.#channel.readyState !== "closed") {
      this.#channel.close();
    }
    try {
      this.#onError?.(error);
    } catch {
      // Error observers cannot reopen or poison the closed authentication boundary.
    }
  }

  #settleAuthentication(): void {
    this.#resolveAuthentication = null;
    this.#rejectAuthentication = null;
  }

  #isClosed(): boolean {
    return this.#lifecycle === "closed";
  }

  #cleanup(): void {
    this.#clearAuthenticationTimer();
    this.#channel.removeEventListener("open", this.#handleOpen);
    this.#channel.removeEventListener("message", this.#handleMessage);
    this.#channel.removeEventListener("close", this.#handleClose);
    this.#channel.removeEventListener("error", this.#handleError);
    this.#reassembler.clear();
  }

  #clearAuthenticationTimer(): void {
    if (this.#authenticationTimer !== null) {
      globalThis.clearTimeout(this.#authenticationTimer);
      this.#authenticationTimer = null;
    }
  }
}

function requireProfileChannel(channel: RTCDataChannel): void {
  if (
    typeof channel !== "object" ||
    channel === null ||
    channel.label !== DATA_CHANNEL_LABEL ||
    channel.id !== DATA_CHANNEL_ID ||
    !channel.negotiated ||
    !channel.ordered ||
    channel.maxPacketLifeTime !== null ||
    channel.maxRetransmits !== null
  ) {
    throw new TypeError("Authenticated channel must satisfy the reliable data-channel profile");
  }
}

function messageBytes(value: unknown): Uint8Array {
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value.slice(0));
  }
  if (value instanceof Uint8Array && value.constructor === Uint8Array) {
    return value.slice();
  }
  throw new TypeError("Data-channel messages must be ArrayBuffer or Uint8Array values");
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function asError(cause: unknown, fallback: string): Error {
  return cause instanceof Error ? cause : new Error(fallback, { cause });
}
