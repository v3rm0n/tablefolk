import { encodeDataFrame, splitDataFrames } from "./frame";

export const DEFAULT_BUFFERED_AMOUNT_HIGH_WATER_BYTES = 4 * 1024 * 1024;
export const DEFAULT_BUFFERED_AMOUNT_LOW_WATER_BYTES = 2 * 1024 * 1024;
export const DEFAULT_MAX_OUTBOUND_PAYLOAD_BYTES = 8 * 1024 * 1024;

export type FramedDataChannel = Pick<
  RTCDataChannel,
  | "addEventListener"
  | "bufferedAmount"
  | "bufferedAmountLowThreshold"
  | "readyState"
  | "removeEventListener"
  | "send"
>;

export interface FramedSendOptions {
  readonly highWaterBytes?: number;
  readonly lowWaterBytes?: number;
  readonly maxPayloadBytes?: number;
}

const channelQueues = new WeakMap<object, Promise<void>>();

export function sendFramedPayload(
  channel: FramedDataChannel,
  payload: Uint8Array,
  id: number,
  options: FramedSendOptions = {},
): Promise<void> {
  requireBytes(payload);
  const payloadSnapshot = payload.slice();
  const optionsSnapshot: FramedSendOptions = { ...options };
  const previous = channelQueues.get(channel);
  const run =
    previous === undefined
      ? sendFramedPayloadNow(channel, payloadSnapshot, id, optionsSnapshot)
      : previous
          .catch(() => undefined)
          .then(() => sendFramedPayloadNow(channel, payloadSnapshot, id, optionsSnapshot));
  channelQueues.set(channel, run);
  return run.finally(() => {
    if (channelQueues.get(channel) === run) {
      channelQueues.delete(channel);
    }
  });
}

async function sendFramedPayloadNow(
  channel: FramedDataChannel,
  payload: Uint8Array,
  id: number,
  options: FramedSendOptions,
): Promise<void> {
  const highWaterBytes = nonNegativeInteger(
    options.highWaterBytes ?? DEFAULT_BUFFERED_AMOUNT_HIGH_WATER_BYTES,
    "Data-channel high-water mark",
  );
  const lowWaterBytes = nonNegativeInteger(
    options.lowWaterBytes ?? DEFAULT_BUFFERED_AMOUNT_LOW_WATER_BYTES,
    "Data-channel low-water mark",
  );
  const maxPayloadBytes = nonNegativeInteger(
    options.maxPayloadBytes ?? DEFAULT_MAX_OUTBOUND_PAYLOAD_BYTES,
    "Maximum outbound payload bytes",
  );
  if (lowWaterBytes > highWaterBytes) {
    throw new RangeError("Data-channel low-water mark must not exceed its high-water mark");
  }
  if (payload.length > maxPayloadBytes) {
    throw new RangeError(`Outbound payload exceeds the ${maxPayloadBytes}-byte local limit`);
  }
  requireOpen(channel);
  channel.bufferedAmountLowThreshold = lowWaterBytes;

  for (const frame of splitDataFrames(payload, id)) {
    await waitForCapacity(channel, highWaterBytes);
    const encoded = encodeDataFrame(frame);
    const outbound = new Uint8Array(encoded.length);
    outbound.set(encoded);
    channel.send(outbound);
  }
}

async function waitForCapacity(
  channel: FramedDataChannel,
  highWaterBytes: number,
): Promise<void> {
  requireOpen(channel);
  if (channel.bufferedAmount <= highWaterBytes) {
    return;
  }

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error): void => {
      if (settled) {
        return;
      }
      settled = true;
      channel.removeEventListener("bufferedamountlow", onLow);
      channel.removeEventListener("close", onClose);
      channel.removeEventListener("error", onError);
      if (error === undefined) {
        resolve();
      } else {
        reject(error);
      }
    };
    const onLow = (): void => finish();
    const onClose = (): void => finish(new Error("Data channel closed during backpressure"));
    const onError = (): void => finish(new Error("Data channel failed during backpressure"));

    channel.addEventListener("bufferedamountlow", onLow);
    channel.addEventListener("close", onClose);
    channel.addEventListener("error", onError);
    if (channel.readyState !== "open") {
      finish(new Error("Data channel must be open before sending"));
    } else if (channel.bufferedAmount <= highWaterBytes) {
      finish();
    }
  });
}

function requireOpen(channel: FramedDataChannel): void {
  if (channel.readyState !== "open") {
    throw new Error("Data channel must be open before sending");
  }
}

function requireBytes(value: Uint8Array): void {
  if (!(value instanceof Uint8Array) || value.constructor !== Uint8Array) {
    throw new TypeError("Outbound payload must be a Uint8Array");
  }
}

function nonNegativeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}
