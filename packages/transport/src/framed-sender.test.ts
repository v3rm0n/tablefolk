import { describe, expect, it } from "vitest";

import {
  DEFAULT_BUFFERED_AMOUNT_HIGH_WATER_BYTES,
  DEFAULT_BUFFERED_AMOUNT_LOW_WATER_BYTES,
  sendFramedPayload,
  type FramedDataChannel,
} from "./framed-sender";
import {
  decodeDataFrame,
  FrameReassembler,
  MAX_FRAME_PAYLOAD_BYTES,
} from "./frame";

describe("framed data-channel sender", () => {
  it("frames payloads and emits deterministic CBOR in chunk order", async () => {
    const channel = new FakeDataChannel();
    const payload = Uint8Array.from(
      { length: MAX_FRAME_PAYLOAD_BYTES + 1 },
      (_, index) => index & 0xff,
    );

    await sendFramedPayload(channel, payload, 17);

    expect(channel.sent).toHaveLength(2);
    expect(channel.sent.map(decodeDataFrame)).toMatchObject([
      { id: 17, index: 0, count: 2 },
      { id: 17, index: 1, count: 2 },
    ]);
    const reassembler = new FrameReassembler();
    let completed: Uint8Array | undefined;
    for (const encoded of channel.sent) {
      const result = reassembler.acceptEncoded(encoded);
      if (result.status === "complete") {
        completed = result.payload;
      }
    }
    expect(completed).toEqual(payload);
  });

  it("pauses above the 4 MiB default and resumes on bufferedamountlow", async () => {
    const channel = new FakeDataChannel();
    channel.bufferedAmount = DEFAULT_BUFFERED_AMOUNT_HIGH_WATER_BYTES + 1;

    const sending = sendFramedPayload(channel, new Uint8Array([1]), 1);
    await Promise.resolve();
    expect(channel.sent).toEqual([]);
    expect(channel.bufferedAmountLowThreshold).toBe(
      DEFAULT_BUFFERED_AMOUNT_LOW_WATER_BYTES,
    );

    channel.drain(DEFAULT_BUFFERED_AMOUNT_LOW_WATER_BYTES);
    await sending;
    expect(channel.sent).toHaveLength(1);
  });

  it("handles the listener-registration race without waiting forever", async () => {
    const channel = new FakeDataChannel();
    channel.bufferedAmount = 11;
    channel.afterFirstListener = () => {
      channel.bufferedAmount = 10;
    };

    await sendFramedPayload(channel, new Uint8Array([1]), 1, {
      highWaterBytes: 10,
      lowWaterBytes: 5,
    });
    expect(channel.sent).toHaveLength(1);
  });

  it("rejects closure while paused and invalid local limits", async () => {
    const channel = new FakeDataChannel();
    channel.bufferedAmount = 2;
    const sending = sendFramedPayload(channel, new Uint8Array([1]), 1, {
      highWaterBytes: 1,
      lowWaterBytes: 0,
    });
    channel.close();
    await expect(sending).rejects.toThrow(/closed during backpressure/);

    await expect(
      sendFramedPayload(new FakeDataChannel(), new Uint8Array(2), 1, {
        maxPayloadBytes: 1,
      }),
    ).rejects.toThrow(/local limit/);
    await expect(
      sendFramedPayload(new FakeDataChannel(), new Uint8Array(), 1, {
        highWaterBytes: 1,
        lowWaterBytes: 2,
      }),
    ).rejects.toThrow(/must not exceed/);
  });

  it("serializes concurrent sends so later payloads cannot bypass backpressure", async () => {
    const channel = new FakeDataChannel();
    const secondPayload = new Uint8Array([2]);
    const first = sendFramedPayload(channel, new Uint8Array([1]), 1, {
      highWaterBytes: 0,
      lowWaterBytes: 0,
    });
    const second = sendFramedPayload(channel, secondPayload, 2, {
      highWaterBytes: 0,
      lowWaterBytes: 0,
    });
    secondPayload[0] = 0xff;

    await first;
    await Promise.resolve();
    expect(channel.sent).toHaveLength(1);
    channel.drain(0);
    await second;

    expect(channel.sent.map(decodeDataFrame)).toMatchObject([
      { id: 1, bytes: new Uint8Array([1]) },
      { id: 2, bytes: new Uint8Array([2]) },
    ]);
  });
});

class FakeDataChannel extends EventTarget {
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  readyState: RTCDataChannelState = "open";
  readonly sent: Uint8Array[] = [];
  afterFirstListener: (() => void) | undefined;
  #listenerAdded = false;

  override addEventListener(
    type: string,
    callback: EventListenerOrEventListenerObject | null,
    options?: AddEventListenerOptions | boolean,
  ): void {
    super.addEventListener(type, callback, options);
    if (!this.#listenerAdded) {
      this.#listenerAdded = true;
      this.afterFirstListener?.();
    }
  }

  send(data: ArrayBuffer | ArrayBufferView | Blob | string): void {
    if (!(data instanceof Uint8Array)) {
      throw new TypeError("Fake channel only accepts Uint8Array payloads");
    }
    const snapshot = data.slice();
    this.sent.push(snapshot);
    this.bufferedAmount += snapshot.length;
  }

  drain(bufferedAmount: number): void {
    this.bufferedAmount = bufferedAmount;
    this.dispatchEvent(new Event("bufferedamountlow"));
  }

  close(): void {
    this.readyState = "closed";
    this.dispatchEvent(new Event("close"));
  }
}

const _typeCompatibility: FramedDataChannel = new FakeDataChannel() as FramedDataChannel;
void _typeCompatibility;
