import { decodeCanonical, encodeCanonical } from "@p2pcards/encoding";

import { decodeHeadsBody, encodeHeadsBody, type HeadsBody } from "./heads";
import { expectExactMap, expectUnsignedInteger } from "./schema";
import {
  decodeSyncRequestBody, decodeSyncResponseBody, encodeSyncRequestBody, encodeSyncResponseBody,
  type SyncRequestBody, type SyncResponseBody,
} from "./sync";

export const CHANNEL_CONTROL_PREFIX = 3;
export const MAX_GAME_ENVELOPE_BYTES = 64 * 1024;
// A certificate may carry two maximum-sized originals plus its own signed fields.
export const MAX_HISTORY_ENVELOPE_BYTES = 2 * MAX_GAME_ENVELOPE_BYTES + 512;
export const MAX_CHANNEL_CONTROL_BYTES = MAX_HISTORY_ENVELOPE_BYTES + 128;

export type ChannelControl =
  | { readonly type: "HEADS"; readonly body: HeadsBody }
  | { readonly type: "SYNC_REQ"; readonly id: number; readonly body: SyncRequestBody }
  | { readonly type: "SYNC_RESP"; readonly id: number; readonly body: SyncResponseBody | null }
  | { readonly type: "ABORT_VOTE"; readonly body: { readonly missing: number; readonly ended: boolean } };

export function encodeChannelControl(control: ChannelControl): Uint8Array {
  const fields = controlFields(control);
  const bytes = encodeCanonical(fields);
  if (bytes.length >= MAX_CHANNEL_CONTROL_BYTES) throw new RangeError("Channel control exceeds size limit");
  const payload = new Uint8Array(bytes.length + 1);
  payload[0] = CHANNEL_CONTROL_PREFIX;
  payload.set(bytes, 1);
  return payload;
}

export function decodeChannelControl(payload: Uint8Array): ChannelControl {
  if (payload[0] !== CHANNEL_CONTROL_PREFIX || payload.length > MAX_CHANNEL_CONTROL_BYTES) {
    throw new Error("Invalid channel control framing");
  }
  const value = decodeCanonical(payload.subarray(1));
  const type = value && typeof value === "object" && "type" in value ? value["type"] : undefined;
  if (type === "HEADS" || type === "ABORT_VOTE") {
    const { body } = expectExactMap(value, ["type", "body"], type);
    return type === "HEADS" ? { type, body: decodeHeadsBody(body) } : { type, body: decodeVote(body) };
  }
  if (type === "SYNC_REQ" || type === "SYNC_RESP") {
    const { id, body } = expectExactMap(value, ["type", "id", "body"], type);
    const requestId = expectUnsignedInteger(id, type + ".id");
    if (type === "SYNC_REQ") return { type, id: requestId, body: decodeRequest(body) };
    return { type, id: requestId, body: body === null ? null : decodeResponse(body) };
  }
  throw new Error("Unknown channel control");
}

function controlFields(control: ChannelControl) {
  const { type, body } = control;
  if ("id" in control) expectUnsignedInteger(control.id, type + ".id");
  switch (type) {
    case "HEADS": return { type, body: encodeHeadsBody(body) };
    case "ABORT_VOTE": return { type, body: decodeVote(body) };
    case "SYNC_REQ": {
      const request = encodeSyncRequestBody(body);
      decodeRequest(request);
      return { type, id: control.id, body: request };
    }
    case "SYNC_RESP": {
      if (body !== null && (body.envelopes.length !== 1 || body.envelopes[0]!.canonicalBytes.length > MAX_HISTORY_ENVELOPE_BYTES)) {
        throw new RangeError("SYNC_RESP must carry one bounded envelope");
      }
      return { type, id: control.id, body: body === null ? null : encodeSyncResponseBody(body) };
    }
  }
}

function decodeRequest(value: Parameters<typeof decodeSyncRequestBody>[0]): SyncRequestBody {
  const request = decodeSyncRequestBody(value);
  if (request.fromSeq !== request.toSeq) throw new RangeError("SYNC_REQ must request one envelope");
  return request;
}

function decodeResponse(value: Parameters<typeof decodeSyncResponseBody>[0]): SyncResponseBody {
  const { envelopes } = expectExactMap(value, ["envelopes"], "SYNC_RESP.body");
  if (!Array.isArray(envelopes) || envelopes.length !== 1) throw new RangeError("SYNC_RESP must carry one envelope");
  const response = decodeSyncResponseBody(value);
  if (response.envelopes[0]!.canonicalBytes.length > MAX_HISTORY_ENVELOPE_BYTES) {
    throw new RangeError("SYNC_RESP envelope exceeds size limit");
  }
  return response;
}

function decodeVote(value: Parameters<typeof expectExactMap>[0]) {
  const { missing, ended } = expectExactMap(value, ["missing", "ended"], "ABORT_VOTE.body");
  const mask = expectUnsignedInteger(missing, "ABORT_VOTE.body.missing", 15);
  if (typeof ended !== "boolean") throw new Error("Invalid abort vote status");
  return { missing: mask, ended };
}
