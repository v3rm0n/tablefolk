import { parseSaskuCard, type SaskuCardId } from "./cards";
import { SaskuHandError, type SaskuHandAction } from "./hand";
import { SASKU_SUITS, type SaskuSeat, type SaskuSuit } from "./scoring";

export interface SaskuActionInput {
  readonly kind: string;
  readonly data: unknown;
  readonly reveal: readonly number[];
}

/** Actor and revealed cards must come from engine-verified authority and reveals, never from action data. */
export function decodeSaskuAction(
  actor: number,
  input: SaskuActionInput,
  revealed: Readonly<Record<number, SaskuCardId>>,
): SaskuHandAction {
  if (!Number.isSafeInteger(actor) || actor < 0 || actor > 3 || Object.is(actor, -0)) {
    throw new SaskuHandError("Seat must be zero through three");
  }
  if (!isPlainMap(input) || Object.keys(input).sort().join(",") !== "data,kind,reveal" ||
      !Array.isArray(input.reveal) || !isPlainMap(input.data) || !isPlainMap(revealed)) {
    throw new SaskuHandError("Sasku action requires kind, data, reveal, and a revealed-card map");
  }
  const seat = actor as SaskuSeat;
  const data = input.data;
  const dataKeys = Object.keys(data).sort().join(",");
  const revealedKeys = Object.keys(revealed);
  if (input.kind === "play") {
    const pos: unknown = input.reveal[0];
    if (dataKeys !== "" || input.reveal.length !== 1 || typeof pos !== "number" ||
        !Number.isSafeInteger(pos) || pos < 0 || pos > 35 || Object.is(pos, -0) ||
        revealedKeys.length !== 1 || !Object.hasOwn(revealed, String(pos))) {
      throw new SaskuHandError("A Sasku play requires empty data and exactly one matching revealed position from 0 through 35");
    }
    return Object.freeze({ type: "play", seat, card: parseSaskuCard(revealed[pos]).id });
  }
  if (input.reveal.length !== 0 || revealedKeys.length !== 0) {
    throw new SaskuHandError("Sasku auction actions cannot reveal cards");
  }
  if ((input.kind === "pass" || input.kind === "diamonds") && dataKeys === "") {
    return Object.freeze({ type: input.kind, seat });
  }
  if (input.kind === "bid" && dataKeys === "value" && typeof data["value"] === "number" &&
      Number.isSafeInteger(data["value"]) && data["value"] >= 3 && data["value"] <= 9) {
    return Object.freeze({ type: "bid", seat, value: data["value"] });
  }
  if (input.kind === "choose_trump" && dataKeys === "suit" && SASKU_SUITS.includes(data["suit"] as SaskuSuit)) {
    return Object.freeze({ type: "choose_trump", seat, suit: data["suit"] as SaskuSuit });
  }
  throw new SaskuHandError("Invalid Sasku action kind or data");
}

function isPlainMap(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) { return false; }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) { return false; }
  return Reflect.ownKeys(value).every((key) => {
    const property = Object.getOwnPropertyDescriptor(value, key);
    return typeof key === "string" && property !== undefined && property.enumerable && "value" in property;
  });
}
