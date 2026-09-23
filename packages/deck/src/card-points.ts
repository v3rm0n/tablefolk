import { bytesToHex, RistrettoPoint } from "@p2pcards/crypto";
import { cardDerivationHash } from "@p2pcards/protocol";

export const MIN_DECK_SIZE = 2;
export const MAX_DECK_SIZE = 128;

export interface DeckSpec {
  readonly id: string;
  readonly cards: readonly string[];
}

export class DeckSpecError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeckSpecError";
  }
}

export class CardPointTable {
  readonly #deckSpecId: string;
  readonly #cardIds: readonly string[];
  readonly #points: readonly RistrettoPoint[];
  readonly #cardByPoint: ReadonlyMap<string, string>;

  constructor(spec: DeckSpec) {
    if (typeof spec.id !== "string" || spec.id.length === 0) {
      throw new DeckSpecError("Deck specification ID must be a non-empty string");
    }
    if (spec.cards.length < MIN_DECK_SIZE || spec.cards.length > MAX_DECK_SIZE) {
      throw new DeckSpecError(
        `Deck must contain ${MIN_DECK_SIZE} to ${MAX_DECK_SIZE} cards; got ${spec.cards.length}`,
      );
    }

    const seenIds = new Set<string>();
    const pointMap = new Map<string, string>();
    const cardIds: string[] = [];
    const points: RistrettoPoint[] = [];

    for (const cardId of spec.cards) {
      if (typeof cardId !== "string" || cardId.length === 0) {
        throw new DeckSpecError("Every card identifier must be a non-empty string");
      }
      if (seenIds.has(cardId)) {
        throw new DeckSpecError(`Duplicate card identifier: ${cardId}`);
      }

      let point: RistrettoPoint;
      try {
        point = deriveCardPoint(spec.id, cardId);
      } catch (cause) {
        throw new DeckSpecError(`Unable to derive card point for ${cardId}`, { cause });
      }
      const encoded = bytesToHex(point.toBytes());
      if (pointMap.has(encoded)) {
        throw new DeckSpecError(`Card-point collision for ${cardId}`);
      }

      seenIds.add(cardId);
      pointMap.set(encoded, cardId);
      cardIds.push(cardId);
      points.push(point);
    }

    this.#deckSpecId = spec.id;
    this.#cardIds = Object.freeze(cardIds);
    this.#points = Object.freeze(points);
    this.#cardByPoint = pointMap;
  }

  get deckSpecId(): string {
    return this.#deckSpecId;
  }

  get size(): number {
    return this.#cardIds.length;
  }

  cardIdAt(position: number): string {
    assertPosition(position, this.size);
    return this.#cardIds[position]!;
  }

  pointAt(position: number): RistrettoPoint {
    assertPosition(position, this.size);
    return this.#points[position]!;
  }

  identify(point: RistrettoPoint): string | null {
    return this.#cardByPoint.get(bytesToHex(point.toBytes())) ?? null;
  }
}

export function deriveCardPoint(deckSpecId: string, cardId: string): RistrettoPoint {
  return RistrettoPoint.fromUniformBytes(cardDerivationHash(deckSpecId, cardId));
}

function assertPosition(position: number, size: number): void {
  if (!Number.isInteger(position) || position < 0 || position >= size) {
    throw new RangeError(`Card position must be an integer from 0 through ${size - 1}`);
  }
}
