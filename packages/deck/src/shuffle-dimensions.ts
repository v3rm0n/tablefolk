export interface ShuffleDimensions {
  readonly rows: number;
  readonly columns: number;
}

export const MAX_SHUFFLE_CARDS = 128;

export function shuffleCardCount({ rows, columns }: ShuffleDimensions): number {
  if (!Number.isInteger(rows) || !Number.isInteger(columns) ||
    rows < 2 || columns < 2 || rows * columns > MAX_SHUFFLE_CARDS) {
    throw new RangeError("Shuffle dimensions must be integers >= 2 with at most 128 cards");
  }
  return rows * columns;
}
