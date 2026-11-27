const ALL_SEATS = 0b1111;

function votersFor(missing: number): number {
  const voters = ALL_SEATS ^ missing;
  return missing !== 0 && (voters & (voters - 1)) !== 0 ? voters : 0;
}

/** Authenticated votes count only for the exact set of missing roster seats. */
export class TableAbortVote {
  #votes = 0;
  #missing = 0;
  readonly #confirmations = new Map<number, number>();

  update(missing: number): void {
    if (this.#missing === missing) return;
    this.#missing = missing;
    this.#votes = 0;
  }

  get missing(): number { return this.#missing; }

  get available(): boolean { return votersFor(this.#missing) !== 0; }

  receive(seat: number, missing: number): void {
    const voter = 1 << seat;
    if (this.#missing === missing && (votersFor(missing) & voter)) this.#votes |= voter;
  }

  /** A returning seat can learn an outcome directly from every voter who observed it. */
  confirm(seat: number, missing: number): boolean {
    const voter = 1 << seat;
    const voters = votersFor(missing);
    if ((voters & voter) === 0) return false;
    const confirmations = (this.#confirmations.get(missing) ?? 0) | voter;
    this.#confirmations.set(missing, confirmations);
    return confirmations === voters;
  }

  hasVoted(seat: number): boolean { return (this.#votes & (1 << seat)) !== 0; }
  get count(): number { return [0, 1, 2, 3].filter(seat => this.hasVoted(seat)).length; }

  get ended(): boolean { return this.available && this.#votes === votersFor(this.#missing); }
}
