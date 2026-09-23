import { systemRandomSource, type RandomSource } from "@p2pcards/crypto";

export function checkPreparationGuard(guard?: () => undefined): void {
  if (guard === undefined) return;
  if (typeof guard !== "function") { throw new TypeError("Preparation guard must be a function"); }
  const result: unknown = guard();
  if (result !== undefined) {
    // Invalid async guards must not leave rejected promises unobserved.
    void Promise.resolve(result).catch(() => {});
    throw new TypeError("Preparation guard must synchronously return undefined");
  }
}

export function preparationRandomSource(source: RandomSource | undefined, guard?: () => undefined): RandomSource {
  const selected = source === undefined ? systemRandomSource : source;
  if (typeof selected !== "object" || selected === null) {
    throw new TypeError("Random source must implement fill(target)");
  }
  const fill = selected.fill;
  if (typeof fill !== "function") { throw new TypeError("Random source must implement fill(target)"); }
  return Object.freeze({
    fill(target: Uint8Array): void {
      checkPreparationGuard(guard);
      // Keep sampler bytes private, even if the source retains its output buffer.
      const bytes = new Uint8Array(target.length);
      fill.call(selected, bytes);
      target.set(bytes);
      checkPreparationGuard(guard);
    },
  });
}
