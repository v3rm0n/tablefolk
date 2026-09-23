// Self-contained, versioned connection-check module. This is not a Sasku rules bundle.
export const id = "connection-check";
export const version = "1";
export const players = 4;
export const gameplayAvailable = false;
export function start() {
  throw new Error("This profile verifies lobby agreement only; gameplay is unavailable");
}
