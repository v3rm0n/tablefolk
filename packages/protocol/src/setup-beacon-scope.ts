import { bytesEqual, bytesToHex, importEd25519PublicKey } from "@p2pcards/crypto";

import { parseGameId, parseIdentityPublicKey, type GameId, type IdentityPublicKey } from "./fields";

/** Local persistence scope for the single setup.rand beacon, not a new wire value or a beacon scheduling policy. */
export interface SetupBeaconScope {
  readonly gameId: GameId;
  readonly round: number;
  readonly roster: readonly IdentityPublicKey[];
  readonly sender: IdentityPublicKey;
}

export function snapshotSetupBeaconScope(candidate: SetupBeaconScope): SetupBeaconScope {
  if (typeof candidate !== "object" || candidate === null ||
      (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null)) {
    throw new TypeError("Setup beacon scope must be a plain object");
  }
  const keys = Reflect.ownKeys(candidate);
  if (keys.length !== 4 || !["gameId", "round", "roster", "sender"].every((key) => keys.includes(key))) {
    throw new TypeError("Setup beacon scope requires exactly gameId, round, roster, and sender");
  }
  const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(candidate, key);
    if (typeof key !== "string" || descriptor === undefined || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError("Setup beacon scope fields must be enumerable data properties");
    }
    values[key] = descriptor.value;
  }
  const gameId = parseGameId(values["gameId"]);
  const round = values["round"];
  const identities = values["roster"];
  const sender = parseIdentityPublicKey(values["sender"]);
  if (typeof round !== "number" || !Number.isSafeInteger(round) || round < 0 || Object.is(round, -0)) {
    throw new RangeError("Setup beacon round must be a non-negative safe integer");
  }
  if (!Array.isArray(identities)) {
    throw new RangeError("Setup beacon roster must contain three through eight identities");
  }
  const count = identities.length;
  if (!Number.isSafeInteger(count) || count < 3 || count > 8) {
    throw new RangeError("Setup beacon roster must contain three through eight identities");
  }
  const roster: IdentityPublicKey[] = [];
  const seen = new Set<string>();
  for (let seat = 0; seat < count; seat += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(identities, seat);
    if (descriptor === undefined || !("value" in descriptor)) { throw new TypeError("Setup beacon roster must be a dense data array"); }
    const identity = parseIdentityPublicKey(descriptor.value);
    importEd25519PublicKey(identity);
    const key = bytesToHex(identity);
    if (seen.has(key)) { throw new TypeError("Setup beacon roster cannot repeat identities"); }
    seen.add(key);
    roster.push(identity);
  }
  if (!roster.some((identity) => bytesEqual(identity, sender))) { throw new TypeError("Setup beacon sender must belong to the roster"); }
  return Object.freeze({ gameId, round, roster: Object.freeze(roster), sender });
}
