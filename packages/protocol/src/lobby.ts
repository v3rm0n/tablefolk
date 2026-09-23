import { bytesToHex, sha256 } from "@p2pcards/crypto";
import { encodeCanonical, type CborMap, type CborValue } from "@p2pcards/encoding";

import {
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  type GameId,
  type Hash256,
  type IdentityPublicKey,
} from "./fields";
import {
  expectArray,
  expectByteString,
  expectExactMap,
  expectNonEmptyText,
  ProtocolSchemaError,
} from "./schema";

export const MAX_LOBBY_SEATS = 8;

export interface JoinBody {
  readonly pkId: IdentityPublicKey;
  readonly rulesHash: Hash256;
  readonly clientVersion: string;
}

export interface RosterBody {
  readonly gameId: GameId;
  readonly rulesHash: Hash256;
  readonly iceConfigHash: Hash256;
  readonly seats: readonly IdentityPublicKey[];
}

export interface ReadyBody {
  readonly rosterHash: Hash256;
}

const JOIN_KEYS = ["pk_id", "rules_hash", "client_version"] as const;
const ROSTER_KEYS = ["game_id", "rules_hash", "ice_config_hash", "seats"] as const;
const READY_KEYS = ["roster_hash"] as const;

export function encodeJoinBody(body: JoinBody): CborMap {
  const normalized = normalizeJoinBody(body.pkId, body.rulesHash, body.clientVersion);
  return {
    pk_id: normalized.pkId,
    rules_hash: normalized.rulesHash,
    client_version: normalized.clientVersion,
  };
}

export function decodeJoinBody(value: CborValue): JoinBody {
  const body = expectExactMap(value, JOIN_KEYS, "JOIN.body");
  return normalizeJoinBody(
    decodeIdentity(body["pk_id"], "JOIN.body.pk_id"),
    decodeHash(body["rules_hash"], "JOIN.body.rules_hash"),
    expectNonEmptyText(body["client_version"], "JOIN.body.client_version"),
  );
}

export function encodeRosterBody(body: RosterBody): CborMap {
  const normalized = normalizeRosterBody(
    body.gameId,
    body.rulesHash,
    body.iceConfigHash,
    body.seats,
  );
  return {
    game_id: normalized.gameId,
    rules_hash: normalized.rulesHash,
    ice_config_hash: normalized.iceConfigHash,
    seats: normalized.seats,
  };
}

export function decodeRosterBody(value: CborValue): RosterBody {
  const body = expectExactMap(value, ROSTER_KEYS, "ROSTER.body");
  return normalizeRosterBody(
    decodeGameId(body["game_id"], "ROSTER.body.game_id"),
    decodeHash(body["rules_hash"], "ROSTER.body.rules_hash"),
    decodeHash(body["ice_config_hash"], "ROSTER.body.ice_config_hash"),
    expectArray(body["seats"], "ROSTER.body.seats"),
  );
}

export function encodeReadyBody(body: ReadyBody): CborMap {
  return { roster_hash: decodeHash(body.rosterHash, "READY.body.roster_hash") };
}

export function decodeReadyBody(value: CborValue): ReadyBody {
  const body = expectExactMap(value, READY_KEYS, "READY.body");
  return Object.freeze({
    rosterHash: decodeHash(body["roster_hash"], "READY.body.roster_hash"),
  });
}

export function hashRosterBody(body: RosterBody): Hash256 {
  return parseHash256(sha256(encodeCanonical(encodeRosterBody(body))));
}

function normalizeJoinBody(
  pkId: CborValue,
  rulesHash: CborValue,
  clientVersion: CborValue,
): JoinBody {
  return Object.freeze({
    pkId: decodeIdentity(pkId, "JOIN.body.pk_id"),
    rulesHash: decodeHash(rulesHash, "JOIN.body.rules_hash"),
    clientVersion: expectNonEmptyText(clientVersion, "JOIN.body.client_version"),
  });
}

function normalizeRosterBody(
  gameId: CborValue,
  rulesHash: CborValue,
  iceConfigHash: CborValue,
  seats: CborValue,
): RosterBody {
  const candidates = expectArray(seats, "ROSTER.body.seats");
  if (candidates.length === 0 || candidates.length > MAX_LOBBY_SEATS) {
    throw new ProtocolSchemaError(
      "ROSTER.body.seats",
      `must contain between 1 and ${MAX_LOBBY_SEATS} identities`,
    );
  }

  const seen = new Set<string>();
  const normalizedSeats = candidates.map((candidate, index) => {
    const seat = decodeIdentity(candidate, `ROSTER.body.seats[${index}]`);
    const key = bytesToHex(seat);
    if (seen.has(key)) {
      throw new ProtocolSchemaError(
        "ROSTER.body.seats",
        `contains duplicate identity at index ${index}`,
      );
    }
    seen.add(key);
    return seat;
  });

  return Object.freeze({
    gameId: decodeGameId(gameId, "ROSTER.body.game_id"),
    rulesHash: decodeHash(rulesHash, "ROSTER.body.rules_hash"),
    iceConfigHash: decodeHash(iceConfigHash, "ROSTER.body.ice_config_hash"),
    seats: Object.freeze(normalizedSeats),
  });
}

function decodeGameId(value: CborValue, path: string): GameId {
  return decodeFixedBytes(value, path, "must be a 16-byte game identifier", parseGameId);
}

function decodeIdentity(value: CborValue, path: string): IdentityPublicKey {
  return decodeFixedBytes(value, path, "must be a 32-byte identity key", parseIdentityPublicKey);
}

function decodeHash(value: CborValue, path: string): Hash256 {
  return decodeFixedBytes(value, path, "must be a 32-byte hash", parseHash256);
}

function decodeFixedBytes<T>(
  value: CborValue,
  path: string,
  message: string,
  parse: (bytes: Uint8Array) => T,
): T {
  try {
    return parse(expectByteString(value, path));
  } catch (cause) {
    if (cause instanceof ProtocolSchemaError) {
      throw cause;
    }
    throw new ProtocolSchemaError(path, message, { cause });
  }
}
