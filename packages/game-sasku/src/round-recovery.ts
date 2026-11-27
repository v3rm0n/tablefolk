import { bytesEqual } from "@p2pcards/crypto";
import { MAX_ROUND_REVEAL_ENVELOPE_BYTES, recoverSetup, type SetupEnvelopeCoordinator } from "@p2pcards/engine";
import { type EnvelopeArtifact } from "@p2pcards/protocol";
import { captureSessionHistory, type SessionChainRegistry } from "@p2pcards/session";

export const DEFAULT_MAX_SASKU_RECOVERY_ENVELOPES = 1024;
export const DEFAULT_MAX_SASKU_RECOVERY_BYTES = 16 * 1024 * 1024;

export interface SaskuRoundRecoveryLimits {
  readonly maxEnvelopes?: number;
  readonly maxBytes?: number;
  /** The match driver verifies other rounds separately before accepting their scores. */
  readonly allowOtherRounds?: boolean;
}

export class SaskuRoundRecoveryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SaskuRoundRecoveryError";
  }
}

/** Captures authenticated history only; the caller owns round semantics and external prerequisites. */
export function captureSaskuRoundHistory(
  setup: SetupEnvelopeCoordinator,
  session: SessionChainRegistry,
  round: number,
  limits: SaskuRoundRecoveryLimits = {},
): { readonly bySeat: readonly (readonly EnvelopeArtifact[])[]; readonly assertUnchanged: () => void } {
  if (typeof limits !== "object" || limits === null) { throw new TypeError("Sasku recovery limits must be an object"); }
  const { maxEnvelopes = DEFAULT_MAX_SASKU_RECOVERY_ENVELOPES, maxBytes = DEFAULT_MAX_SASKU_RECOVERY_BYTES,
    allowOtherRounds = false } = limits;
  if (!Number.isSafeInteger(maxEnvelopes) || maxEnvelopes < 1 || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new RangeError("Sasku recovery limits must be positive safe integers");
  }
  if (typeof allowOtherRounds !== "boolean") throw new TypeError("Invalid other-round recovery policy");

  try {
    const game = setup.gameId;
    const roster = setup.roster;
    if (!bytesEqual(game, session.gameId) || roster.length !== 4 ||
        roster.some((sender, seat) => session.seatOf(sender) !== seat)) {
      throw new SaskuRoundRecoveryError("Sasku recovery history does not match its setup");
    }
    const history = captureSessionHistory(session, { maxEnvelopes, maxBytes });
    if (history.bySeat.length !== 4 || history.bySeat.some((artifacts) => artifacts.length === 0)) {
      throw new SaskuRoundRecoveryError("Sasku recovery requires every sender chain");
    }

    const setupArtifacts: EnvelopeArtifact[] = [];
    const bySeat: EnvelopeArtifact[][] = [[], [], [], []];
    for (let seat = 0; seat < 4; seat += 1) {
      const artifacts = history.bySeat[seat]!;
      let revealed = false;
      for (const artifact of artifacts) {
        const envelope = artifact.envelope;
        switch (envelope.type) {
          case "KEY_SHARE":
          case "RAND_COMMIT":
          case "RAND_REVEAL":
            setupArtifacts.push(artifact);
            if (envelope.type === (setup.beaconRequired ? "RAND_REVEAL" : "KEY_SHARE")) revealed = true;
            break;
          case "SHARES":
          case "ACTION":
          case "AUDIT_DISCLOSE":
            if ((!allowOtherRounds && envelope.round !== round) || !revealed ||
                artifact.canonicalBytes.length > MAX_ROUND_REVEAL_ENVELOPE_BYTES) {
              throw new SaskuRoundRecoveryError("Invalid Sasku recovery round traffic or setup order");
            }
            if (envelope.round === round) bySeat[seat]!.push(artifact);
            break;
          case "SHUFFLE":
            if ((!allowOtherRounds && envelope.round !== round) || !revealed) {
              throw new SaskuRoundRecoveryError("Invalid Sasku recovery shuffle traffic or setup order");
            }
            break;
          case "JOIN":
          case "ROSTER":
          case "READY":
          case "WITNESS":
          case "SYNC_REQ":
          case "SYNC_RESP":
          case "TIMEOUT_VOTE":
          case "VIOLATION":
            break;
          default:
            throw new SaskuRoundRecoveryError("Unsupported Sasku recovery envelope type");
        }
      }
    }

    const recovered = recoverSetup(game, setup.round, roster, setupArtifacts, setup.beaconRequired).coordinator;
    const aggregateKey = setup.aggregateKey;
    const seed = setup.seed;
    const recoveredSeed = recovered.seed;
    if (setup.state !== "complete" || recovered.state !== "complete" || aggregateKey === null ||
        !recovered.aggregateKey?.equals(aggregateKey) ||
        (setup.beaconRequired && (seed === null || recoveredSeed === null || !bytesEqual(seed, recoveredSeed))) ||
        (!setup.beaconRequired && (seed !== null || recoveredSeed !== null))) {
      throw new SaskuRoundRecoveryError("Sasku recovery setup is incomplete or does not match");
    }
    for (let seat = 0; seat < 4; seat += 1) {
      const key = setup.publicKeyAt(seat);
      if (key === null || !recovered.publicKeyAt(seat)?.equals(key)) {
        throw new SaskuRoundRecoveryError("Sasku recovery setup public keys do not match");
      }
    }

    return Object.freeze({ bySeat: Object.freeze(bySeat.map((artifacts) => Object.freeze(artifacts))), assertUnchanged: history.assertUnchanged });
  } catch (cause) {
    if (cause instanceof SaskuRoundRecoveryError) throw cause;
    throw new SaskuRoundRecoveryError("Could not capture Sasku round history", { cause });
  }
}
