import {
  randomNonZeroRistrettoScalar,
  RISTRETTO_SCALAR_ORDER,
  type RandomSource,
  type RistrettoScalar,
} from "@p2pcards/crypto";
import { createGameKeyShare, type GameKeyShare } from "@p2pcards/deck";
import { parseGameId, type GameId, type ProofContext } from "@p2pcards/protocol";

import { checkPreparationGuard, preparationRandomSource } from "./local-preparation";

export interface DurableGameSecretStore {
  getOrCreateGameSecret(
    gameId: GameId,
    create: () => RistrettoScalar,
  ): Promise<RistrettoScalar>;
}

export interface LocalGameKeyShare {
  readonly secret: RistrettoScalar;
  readonly share: GameKeyShare;
}

/** Private setup preparation only, not permission to author a KEY_SHARE. */
export async function prepareLocalGameKeyShare(
  context: ProofContext,
  store: DurableGameSecretStore,
  source?: RandomSource,
  guard?: () => undefined,
): Promise<LocalGameKeyShare> {
  const stableContext: ProofContext = Object.freeze({
    gameId: parseGameId(context.gameId),
    round: context.round,
    phase: context.phase,
  });
  if (stableContext.phase !== "setup.keys") {
    throw new TypeError('Local game key proof phase must be exactly "setup.keys"');
  }
  if (!Number.isSafeInteger(stableContext.round) || stableContext.round < 0) {
    throw new RangeError("Local game key proof round must be an unsigned safe integer");
  }
  checkPreparationGuard(guard);
  const getOrCreate = store?.getOrCreateGameSecret;
  if (typeof store !== "object" || store === null || typeof getOrCreate !== "function") {
    throw new TypeError("Durable game-secret store must implement getOrCreateGameSecret");
  }

  const random = preparationRandomSource(source, guard);
  const gameId = parseGameId(stableContext.gameId);
  let open = true;
  let attempted = false;
  let failed = false;
  let failure: unknown;
  let generated: RistrettoScalar | null = null;
  try {
    checkPreparationGuard(guard);
    const secret = await getOrCreate.call(store, gameId, () => {
      if (!open || attempted) {
        failed = true;
        failure = new TypeError("Invalid game-secret store creator invocation");
        throw failure;
      }
      attempted = true;
      try {
        checkPreparationGuard(guard);
        generated = randomNonZeroRistrettoScalar(random);
        return generated;
      } catch (cause) { failed = true; failure = cause; throw cause; }
    });
    open = false;
    checkPreparationGuard(guard);
    if (failed) throw failure;
    if (typeof secret !== "bigint" || secret <= 0n || secret >= RISTRETTO_SCALAR_ORDER ||
        (generated !== null && secret !== generated)) {
      throw new TypeError("Invalid game-secret store result");
    }
    const share = createGameKeyShare(stableContext, secret, random);
    checkPreparationGuard(guard);
    if (failed) throw failure;
    return Object.freeze({ secret, share });
  } catch (cause) { throw failed ? failure : cause; }
  finally { open = false; }
}
