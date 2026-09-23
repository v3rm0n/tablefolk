import { bytesEqual, randomBytes, type RandomSource } from "@p2pcards/crypto";
import {
  beaconCommitment, parseHash256, parseRandomSecret, snapshotSetupBeaconScope,
  type Hash256, type RandomSecret, type SetupBeaconScope,
} from "@p2pcards/protocol";

import type { BeaconContribution } from "./randomness-beacon";
import { checkPreparationGuard, preparationRandomSource } from "./local-preparation";

export interface DurableSetupBeaconSecretStore {
  /** Initial preparation only. Resolve with the selected secret only after its storage transaction commits. */
  getOrCreateSetupBeaconSecret(scope: SetupBeaconScope, create: () => RandomSecret): Promise<RandomSecret>;
}

export interface SetupBeaconSecretReader {
  loadSetupBeaconSecret(scope: SetupBeaconScope): Promise<RandomSecret | null>;
}

export type LocalBeaconSecretErrorCode = "missing_secret" | "commitment_mismatch" | "invalid_store_result";

export class LocalBeaconSecretError extends Error {
  readonly code: LocalBeaconSecretErrorCode;
  constructor(code: LocalBeaconSecretErrorCode, options?: ErrorOptions) {
    super(`Local setup beacon: ${code}`, options);
    this.name = "LocalBeaconSecretError";
    this.code = code;
  }
}

/** Private material for initial setup preparation, not permission to author or reveal it. */
export async function prepareLocalBeaconContribution(
  scope: SetupBeaconScope, store: DurableSetupBeaconSecretStore, source?: RandomSource,
  guard?: () => undefined,
): Promise<BeaconContribution> {
  const captured = snapshotSetupBeaconScope(scope);
  checkPreparationGuard(guard);
  const getOrCreate = store?.getOrCreateSetupBeaconSecret;
  if (typeof getOrCreate !== "function") { throw new TypeError("A durable setup-beacon secret store is required"); }
  const random = preparationRandomSource(source, guard);
  const dependencyScope = snapshotSetupBeaconScope(captured);
  let open = true;
  let attempted = false;
  let failed = false;
  let failure: unknown;
  let generated: RandomSecret | null = null;
  try {
    checkPreparationGuard(guard);
    const stored = await getOrCreate.call(store, dependencyScope, () => {
      if (!open || attempted) {
        failed = true;
        failure = new LocalBeaconSecretError("invalid_store_result");
        throw failure;
      }
      attempted = true;
      try {
        checkPreparationGuard(guard);
        generated = parseRandomSecret(randomBytes(32, random));
        return parseRandomSecret(generated);
      } catch (cause) { failed = true; failure = cause; throw cause; }
    });
    open = false;
    checkPreparationGuard(guard);
    if (failed) throw failure;
    let secret: RandomSecret;
    try { secret = parseRandomSecret(stored); }
    catch { throw new LocalBeaconSecretError("invalid_store_result"); }
    if (generated !== null && !bytesEqual(secret, generated)) { throw new LocalBeaconSecretError("invalid_store_result"); }
    const local = contribution(captured, secret);
    checkPreparationGuard(guard);
    if (failed) throw failure;
    return local;
  } catch (cause) { throw failed ? failure : cause; }
  finally { open = false; }
}

/** Restore against an authenticated, accepted commitment. Missing/mismatched secrets are never regenerated. */
export async function restoreLocalBeaconContribution(
  scope: SetupBeaconScope, store: SetupBeaconSecretReader, expectedCommitment: Hash256,
  guard?: () => undefined,
): Promise<BeaconContribution> {
  const captured = snapshotSetupBeaconScope(scope);
  const expected = parseHash256(expectedCommitment);
  checkPreparationGuard(guard);
  const load = store?.loadSetupBeaconSecret;
  if (typeof load !== "function") { throw new TypeError("A load-only setup-beacon secret reader is required"); }
  const dependencyScope = snapshotSetupBeaconScope(captured);
  checkPreparationGuard(guard);
  const stored = await load.call(store, dependencyScope);
  checkPreparationGuard(guard);
  if (stored === null) { throw new LocalBeaconSecretError("missing_secret"); }
  let secret: RandomSecret;
  try { secret = parseRandomSecret(stored); }
  catch { throw new LocalBeaconSecretError("invalid_store_result"); }
  const restored = contribution(captured, secret);
  if (!bytesEqual(restored.commitment, expected)) { throw new LocalBeaconSecretError("commitment_mismatch"); }
  checkPreparationGuard(guard);
  return restored;
}

function contribution(scope: SetupBeaconScope, secret: RandomSecret): BeaconContribution {
  const seat = scope.roster.findIndex((identity) => bytesEqual(identity, scope.sender));
  return Object.freeze({
    secret: parseRandomSecret(secret),
    commitment: parseHash256(beaconCommitment(scope.gameId, scope.round, seat, secret)),
  });
}
