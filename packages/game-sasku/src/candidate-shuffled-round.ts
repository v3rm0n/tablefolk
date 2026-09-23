import { PersistentCandidateShuffleReceiver, recoverSetup, type PersistentCandidateShuffleOptions, type PrivateDealStep } from "@p2pcards/engine";
import { captureSessionHistory } from "@p2pcards/session";
import { SASKU_DECK_SPEC, type SaskuSeat } from "@p2pcards/rules-sasku";
import { PersistentSaskuRoundReceiver } from "./persistent-round-receiver";
import type { SaskuRoundRecoveryLimits } from "./round-recovery";

export interface CandidateShuffledSaskuRoundOptions extends Omit<PersistentCandidateShuffleOptions, "deckSpec"> {
  /** Caller must establish agreement on this policy; no dealer/beacon convention is inferred here. */
  readonly dealer: SaskuSeat;
  readonly schedule: readonly PrivateDealStep[];
  readonly roundHistoryLimits?: SaskuRoundRecoveryLimits;
}

/** Re-verifies the complete durable shuffle chain before restoring private dealing/play. No supplied deck is accepted. */
export async function recoverCandidateShuffledSaskuRound(input: CandidateShuffledSaskuRoundOptions): Promise<PersistentSaskuRoundReceiver> {
  const { dealer, schedule } = captureCandidateSaskuPolicy(input);
  const options = { ...input, deckSpec: SASKU_DECK_SPEC };
  const roundLimits = input.roundHistoryLimits === undefined ? undefined : Object.freeze({ ...input.roundHistoryLimits });
  const history = captureSessionHistory(options.session, options.historyLimits);
  const setup = recoverSetup(options.session.gameId, options.setupRound, options.session.roster, history.envelopes).coordinator;
  const shuffle = await PersistentCandidateShuffleReceiver.open(options);
  let round: PersistentSaskuRoundReceiver | undefined;
  try {
    history.assertUnchanged();
    if (!shuffle.snapshot.complete) throw new Error("Sasku requires all four verified shuffle contributions");
    round = PersistentSaskuRoundReceiver.recover({ setup, round: options.round, deck: shuffle.finalDeck,
      dealer, schedule, session: options.session, sessionReceiver: options.sessionReceiver }, roundLimits);
    history.assertUnchanged();
    return round;
  } catch (error) { round?.close(); throw error; }
  finally { shuffle.close(); }
}

/** Shared policy admission for the candidate round owner; does not establish agreement. */
export function captureCandidateSaskuPolicy(input: Pick<CandidateShuffledSaskuRoundOptions, "dealer" | "schedule">) {
  const dealer = input.dealer;
  if (!Number.isInteger(dealer) || dealer < 0 || dealer > 3 || Object.is(dealer, -0)) throw new Error("Invalid agreed Sasku dealer");
  if (!Array.isArray(input.schedule) || input.schedule.length < 4 || input.schedule.length > 36) throw new Error("Invalid agreed Sasku deal schedule");
  const counts = [0, 0, 0, 0];
  const schedule = Object.freeze(Array.from(input.schedule, step => {
    if (!step || !Number.isInteger(step.to) || step.to < 0 || step.to > 3 || Object.is(step.to, -0) ||
      !Number.isInteger(step.count) || step.count < 1 || step.count > 9) throw new Error("Invalid agreed Sasku deal step");
    counts[step.to]! += step.count;
    return Object.freeze({ to: step.to, count: step.count });
  }));
  if (counts.some(count => count !== 9)) throw new Error("Sasku must deal nine cards to every seat");
  return Object.freeze({ dealer, schedule });
}
