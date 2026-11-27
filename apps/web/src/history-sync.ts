import { bytesEqual, bytesToHex } from "@p2pcards/crypto";
import type { AdvertisedHead, ChannelControl, EnvelopeArtifact, IdentityPublicKey } from "@p2pcards/protocol";
import { planHeadSyncRequest, type ChainHead } from "@p2pcards/session";

type Request = Extract<ChannelControl, { type: "SYNC_REQ" }>;
type Response = Extract<ChannelControl, { type: "SYNC_RESP" }>;

interface Source {
  allowed(from: IdentityPublicKey): boolean;
  head(from: IdentityPublicKey): ChainHead | null;
  get(from: IdentityPublicKey, seq: number): EnvelopeArtifact | undefined;
}

interface Flight {
  readonly request: Request;
  readonly target: AdvertisedHead;
  readonly startSeq: number;
  readonly expected: AdvertisedHead | null;
  answered: boolean;
}

/** Catch-up and fork checks for one authenticated channel generation. */
export class HistorySync {
  #heads: readonly AdvertisedHead[] | null = null;
  #nextId = 0;
  readonly #flights = new Map<string, Flight>();
  #ready = false;

  get ready(): boolean { return this.#ready; }

  advertise(heads: readonly AdvertisedHead[]): void {
    const keys = new Set(heads.map(head => bytesToHex(head.from)));
    for (const [key, flight] of this.#flights) {
      if (!keys.has(key) && flight.answered) this.#flights.delete(key);
    }
    this.#heads = heads;
  }

  advance(source: Source): readonly Request[] {
    if (this.#heads === null) return [];
    const requests: Request[] = [];
    let caughtUp = true;
    for (const claimed of this.#heads) {
      if (!source.allowed(claimed.from)) continue;
      const key = bytesToHex(claimed.from);
      const plan = planHeadSyncRequest(claimed, source.head(claimed.from), seq => source.get(claimed.from, seq));
      if (plan.status === "known") {
        if (this.#flights.get(key)?.answered) this.#flights.delete(key);
        continue;
      }
      caughtUp = false;
      const flight = this.#flights.get(key);
      if (flight && (!flight.answered || (
        flight.startSeq === plan.request.fromSeq && flight.target.seq === claimed.seq &&
        bytesEqual(flight.target.hash, claimed.hash)
      ))) continue;
      const expected = plan.request.toSeq === claimed.seq ? claimed : null;
      requests.push(this.#request(key, plan.request, claimed, expected));
    }
    // Later advertisements detect gaps and forks without reinstating a live acknowledgement barrier.
    this.#ready ||= caughtUp;
    return requests;
  }

  receive(response: Response, source: Source):
    | { artifact: EnvelopeArtifact; conflict?: EnvelopeArtifact }
    | { request: Request }
    | null {
    const entry = [...this.#flights.entries()].find(([, flight]) => flight.request.id === response.id);
    if (!entry || entry[1].answered) throw new Error("Unsolicited SYNC_RESP");
    const [key, flight] = entry;
    flight.answered = true;
    if (response.body === null) return null;
    const { from, fromSeq } = flight.request.body;
    const artifact = response.body.envelopes[0]!;
    const { seq, prev } = artifact.envelope;
    if (!bytesEqual(artifact.envelope.from, from) || seq !== fromSeq ||
        (flight.expected && !bytesEqual(artifact.hash, flight.expected.hash))) {
      throw new Error("SYNC_RESP does not match the requested signed history");
    }
    const existing = source.get(from, seq);
    if (existing) return bytesEqual(existing.hash, artifact.hash) ? null : { artifact, conflict: existing };

    const predecessor = seq === 0 ? undefined : source.get(from, seq - 1);
    if (predecessor && !bytesEqual(predecessor.hash, prev)) {
      // The advertised fork is ahead of our head. Fetch its signed predecessor at our known sequence.
      const expected = { from, seq: seq - 1, hash: prev };
      return { request: this.#request(key, { from, fromSeq: expected.seq, toSeq: expected.seq }, flight.target, expected, flight.startSeq) };
    }
    return { artifact };
  }

  #request(key: string, body: Request["body"], target: AdvertisedHead, expected: AdvertisedHead | null, startSeq = body.fromSeq): Request {
    const request: Request = { type: "SYNC_REQ", id: this.#nextId++, body };
    this.#flights.set(key, { request, target, expected, startSeq, answered: false });
    return request;
  }
}
