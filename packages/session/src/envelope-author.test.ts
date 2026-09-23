import {
  bytesToHex,
  hexToBytes,
  importEd25519SecretKey,
} from "@p2pcards/crypto";
import { encodeCanonical, type CborMap } from "@p2pcards/encoding";
import * as protocol from "@p2pcards/protocol";
import {
  decodeAndVerifyEnvelope,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type GameId,
  type IdentityPublicKey,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MAX_AUTHORED_HISTORY_PAGE_BYTES } from "./authored-history";
import {
  AuthoredEnvelopeStoreError,
  PersistentEnvelopeAuthor,
  type AuthoredEnvelopeStore,
  type EnvelopeContent,
} from "./envelope-author";

const SECRET_KEY = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const PUBLIC_KEY = parseIdentityPublicKey(
  hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
);
const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("persistent envelope author", () => {
  afterEach(() => vi.restoreAllMocks());

  it("returns a defensive copy of the game ID", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const gameId = author.gameId;

    expect(gameId).toEqual(GAME_ID);
    expect(author.gameId).not.toBe(gameId);
    gameId.fill(0xff);

    expect(author.gameId).toEqual(GAME_ID);
    const artifact = await author.author(content("unchanged game"));
    expect(artifact.envelope.game).toEqual(GAME_ID);
    expect(store.records[0]!.envelope.game).toEqual(GAME_ID);
  });

  it("serializes concurrent calls into one durably appended sender chain", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);

    const [first, second, third] = await Promise.all([
      author.author(content("first")),
      author.author(content("second")),
      author.author(content("third")),
    ]);

    expect(first.envelope).toMatchObject({ seq: 0, prev: ZERO_HASH });
    expect(second.envelope).toMatchObject({ seq: 1, prev: first.hash });
    expect(third.envelope).toMatchObject({ seq: 2, prev: second.hash });
    expect(store.records.map(({ envelope }) => envelope.seq)).toEqual([0, 1, 2]);
  });

  it("runs queued guards only when delayed storage supplies the actual head, just before signing", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    let release!: () => void;
    let reportEntered!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const entered = new Promise<void>((resolve) => { reportEntered = resolve; });
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, {
      async appendNext(gameId, sender, create) {
        reportEntered();
        await gate;
        return store.appendNext(gameId, sender, create);
      },
    });
    const sign = vi.spyOn(protocol, "signEnvelope");
    const guard = vi.fn((head: EnvelopeArtifact | null) => {
      expect(head).toEqual(store.records.at(-1) ?? null);
      expect(sign).toHaveBeenCalledTimes(store.records.length);
      return undefined;
    });

    const firstPending = author.author(content("first queued"), guard);
    const secondPending = author.author(content("second queued"), guard);
    await entered;
    expect(guard).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();

    const other = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const initial = await other.author(content("while storage waits"));
    expect(guard).not.toHaveBeenCalled();
    release();
    const [first, second] = await Promise.all([firstPending, secondPending]);

    expect(guard).toHaveBeenCalledTimes(2);
    expect(guard).toHaveBeenNthCalledWith(1, initial);
    expect(guard).toHaveBeenNthCalledWith(2, first);
    expect(sign).toHaveBeenCalledTimes(3);
    expect(first.envelope).toMatchObject({ seq: 1, prev: initial.hash });
    expect(second.envelope).toMatchObject({ seq: 2, prev: first.hash });
  });

  it.each([false, true])("does not sign or consume a sequence on a thrown guard, and keeps queued work usable (existing head: %s)", async (hasHead) => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const head = hasHead ? await author.author(content("initial")) : null;
    const sign = vi.spyOn(protocol, "signEnvelope");
    const error = new Error("guard rejected");
    const guard = vi.fn((current: EnvelopeArtifact | null) => {
      expect(current).toEqual(head);
      expect(sign).not.toHaveBeenCalled();
      throw error;
    });

    const rejected = author.author(content("rejected"), guard);
    const queued = author.author(content("queued"), (current) => {
      expect(current).toEqual(head);
      return undefined;
    });
    await expect(rejected).rejects.toBe(error);
    const committed = await queued;

    expect(guard).toHaveBeenCalledOnce();
    expect(sign).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ body: content("queued").body }), SECRET_KEY);
    expect(committed.envelope).toMatchObject({ seq: hasHead ? 1 : 0, prev: head?.hash ?? ZERO_HASH });
    expect(store.records).toHaveLength(hasHead ? 2 : 1);
  });

  it.each([null, false, 1, "guard", {}])("rejects a non-function guard before storage or signing: %j", async (guard) => {
    const store = new MemoryAuthoredEnvelopeStore();
    const append = vi.spyOn(store, "appendNext");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);

    // @ts-expect-error Deliberately bypass the guard type to test runtime validation.
    await expect(author.author(content("invalid guard"), guard)).rejects.toThrow("guard must be a function");
    expect(append).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it.each<[string, () => unknown]>([
    ["null", () => null],
    ["false", () => false],
    ["number", () => 0],
    ["object", () => ({})],
    ["resolved Promise", () => Promise.resolve(undefined)],
    ["rejected Promise", () => Promise.reject(new Error("rejected guard Promise"))],
    ["async", async () => undefined],
    ["rejected async", async () => { throw new Error("rejected async guard"); }],
  ])("rejects a %s guard result without signing or an unhandled rejection", async (_name, guard) => {
    const store = new MemoryAuthoredEnvelopeStore();
    const sign = vi.spyOn(protocol, "signEnvelope");
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);

    // @ts-expect-error Deliberately bypass the synchronous undefined return type.
    await expect(author.author(content("bad result"), guard)).rejects.toThrow("guard must return undefined synchronously");
    expect(sign).not.toHaveBeenCalled();
    expect(store.records).toHaveLength(0);

    const committed = await author.author(content("after bad result"));
    expect(committed.envelope.seq).toBe(0);
    expect(sign).toHaveBeenCalledOnce();
  });

  it("detaches the guard head from the validated signing head and stored head", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const first = await author.author({ ...content("head"), body: { bytes: new Uint8Array([1, 2, 3]) } });
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const sign = vi.spyOn(protocol, "signEnvelope");

    const second = await author.author(content("next"), (head) => {
      expect(decode).toHaveBeenCalledTimes(2);
      const validated = decode.mock.results[0]!.value as EnvelopeArtifact;
      expect(head).toEqual(first);
      expect(head).not.toBe(validated);
      expect(head).not.toBe(store.records[0]);
      for (const bytes of [
        head!.canonicalBytes, head!.hash, head!.envelope.game, head!.envelope.from,
        head!.envelope.prev, head!.envelope.sig, (head!.envelope.body as CborMap)["bytes"] as Uint8Array,
      ]) {
        bytes.fill(0xff);
      }
      expect(validated).toEqual(first);
      expect(store.records[0]).toEqual(first);
      return undefined;
    });

    expect(sign).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
      game: GAME_ID, from: PUBLIC_KEY, seq: 1, prev: first.hash, body: content("next").body,
    }), SECRET_KEY);
    expect(decodeAndVerifyEnvelope(second.canonicalBytes).envelope).toMatchObject({ seq: 1, prev: first.hash });
  });

  it("does not resolve an artifact until the durable append completes", async () => {
    let releaseCommit!: () => void;
    let reportCreated!: () => void;
    const commitGate = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    const created = new Promise<void>((resolve) => {
      reportCreated = resolve;
    });
    let persisted = false;
    const store: AuthoredEnvelopeStore = {
      async appendNext(_gameId, _sender, create) {
        create(null);
        reportCreated();
        await commitGate;
        persisted = true;
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    let resolved = false;

    const pending = author.author(content("held"));
    void pending.then(() => {
      resolved = true;
    });
    await created;
    expect(resolved).toBe(false);
    expect(persisted).toBe(false);

    releaseCommit();
    await pending;
    expect(persisted).toBe(true);
    expect(resolved).toBe(true);
  });

  it("does not consume a sequence when persistence fails", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    store.failNext = true;

    await expect(author.author(content("not committed"))).rejects.toThrow("storage failure");
    const committed = await author.author(content("committed"));

    expect(committed.envelope.seq).toBe(0);
    expect(committed.envelope.prev).toEqual(ZERO_HASH);
    expect(store.records).toHaveLength(1);
  });

  it("propagates a pre-callback store error and allows queued work to continue", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const error = new Error("transaction aborted");
    const append = vi.spyOn(store, "appendNext").mockRejectedValueOnce(error);
    const sign = vi.spyOn(protocol, "signEnvelope");
    const guard = vi.fn(() => undefined);
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);

    const rejected = author.author(content("not created"), guard);
    const queued = author.author(content("committed"));
    await expect(rejected).rejects.toBe(error);
    const committed = await queued;

    expect(committed.envelope).toMatchObject({ seq: 0, prev: ZERO_HASH });
    expect(store.records).toEqual([committed]);
    expect(() => append.mock.calls[0]![2](null)).toThrow(/closed/);
    expect(guard).not.toHaveBeenCalled();
    expect(sign).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ body: content("committed").body }), SECRET_KEY);
  });

  it("loads the durable head across authors and serializes competing instances", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const firstAuthor = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const first = await firstAuthor.author(content("initial"));
    const left = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const right = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);

    const next = await Promise.all([left.author(content("left")), right.author(content("right"))]);

    expect(first.envelope.seq).toBe(0);
    expect(next.map(({ envelope }) => envelope.seq).sort()).toEqual([1, 2]);
    expect(store.records).toHaveLength(3);
  });

  it("snapshots mutable body input before waiting for storage", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const store: AuthoredEnvelopeStore = {
      async appendNext(_gameId, _sender, create) {
        await gate;
        create(null);
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const bytes = new Uint8Array([1, 2, 3]);
    const body = { marker: "before", bytes };

    const pending = author.author({ ...content("ignored"), body }, (head) => {
      expect(head).toBeNull();
      body.marker = "during guard";
      bytes.fill(7);
      return undefined;
    });
    body.marker = "after";
    bytes.fill(9);
    release();
    const artifact = await pending;
    const storedBody = artifact.envelope.body as CborMap;

    expect(storedBody["marker"]).toBe("before");
    expect(storedBody["bytes"]).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("rejects invalid or mismatched durable heads", async () => {
    const wrongGame = parseGameId(new Uint8Array(16).fill(9));
    const wrongHead = signedHead(wrongGame, 0);
    const store: AuthoredEnvelopeStore = {
      async appendNext(_gameId, _sender, create) {
        create(wrongHead);
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const guard = vi.fn(() => undefined);
    const sign = vi.spyOn(protocol, "signEnvelope");

    await expect(author.author(content("next"), guard)).rejects.toThrow(
      expect.objectContaining({
        name: "AuthoredEnvelopeStoreError",
        message: "Envelope store returned a head for another game",
      }),
    );
    expect(guard).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("refuses to advance beyond the safe integer sequence range", async () => {
    const exhaustedHead = signedHead(GAME_ID, Number.MAX_SAFE_INTEGER);
    const store: AuthoredEnvelopeStore = {
      async appendNext(_gameId, _sender, create) {
        create(exhaustedHead);
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const guard = vi.fn(() => undefined);
    const sign = vi.spyOn(protocol, "signEnvelope");

    await expect(author.author(content("overflow"), guard)).rejects.toBeInstanceOf(
      AuthoredEnvelopeStoreError,
    );
    expect(guard).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("copies constructor keys and rejects malformed content before storage", async () => {
    const mutableSecret = importEd25519SecretKey(SECRET_KEY);
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, mutableSecret, store);
    mutableSecret.fill(0);

    const artifact = await author.author(content("stable key"));
    expect(artifact.envelope.from).toEqual(PUBLIC_KEY);
    await expect(
      author.author({ ...content("bad"), body: Number.NaN }),
    ).rejects.toThrow();
    expect(store.records).toHaveLength(1);
  });

  it("isolates scope and returned artifacts from storage callback mutation", async () => {
    const store: AuthoredEnvelopeStore = {
      async appendNext(game, sender, create) {
        game.fill(0xff);
        sender.fill(0xff);
        const artifact = create(null);
        artifact.canonicalBytes.fill(0xff);
        artifact.hash.fill(0xff);
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const result = await author.author(content("stable"));
    expect(decodeAndVerifyEnvelope(result.canonicalBytes).envelope).toMatchObject({ game: GAME_ID, from: PUBLIC_KEY, seq: 0 });
    expect(author.sender).toEqual(PUBLIC_KEY);
    expect(result.hash).toEqual(decodeAndVerifyEnvelope(result.canonicalBytes).hash);
  });

  it("rejects repeated creation even if the store swallows the callback error", async () => {
    const guard = vi.fn(() => undefined);
    const sign = vi.spyOn(protocol, "signEnvelope");
    const store: AuthoredEnvelopeStore = {
      async appendNext(_game, _sender, create) {
        create(null);
        try { create(null); } catch { /* Deliberately broken store contract. */ }
      },
    };
    await expect(new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).author(content("repeated"), guard)).rejects.toThrow(/more than once/);
    expect(guard).toHaveBeenCalledExactlyOnceWith(null);
    expect(sign).toHaveBeenCalledOnce();
  });

  it("expires the signing callback after storage settles", async () => {
    const guard = vi.fn(() => undefined);
    const sign = vi.spyOn(protocol, "signEnvelope");
    let createLater: ((head: EnvelopeArtifact | null) => EnvelopeArtifact) | undefined;
    const store: AuthoredEnvelopeStore = {
      async appendNext(_game, _sender, create) { createLater = create; },
    };
    await expect(new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).author(content("late"), guard)).rejects.toThrow(/without creating/);
    expect(() => createLater!(null)).toThrow(/closed/);
    expect(guard).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it.each([
    { rejects: false, error: new Error("guard failure") },
    { rejects: true, error: new Error("guard failure") },
    { rejects: false, error: undefined },
    { rejects: true, error: undefined },
  ])("preserves a guard failure ($error) when the store rejects: $rejects", async ({ rejects, error }) => {
    const sign = vi.spyOn(protocol, "signEnvelope");
    const store: AuthoredEnvelopeStore = {
      async appendNext(_game, _sender, create) {
        try { create(null); } catch { /* Deliberately broken store contract. */ }
        if (rejects) {
          throw new Error("transaction aborted");
        }
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    await expect(author.author(content("rejected"), () => { throw error; })).rejects.toBe(error);
    expect(sign).not.toHaveBeenCalled();
  });

  it.each([
    ["malformed", "Envelope store returned an invalid chain head"],
    ["game", "Envelope store returned a head for another game"],
    ["sender", "Envelope store returned a head for another sender"],
  ])("preserves a %s head callback error masked by a generic store rejection", async (kind, message) => {
    const head = signedHead(kind === "game" ? parseGameId(new Uint8Array(16).fill(4)) : GAME_ID, 0);
    if (kind === "malformed") {
      head.canonicalBytes.fill(0xff);
    }
    const secretKey = kind === "sender" ? importEd25519SecretKey(new Uint8Array(32).fill(7)) : SECRET_KEY;
    const sign = vi.spyOn(protocol, "signEnvelope");
    const guard = vi.fn(() => undefined);
    let callbackError: unknown;
    const store: AuthoredEnvelopeStore = {
      async appendNext(_game, _sender, create) {
        try { create(head); } catch (cause) { callbackError = cause; }
        throw new Error("transaction aborted");
      },
    };
    const author = new PersistentEnvelopeAuthor(GAME_ID, secretKey, store);

    const rejected = author.author(content("bad head"), guard);
    await expect(rejected).rejects.toThrow(expect.objectContaining({ name: "AuthoredEnvelopeStoreError", message }));
    await expect(rejected).rejects.toBe(callbackError);
    expect(guard).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("preserves a validation failure swallowed by a broken store", async () => {
    const store: AuthoredEnvelopeStore = {
      async appendNext(_game, _sender, create) {
        try { create(signedHead(parseGameId(new Uint8Array(16).fill(4)), 0)); } catch { /* Deliberate fault. */ }
      },
    };
    await expect(new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).author(content("bad head"))).rejects.toThrow(/another game/);
  });
});

describe("persistent envelope author head preflight", () => {
  afterEach(() => vi.restoreAllMocks());

  it("reads its own empty or durable head without signing, appending, or consuming a sequence", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const append = vi.spyOn(store, "appendNext");
    const sign = vi.spyOn(protocol, "signEnvelope");
    await expect(author.readHead()).resolves.toBeNull();
    expect(append).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();

    const first = await author.author(content("first"));
    const head = await author.readHead();
    expect(head).toEqual(first);
    expect(head).not.toBe(store.records[0]);
    expect(append).toHaveBeenCalledOnce();
    expect(sign).toHaveBeenCalledOnce();
    const second = await author.author(content("second"));
    expect(second.envelope).toMatchObject({ seq: 1, prev: first.hash });
  });

  it("can inspect an exhausted sequence without trying to advance it", async () => {
    const head = signedHead(GAME_ID, Number.MAX_SAFE_INTEGER);
    const store = { appendNext: vi.fn(), readAuthoredHead: vi.fn(async () => head) };
    const sign = vi.spyOn(protocol, "signEnvelope");
    await expect(new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).readHead()).resolves.toEqual(head);
    expect(store.appendNext).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
  });

  it("orders author -> read -> author in both directions, waiting for each operation to settle", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const append = store.appendNext.bind(store);
    const read = store.readAuthoredHead.bind(store);
    let releaseAppend!: () => void;
    let releaseRead!: () => void;
    let enteredAppend!: () => void;
    let enteredRead!: () => void;
    const appendGate = new Promise<void>((resolve) => { releaseAppend = resolve; });
    const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
    const appending = new Promise<void>((resolve) => { enteredAppend = resolve; });
    const reading = new Promise<void>((resolve) => { enteredRead = resolve; });
    const events: string[] = [];
    vi.spyOn(store, "appendNext").mockImplementationOnce(async (...args) => {
      events.push("append entered");
      enteredAppend();
      await appendGate;
      await append(...args);
      events.push("append committed");
    });
    const readSpy = vi.spyOn(store, "readAuthoredHead").mockImplementationOnce(async (...args) => {
      events.push("read entered");
      enteredRead();
      await readGate;
      return read(...args);
    });
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const sign = vi.spyOn(protocol, "signEnvelope");
    const first = author.author(content("before"));
    const head = author.readHead();
    const second = author.author(content("after"));
    await appending;
    expect(readSpy).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    releaseAppend();
    await reading;
    expect(events).toEqual(["append entered", "append committed", "read entered"]);
    expect(sign).toHaveBeenCalledOnce();
    expect(store.records).toHaveLength(1);
    releaseRead();
    const [before, snapshot, after] = await Promise.all([first, head, second]);
    expect(snapshot).toEqual(before);
    expect(after.envelope).toMatchObject({ seq: 1, prev: before.hash });
    expect(store.records).toHaveLength(2);
  });

  it("captures the read method once at admission and retains its store receiver while queued", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const original = store.readAuthoredHead;
    let method = original;
    const getter = vi.fn(() => method);
    Object.defineProperty(store, "readAuthoredHead", { get: getter });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const append = store.appendNext.bind(store);
    vi.spyOn(store, "appendNext").mockImplementationOnce(async (...args) => { await gate; await append(...args); });
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const first = author.author(content("queued"));
    const pending = author.readHead();
    expect(getter).toHaveBeenCalledOnce();
    method = vi.fn(async () => { throw new Error("replacement method must not run"); });
    release();
    await expect(pending).resolves.toEqual(await first);
    expect(getter).toHaveBeenCalledOnce();
    expect(method).not.toHaveBeenCalled();
  });

  it("copies read scope arguments and detaches returned bytes, hashes and body values", async () => {
    const head = signEnvelope({ ...signedHead(GAME_ID, 0).envelope, body: { bytes: new Uint8Array([1, 2, 3]) } }, SECRET_KEY);
    const expected = decodeAndVerifyEnvelope(head.canonicalBytes);
    const scopes: Uint8Array[][] = [];
    const store: AuthoredEnvelopeStore = {
      appendNext: vi.fn(),
      async readAuthoredHead(game, sender) {
        expect(this).toBe(store);
        expect(game).toEqual(GAME_ID);
        expect(sender).toEqual(PUBLIC_KEY);
        scopes.push([game, sender]);
        game.fill(0xff);
        sender.fill(0xff);
        return head;
      },
    };
    const game = parseGameId(GAME_ID);
    const author = new PersistentEnvelopeAuthor(game, SECRET_KEY, store);
    game.fill(0xee);
    author.gameId.fill(0xee);
    author.sender.fill(0xee);
    const first = (await author.readHead())!;
    for (const bytes of [first.canonicalBytes, first.hash, first.envelope.game, first.envelope.from,
      first.envelope.prev, first.envelope.sig, (first.envelope.body as CborMap)["bytes"] as Uint8Array]) bytes.fill(0xff);
    expect(head).toEqual(expected);
    const second = await author.readHead();
    head.canonicalBytes.fill(0xee);
    head.hash.fill(0xee);
    expect(second).toEqual(expected);
    expect(scopes[0]![0]).not.toBe(scopes[1]![0]);
    expect(scopes[0]![1]).not.toBe(scopes[1]![1]);
    expect(author.gameId).toEqual(GAME_ID);
    expect(author.sender).toEqual(PUBLIC_KEY);
    expect(store.appendNext).not.toHaveBeenCalled();
  });

  it.each([undefined, null, true, {}])("rejects unsupported read capability (%j) without any fallback append", async (method) => {
    const store = new MemoryAuthoredEnvelopeStore();
    Object.defineProperty(store, "readAuthoredHead", { value: method, configurable: true });
    const append = vi.spyOn(store, "appendNext");
    const sign = vi.spyOn(protocol, "signEnvelope");
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    await expect(author.readHead()).rejects.toBeInstanceOf(AuthoredEnvelopeStoreError);
    expect(append).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    const artifact = await author.author(content("still supported"));
    expect(artifact.envelope.seq).toBe(0);
  });

  it.each(["undefined", "missing bytes", "game", "sender", "signature", "canonical", "malformed"])(
    "rejects a %s head without signing or poisoning queued reads and authors", async (kind) => {
      const head = signedHead(kind === "game" ? parseGameId(new Uint8Array(16).fill(7)) : GAME_ID, 0);
      const candidate = kind === "undefined" ? undefined : kind === "missing bytes" ? {} : kind === "signature"
        ? { ...head, canonicalBytes: encodeCanonical({ ...head.envelope, sig: new Uint8Array(64) }) }
        : kind === "canonical" ? { ...head, canonicalBytes: new Uint8Array([0xb8, 0x0a, ...head.canonicalBytes.slice(1)]) }
        : kind === "malformed" ? { ...head, canonicalBytes: new Uint8Array([0xff]) } : head;
      const store = new MemoryAuthoredEnvelopeStore();
      vi.spyOn(store, "readAuthoredHead").mockResolvedValueOnce(candidate as EnvelopeArtifact);
      const author = new PersistentEnvelopeAuthor(GAME_ID,
        kind === "sender" ? importEd25519SecretKey(new Uint8Array(32).fill(7)) : SECRET_KEY, store);
      const sign = vi.spyOn(protocol, "signEnvelope");
      const rejected = author.readHead();
      const queuedRead = author.readHead();
      await expect(rejected).rejects.toBeInstanceOf(AuthoredEnvelopeStoreError);
      await expect(queuedRead).resolves.toBeNull();
      expect(sign).not.toHaveBeenCalled();
      expect(store.records).toHaveLength(0);
      expect((await author.author(content("valid next"))).envelope.seq).toBe(0);
    },
  );

  it("bounds intrinsic head bytes before copying or verification and rejects spoofed views", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const read = vi.spyOn(store, "readAuthoredHead");
    const decode = vi.spyOn(protocol, "decodeAndVerifyEnvelope");
    const copy = vi.spyOn(Uint8Array.prototype, "set");
    const oversized = Object.defineProperty(new Uint8Array(MAX_AUTHORED_HISTORY_PAGE_BYTES + 1), "length", { value: 1 });
    const wide = Object.setPrototypeOf(new Uint16Array(32), Uint8Array.prototype) as Uint8Array;
    class ByteSubclass extends Uint8Array {}
    for (const canonicalBytes of [oversized, wide, new ByteSubclass(1), new Uint8Array(),
      Object.create(Uint8Array.prototype), new Proxy(new Uint8Array(1), {}), null,
    ]) {
      read.mockResolvedValueOnce({ canonicalBytes } as EnvelopeArtifact);
      await expect(author.readHead()).rejects.toBeInstanceOf(AuthoredEnvelopeStoreError);
      expect(copy.mock.calls.some(([source]) => source === canonicalBytes)).toBe(false);
      expect(decode).not.toHaveBeenCalled();
    }
  });

  it("snapshots canonical head bytes once without trusting overridden view methods or decoded fields", async () => {
    const head = signedHead(GAME_ID, 0);
    const expected = decodeAndVerifyEnvelope(head.canonicalBytes);
    const override = vi.fn(() => { throw new Error("Source copy method used"); });
    Object.defineProperties(head.canonicalBytes, {
      length: { value: 1 }, byteLength: { value: 1 }, slice: { value: override }, [Symbol.iterator]: { value: override },
    });
    const getBytes = vi.fn(() => head.canonicalBytes);
    const candidate = { ...head, envelope: null, hash: ZERO_HASH, get canonicalBytes() { return getBytes(); } };
    const store = { appendNext: vi.fn(), async readAuthoredHead() { return candidate as unknown as EnvelopeArtifact; } };
    await expect(new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).readHead()).resolves.toEqual(expected);
    expect(getBytes).toHaveBeenCalledOnce();
    expect(override).not.toHaveBeenCalled();
  });

  it.each(["reject", "throw", "getter"])("propagates ordinary read errors (%s) and keeps queued work usable", async (failure) => {
    const store = new MemoryAuthoredEnvelopeStore();
    const error = new Error("read unavailable");
    if (failure === "getter") {
      const native = store.readAuthoredHead;
      Object.defineProperty(store, "readAuthoredHead", { get: vi.fn(() => native).mockImplementationOnce(() => { throw error; }) });
    } else {
      const read = vi.spyOn(store, "readAuthoredHead");
      if (failure === "reject") read.mockRejectedValueOnce(error);
      else read.mockImplementationOnce(() => { throw error; });
    }
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const failed = author.readHead();
    const empty = author.readHead();
    const next = author.author(content("next"));
    await expect(failed).rejects.toBe(error);
    await expect(empty).resolves.toBeNull();
    const artifact = await next;
    expect(artifact.envelope.seq).toBe(0);
    await expect(author.readHead()).resolves.toEqual(artifact);
  });

  it("allows a queued head read after a failed author without advancing the stored head", async () => {
    const store = new MemoryAuthoredEnvelopeStore();
    store.failNext = true;
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const failed = author.author(content("not committed"));
    const head = author.readHead();
    await expect(failed).rejects.toThrow("storage failure");
    await expect(head).resolves.toBeNull();
    expect((await author.author(content("committed"))).envelope.seq).toBe(0);
  });
});

class MemoryAuthoredEnvelopeStore implements AuthoredEnvelopeStore {
  readonly records: EnvelopeArtifact[] = [];
  failNext = false;
  readonly #heads = new Map<string, EnvelopeArtifact>();
  #pending: Promise<void> = Promise.resolve();

  async readAuthoredHead(gameId: GameId, sender: IdentityPublicKey): Promise<EnvelopeArtifact | null> {
    return this.#heads.get(`${bytesToHex(gameId)}:${bytesToHex(sender)}`) ?? null;
  }

  appendNext(
    gameId: GameId,
    sender: IdentityPublicKey,
    create: (head: EnvelopeArtifact | null) => EnvelopeArtifact,
  ): Promise<void> {
    const operation = this.#pending.then(() => {
      const key = `${bytesToHex(gameId)}:${bytesToHex(sender)}`;
      const artifact = create(this.#heads.get(key) ?? null);
      if (this.failNext) {
        this.failNext = false;
        throw new Error("storage failure");
      }
      const persisted = decodeAndVerifyEnvelope(artifact.canonicalBytes.slice());
      this.#heads.set(key, persisted);
      this.records.push(persisted);
    });
    this.#pending = operation.then(
      () => undefined,
      () => undefined,
    );
    return operation;
  }
}

function content(marker: string): EnvelopeContent {
  return {
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
}

function signedHead(gameId: GameId, seq: number): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: gameId,
    from: PUBLIC_KEY,
    seq,
    prev: ZERO_HASH,
    round: 0,
    phase: "lobby",
    type: "READY",
    body: null,
  };
  return signEnvelope(envelope, SECRET_KEY);
}
