import {
  bytesEqual,
  bytesToHex,
  deriveEd25519PublicKey,
  hexToBytes,
  importEd25519SecretKey,
} from "@p2pcards/crypto";
import {
  decodeAndVerifyEnvelope,
  decodeWitnessBody,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  signEnvelope,
  type EnvelopeArtifact,
  type Hash256,
  type UnsignedEnvelope,
} from "@p2pcards/protocol";
import {
  AuthoredEnvelopeStoreError,
  PersistentEnvelopeAuthor,
  PersistentSessionReceiver,
  SessionChainRegistry,
  MAX_AUTHORED_HISTORY_PAGE_BYTES,
  replayAuthoredHistory,
  type EnvelopeContent,
} from "@p2pcards/session";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, it, vi } from "vitest";

import {
  AUTHORED_HEADS_STORE,
  GAMES_STORE,
  IDENTITY_STORE,
  TRANSCRIPTS_STORE,
} from "./database";
import { IndexedDbAuthoredEnvelopeStore } from "./indexeddb-envelope-store";
import { IndexedDbSessionStore } from "./indexeddb-session-store";

const SECRET_KEY = importEd25519SecretKey(
  hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
);
const PUBLIC_KEY = parseIdentityPublicKey(
  hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
);
const GAME_ID = parseGameId(hexToBytes("000102030405060708090a0b0c0d0e0f"));
const ZERO_HASH = parseHash256(new Uint8Array(32));

describe("IndexedDB authored envelope store", () => {
  it("restores the durable sender head and retains transcript arrival records", async () => {
    const factory = new IDBFactory();
    const databaseName = "restart";
    const firstStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const firstAuthor = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, firstStore);
    const first = await firstAuthor.author(content("first"));
    const second = await firstAuthor.author(content("second"));
    await firstStore.close();

    const resumedStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const resumedAuthor = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, resumedStore);
    const third = await resumedAuthor.author(content("third"));
    await resumedStore.close();

    expect(first.envelope.seq).toBe(0);
    expect(second.envelope).toMatchObject({ seq: 1, prev: first.hash });
    expect(third.envelope).toMatchObject({ seq: 2, prev: second.hash });
    const inspection = await inspectDatabase(factory, databaseName);
    expect(inspection.stores).toEqual([
      AUTHORED_HEADS_STORE,
      GAMES_STORE,
      IDENTITY_STORE,
      TRANSCRIPTS_STORE,
    ]);
    expect(inspection.transcriptCount).toBe(3);
    expect(inspection.headCount).toBe(1);
  });

  it("aborts both head and transcript writes for an invalid next artifact", async () => {
    const factory = new IDBFactory();
    const databaseName = "atomic-abort";
    const store = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });

    await expect(
      store.appendNext(GAME_ID, PUBLIC_KEY, () => signedEnvelope(1, ZERO_HASH, "invalid")),
    ).rejects.toThrow(AuthoredEnvelopeStoreError);

    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const first = await author.author(content("valid"));
    await store.close();
    const inspection = await inspectDatabase(factory, databaseName);

    expect(first.envelope.seq).toBe(0);
    expect(inspection.transcriptCount).toBe(1);
    expect(inspection.headCount).toBe(1);
  });

  it("serializes readwrite transactions across independent database connections", async () => {
    const factory = new IDBFactory();
    const databaseName = "competing-connections";
    const leftStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const rightStore = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const left = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, leftStore);
    const right = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, rightStore);

    const artifacts = await Promise.all([
      left.author(content("left")),
      right.author(content("right")),
    ]);
    const ordered = [...artifacts].sort(
      (first, second) => first.envelope.seq - second.envelope.seq,
    );

    expect(ordered.map(({ envelope }) => envelope.seq)).toEqual([0, 1]);
    expect(ordered[1]!.envelope.prev).toEqual(ordered[0]!.hash);
    await Promise.all([leftStore.close(), rightStore.close()]);
    expect((await inspectDatabase(factory, databaseName)).transcriptCount).toBe(2);
  });

  it("aborts callback exceptions and allows a later sequence-zero append", async () => {
    const factory = new IDBFactory();
    const databaseName = "callback-error";
    const store = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });

    await expect(
      store.appendNext(GAME_ID, PUBLIC_KEY, () => {
        throw new Error("signing failed");
      }),
    ).rejects.toThrow("signing failed");

    const artifact = await new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).author(
      content("retry"),
    );
    expect(artifact.envelope.seq).toBe(0);
    await store.close();
  });

  it("rejects invalid construction inputs", () => {
    const factory = new IDBFactory();
    expect(
      () => new IndexedDbAuthoredEnvelopeStore({ factory, databaseName: "" }),
    ).toThrow(TypeError);
  });

  it("returns independent bounded history snapshots and isolates asynchronous scope inputs", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName: "read-history" });
    expect(await store.readAuthoredHead(GAME_ID, PUBLIC_KEY)).toBeNull();
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    const first = await author.author(content("zero"));
    const second = await author.author(content("one"));
    const game = parseGameId(GAME_ID);
    const sender = parseIdentityPublicKey(PUBLIC_KEY);
    const reading = store.readAuthoredHead(game, sender);
    game.fill(0xff);
    sender.fill(0xff);
    expect(await reading).toEqual(second);
    const page = await store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 0, 1);
    expect(page).toEqual([first, second]);
    page[0]!.canonicalBytes.fill(0xff);
    page[1]!.hash.fill(0xff);
    expect(await store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 0, 1)).toEqual([first, second]);
    await expect(store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 0, 128)).rejects.toThrow(/128/);
    await expect(store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 0, 2)).rejects.toThrow(/checkpoint/);
    await store.close();
  });

  it.each(["missing_head", "missing_tail", "missing_middle", "stale_head", "different_tail", "unowned_tail"] as const)(
    "rejects checkpoint inconsistency before signing: %s", async (fault) => {
      const factory = new IDBFactory();
      const databaseName = `checkpoint-${fault}`;
      const store = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName });
      const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
      const first = await author.author(content("zero"));
      const second = await author.author(content("one"));
      await author.author(content("two"));
      await editDatabase(factory, databaseName, (transaction) => {
        const heads = transaction.objectStore(AUTHORED_HEADS_STORE);
        const transcripts = transaction.objectStore(TRANSCRIPTS_STORE);
        if (fault === "missing_head") { heads.delete([bytesToHex(GAME_ID), bytesToHex(PUBLIC_KEY)]); }
        if (fault === "stale_head") { heads.put({ game: bytesToHex(GAME_ID), sender: bytesToHex(PUBLIC_KEY), bytes: first.canonicalBytes }); }
        const rows = transcripts.getAll();
        rows.onsuccess = () => {
          const records = rows.result as Array<{ arrival: number; bytes: Uint8Array; authored: boolean }>;
          if (fault === "missing_tail") { transcripts.delete(records[2]!.arrival); }
          if (fault === "missing_middle") { transcripts.delete(records[1]!.arrival); }
          if (fault === "different_tail") {
            transcripts.put({ ...records[2]!, bytes: signedEnvelope(2, second.hash, "changed").canonicalBytes });
          }
          if (fault === "unowned_tail") { transcripts.put({ ...records[2]!, authored: false }); }
        };
      });
      const create = vi.fn(() => signedEnvelope(3, second.hash, "must not sign"));
      await expect(store.appendNext(GAME_ID, PUBLIC_KEY, create)).rejects.toThrow(AuthoredEnvelopeStoreError);
      expect(create).not.toHaveBeenCalled();
      await expect(store.readAuthoredHead(GAME_ID, PUBLIC_KEY)).rejects.toThrow(AuthoredEnvelopeStoreError);
      await store.close();
    },
  );

  it("does not promote received own-signed history into an authored checkpoint", async () => {
    const factory = new IDBFactory();
    const databaseName = "received-self-history";
    const accepted = new IndexedDbSessionStore({ factory, databaseName });
    await accepted.persistAcceptedEnvelope(signedEnvelope(0, ZERO_HASH, "recovered original"));
    const authored = new IndexedDbAuthoredEnvelopeStore({ factory, databaseName, keyRange: IDBKeyRange });
    const create = vi.fn(() => signedEnvelope(0, ZERO_HASH, "new genesis"));
    await expect(authored.appendNext(GAME_ID, PUBLIC_KEY, create)).rejects.toThrow(/checkpoint is missing/);
    expect(create).not.toHaveBeenCalled();
    await Promise.all([accepted.close(), authored.close()]);
  });

  it("keeps the trusted predecessor private from an append callback", async () => {
    const factory = new IDBFactory();
    const store = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName: "callback-head-mutation" });
    const first = await new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store).author(content("zero"));
    await expect(store.appendNext(GAME_ID, PUBLIC_KEY, (head) => {
      head!.hash.fill(0);
      return signedEnvelope(1, head!.hash, "broken link");
    })).rejects.toThrow(/predecessor/);
    await store.appendNext(GAME_ID, PUBLIC_KEY, (head) => {
      head!.hash.fill(0);
      return signedEnvelope(1, first.hash, "correct link");
    });
    expect((await store.readAuthoredHead(GAME_ID, PUBLIC_KEY))?.envelope.prev).toEqual(first.hash);
    await store.close();
  });

  it("size-checks and decodes the same callback byte snapshot", async () => {
    const store = new IndexedDbAuthoredEnvelopeStore({ factory: new IDBFactory(), keyRange: IDBKeyRange, databaseName: "callback-byte-getter" });
    const small = signedEnvelope(0, ZERO_HASH, "small");
    const large = signedEnvelope(0, ZERO_HASH, "x".repeat(MAX_AUTHORED_HISTORY_PAGE_BYTES));
    let reads = 0;
    await store.appendNext(GAME_ID, PUBLIC_KEY, () => ({
      ...large,
      get canonicalBytes() { return ++reads === 1 ? small.canonicalBytes : large.canonicalBytes; },
    }));
    expect(reads).toBe(1);
    expect(await store.readAuthoredHead(GAME_ID, PUBLIC_KEY)).toEqual(small);
    await store.close();
  });

  it("rejects corrupted earlier history during full replay before transmitting anything", async () => {
    const factory = new IDBFactory();
    const databaseName = "corrupt-old-history";
    const store = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName });
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, store);
    await author.author(content("zero"));
    await author.author(content("one"));
    await editDatabase(factory, databaseName, (transaction) => {
      const transcripts = transaction.objectStore(TRANSCRIPTS_STORE);
      const rows = transcripts.getAll();
      rows.onsuccess = () => {
        const first = rows.result[0] as { bytes: Uint8Array };
        first.bytes.fill(0xff);
        transcripts.put(first);
      };
    });
    const send = vi.fn(async () => undefined);
    await expect(replayAuthoredHistory(store, GAME_ID, PUBLIC_KEY, send)).resolves.toMatchObject({ status: "failed", stage: "verify", submittedCount: 0 });
    expect(send).not.toHaveBeenCalled();
    await store.close();
  });

  it("pages large envelopes by bytes rather than returning an oversized batch", async () => {
    const store = new IndexedDbAuthoredEnvelopeStore({ factory: new IDBFactory(), keyRange: IDBKeyRange, databaseName: "byte-pages" });
    const marker = "x".repeat(4 * 1024 * 1024);
    await store.appendNext(GAME_ID, PUBLIC_KEY, () => signedEnvelope(0, ZERO_HASH, marker));
    await store.appendNext(GAME_ID, PUBLIC_KEY, (head) => signedEnvelope(1, head!.hash, marker));
    const page = await store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 0, 1);
    expect(page).toHaveLength(1);
    expect(page[0]!.envelope.seq).toBe(0);
    expect((await store.readAuthoredPage(GAME_ID, PUBLIC_KEY, 1, 1))[0]!.envelope.seq).toBe(1);
    await store.close();
  });

  it("replays originals across restart so the next chained control needs no gap exemption", async () => {
    const factory = new IDBFactory();
    let source = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName: "replay-source" });
    const author = new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, source);
    const records = [
      await author.author({ round: 0, phase: "lobby", type: "WITNESS", body: { heads: [] } }),
      await author.author({ round: 0, phase: "lobby", type: "WITNESS", body: { heads: [] } }),
    ];
    await source.close();
    source = new IndexedDbAuthoredEnvelopeStore({ factory, keyRange: IDBKeyRange, databaseName: "replay-source" });
    const others = [1, 2].map((fill) => parseIdentityPublicKey(deriveEd25519PublicKey(importEd25519SecretKey(new Uint8Array(32).fill(fill)))));
    const registry = new SessionChainRegistry(GAME_ID, [PUBLIC_KEY, ...others]);
    const target = new IndexedDbSessionStore({ factory, databaseName: "replay-target" });
    const receiver = new PersistentSessionReceiver(registry, target);
    await expect(receiver.receive(records[1]!)).resolves.toMatchObject({ status: "rejected", reason: "gap" });
    const submitted: Uint8Array[] = [];
    const replayed = await replayAuthoredHistory(source, GAME_ID, PUBLIC_KEY, async (bytes) => {
      const original = decodeAndVerifyEnvelope(bytes);
      decodeWitnessBody(original.envelope.body);
      // Historical controls are validated and stored, not re-executed as network requests.
      const received = await receiver.receive(original);
      expect(received.status).toBe("accepted");
      submitted.push(bytes);
    });
    expect(replayed).toMatchObject({ status: "replayed", submittedCount: 2, checkpoint: { seq: 1 } });
    expect(submitted).toEqual(records.map(({ canonicalBytes }) => canonicalBytes));
    expect((await source.readAuthoredHead(GAME_ID, PUBLIC_KEY))?.hash).toEqual(records[1]!.hash);
    const next = await new PersistentEnvelopeAuthor(GAME_ID, SECRET_KEY, source).author({
      round: 0, phase: "lobby", type: "SYNC_REQ", body: { from: others[0]!, from_seq: 0, to_seq: 0 },
    });
    await expect(receiver.receive(next)).resolves.toMatchObject({ status: "accepted" });
    expect(next.envelope).toMatchObject({ seq: 2, prev: records[1]!.hash });
    expect((await target.loadTranscript(GAME_ID)).every(({ artifact }, index) =>
      bytesEqual(artifact.canonicalBytes, [...records, next][index]!.canonicalBytes),
    )).toBe(true);
    await Promise.all([source.close(), target.close()]);
  });
});

function content(marker: string): EnvelopeContent {
  return {
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
}

function signedEnvelope(seq: number, prev: Hash256, marker: string): EnvelopeArtifact {
  const envelope: UnsignedEnvelope = {
    v: 1,
    game: GAME_ID,
    from: PUBLIC_KEY,
    seq,
    prev,
    round: 0,
    phase: "lobby",
    type: "READY",
    body: { marker },
  };
  return signEnvelope(envelope, SECRET_KEY);
}

async function inspectDatabase(
  factory: IDBFactory,
  databaseName: string,
): Promise<{ readonly stores: string[]; readonly transcriptCount: number; readonly headCount: number }> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(databaseName);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const transaction = database.transaction(
      [TRANSCRIPTS_STORE, AUTHORED_HEADS_STORE],
      "readonly",
    );
    const transcriptCount = await requestResult(
      transaction.objectStore(TRANSCRIPTS_STORE).count(),
    );
    const headCount = await requestResult(transaction.objectStore(AUTHORED_HEADS_STORE).count());
    await transactionComplete(transaction);
    return {
      stores: Array.from(database.objectStoreNames),
      transcriptCount,
      headCount,
    };
  } finally {
    database.close();
  }
}

async function editDatabase(factory: IDBFactory, name: string, edit: (transaction: IDBTransaction) => void): Promise<void> {
  const database = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = factory.open(name);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  try {
    const transaction = database.transaction([TRANSCRIPTS_STORE, AUTHORED_HEADS_STORE], "readwrite");
    const done = transactionComplete(transaction);
    edit(transaction);
    await done;
  } finally {
    database.close();
  }
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error);
    transaction.onerror = () => reject(transaction.error);
  });
}
