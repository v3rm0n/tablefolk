import {
  asciiToBytes,
  bytesToHex,
  deriveEd25519PublicKey,
  importEd25519SecretKey,
  sha256,
  systemRandomSource,
  type RandomSource,
} from "@p2pcards/crypto";
import { encodeCanonical } from "@p2pcards/encoding";
import * as protocol from "@p2pcards/protocol";
import {
  beaconCommitment,
  parseGameId,
  parseHash256,
  parseIdentityPublicKey,
  parseRandomSecret,
  ProtocolFieldError,
  snapshotSetupBeaconScope,
  type Hash256,
  type RandomSecret,
  type SetupBeaconScope,
} from "@p2pcards/protocol";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  LocalBeaconSecretError,
  prepareLocalBeaconContribution,
  restoreLocalBeaconContribution,
  type DurableSetupBeaconSecretStore,
  type SetupBeaconSecretReader,
} from "./local-beacon-contribution";

vi.mock("@p2pcards/crypto", async (importOriginal) => ({
  ...await importOriginal<typeof import("@p2pcards/crypto")>(),
  systemRandomSource: { fill: vi.fn() },
}));

const IDENTITIES = Array.from({ length: 9 }, (_, seat) =>
  parseIdentityPublicKey(deriveEd25519PublicKey(
    importEd25519SecretKey(new Uint8Array(32).fill(seat + 1)),
  )),
);
const forbidden = vi.fn((): never => { throw new Error("Unexpected RNG or store operation"); });

beforeEach(() => {
  forbidden.mockClear();
  vi.mocked(systemRandomSource.fill).mockReset().mockImplementation(forbidden);
});

afterEach(() => {
  vi.restoreAllMocks();
  expect(forbidden).not.toHaveBeenCalled();
});

describe("durable local setup beacon preparation", () => {
  it("returns no contribution until the store commits, accepting an equal selected copy", async () => {
    const requested = scope();
    const source = rawSource();
    const commit = deferred<RandomSecret>();
    let created!: RandomSecret;
    const store = {
      getOrCreateSetupBeaconSecret: vi.fn((_scope: SetupBeaconScope, create: () => RandomSecret) => {
        created = create();
        return commit.promise;
      }),
      loadSetupBeaconSecret: forbidden,
    };
    const settled = vi.fn();
    const pending = prepareLocalBeaconContribution(requested, store, source);
    void pending.then(settled, settled);
    await Promise.resolve();

    expect(store.getOrCreateSetupBeaconSecret).toHaveBeenCalledExactlyOnceWith(requested, expect.any(Function));
    expect(store.getOrCreateSetupBeaconSecret.mock.contexts[0]).toBe(store);
    expect(source.fill).toHaveBeenCalledTimes(1);
    expect(settled).not.toHaveBeenCalled();

    commit.resolve(parseRandomSecret(created));
    const local = await pending;
    expect(settled).toHaveBeenCalledTimes(1);
    expect(local.secret).toEqual(created);
    expect(local.secret).not.toBe(created);
    expect(local.commitment).toEqual(beaconCommitment(requested.gameId, requested.round, 1, created));
    expect(Reflect.ownKeys(local).sort()).toEqual(["commitment", "secret"]);
    expect(Object.isFrozen(local)).toBe(true);
    expect(source.fill).toHaveBeenCalledTimes(1);
  });

  it("reuses the store's existing secret without a preliminary load or any entropy draw", async () => {
    const requested = scope();
    const stored = secretBytes();
    const store = {
      getOrCreateSetupBeaconSecret: vi.fn(async () => stored),
      loadSetupBeaconSecret: forbidden,
    };

    const local = await prepareLocalBeaconContribution(requested, store, { fill: forbidden });

    expect(store.getOrCreateSetupBeaconSecret).toHaveBeenCalledTimes(1);
    expect(local.secret).toEqual(stored);
    expect(local.secret.buffer).not.toBe(stored.buffer);
    expect(local.commitment).toEqual(beaconCommitment(requested.gameId, requested.round, 1, stored));
  });

  it("matches the independent v1 beacon commitment known-answer vector", async () => {
    const requested = scope(3, 2);
    requested.gameId = parseGameId(Uint8Array.from({ length: 16 }, (_, index) => index));
    requested.round = 3;
    const local = await prepareLocalBeaconContribution(requested, {
      async getOrCreateSetupBeaconSecret(_scope, create) { return create(); },
    }, rawSource());

    expect(local.secret).toEqual(secretBytes());
    expect(bytesToHex(local.commitment)).toBe("c732892833a79489b392f8af7ed2b6f816526f231b68611c0dcc4fb6b5bf6220");
  });

  it("hashes raw zero/full-ff bytes at every sender seat in ordered 3-, 4-, and 8-player rosters", async () => {
    for (const count of [3, 4, 8]) {
      for (let senderSeat = 0; senderSeat < count; senderSeat += 1) {
        for (const fill of [0, 0xff]) {
          const requested = scope(count, senderSeat);
          requested.roster.reverse();
          requested.round = Number.MAX_SAFE_INTEGER;
          const bytes = secretBytes(fill);
          const source = rawSource(bytes);
          const local = await prepareLocalBeaconContribution(requested, {
            async getOrCreateSetupBeaconSecret(_scope, create) { return create(); },
          }, source);

          expect(local.secret).toEqual(bytes);
          expect(local.commitment).toEqual(sha256(
            asciiToBytes("p2pcards/v1/beacon"), requested.gameId,
            encodeCanonical(requested.round), encodeCanonical(count - 1 - senderSeat), bytes,
          ));
          expect(source.fill).toHaveBeenCalledTimes(1);
        }
      }
    }
  });

  it("binds the commitment independently to game, round, sender seat, roster order, and source bytes", async () => {
    const requested = scope(4, 0);
    const store: DurableSetupBeaconSecretStore = {
      async getOrCreateSetupBeaconSecret(_scope, create) { return create(); },
    };
    const baseline = await prepareLocalBeaconContribution(requested, store, rawSource());
    const reversed = scope(4, 0);
    reversed.roster.reverse();
    const variants: [SetupBeaconScope, RandomSecret, number][] = [
      [{ ...requested, gameId: parseGameId(new Uint8Array(16).fill(0x42)) }, secretBytes(), 0],
      [{ ...requested, round: 24 }, secretBytes(), 0],
      [{ ...requested, sender: parseIdentityPublicKey(IDENTITIES[1]) }, secretBytes(), 1],
      [reversed, secretBytes(), 3],
      [requested, secretBytes(0x5b), 0],
    ];
    for (const [candidate, bytes, seat] of variants) {
      const source = rawSource(bytes);
      const local = await prepareLocalBeaconContribution(candidate, store, source);
      expect(local.commitment).toEqual(beaconCommitment(candidate.gameId, candidate.round, seat, bytes));
      expect(local.commitment).not.toEqual(baseline.commitment);
      expect(source.fill).toHaveBeenCalledTimes(1);
    }
  });

  it("uses the default protocol CSPRNG for exactly 32 bytes when no source is supplied", async () => {
    vi.mocked(systemRandomSource.fill).mockImplementation((target: Uint8Array) => {
      expect(target).toHaveLength(32);
      target.fill(0xa5);
    });
    const requested = scope();
    const local = await prepareLocalBeaconContribution(requested, {
      async getOrCreateSetupBeaconSecret(_scope, create) { return create(); },
    });

    expect(systemRandomSource.fill).toHaveBeenCalledTimes(1);
    expect(local.secret).toEqual(secretBytes(0xa5));
    expect(local.commitment).toEqual(beaconCommitment(requested.gameId, requested.round, 1, secretBytes(0xa5)));
  });

  it("preserves failed persistence and load rejections, including throw undefined", async () => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    for (const failure of [new Error("Transaction failed"), undefined, null]) {
      for (const createFirst of [false, true]) {
        const commit = deferred<RandomSecret>();
        const source = rawSource();
        const pending = prepareLocalBeaconContribution(requested, {
          getOrCreateSetupBeaconSecret(_scope, create) {
            if (createFirst) create();
            return commit.promise;
          },
        }, source);
        const rejected = expect(pending).rejects.toBe(failure);
        commit.reject(failure);
        await rejected;
        expect(source.fill).toHaveBeenCalledTimes(createFirst ? 1 : 0);
      }
      const store = {
        loadSetupBeaconSecret: vi.fn(async () => { throw failure; }),
        getOrCreateSetupBeaconSecret: forbidden,
      };
      await expect(restoreLocalBeaconContribution(requested, store, expected)).rejects.toBe(failure);
      expect(store.loadSetupBeaconSecret).toHaveBeenCalledTimes(1);
    }
  });

  it("returns no material and preserves source failures even when the store swallows or substitutes them", async () => {
    for (const failure of [new Error("Entropy unavailable"), undefined, null]) {
      for (const handling of ["propagate", "swallow", "replace"]) {
        const source = { fill: vi.fn((target: Uint8Array) => {
          expect(target).toHaveLength(32);
          target.fill(0xa5);
          throw failure;
        }) };
        const store: DurableSetupBeaconSecretStore = {
          async getOrCreateSetupBeaconSecret(_scope, create) {
            try { return create(); }
            catch (cause) {
              expect(cause).toBe(failure);
              if (handling === "swallow") return secretBytes();
              if (handling === "replace") throw new Error("Store substituted the error");
              throw cause;
            }
          },
        };
        await expect(prepareLocalBeaconContribution(scope(), store, source)).rejects.toBe(failure);
        expect(source.fill).toHaveBeenCalledTimes(1);
      }
    }
  });

  it("rejects repeated creation after a successful or failed attempt without another draw, even if swallowed", async () => {
    for (const firstFails of [false, true]) {
      for (const replaceError of [false, true]) {
        const failure = new Error("First draw failed");
        const source = rawSource();
        if (firstFails) source.fill.mockImplementation(() => { throw failure; });
        let repeated: unknown;
        const store: DurableSetupBeaconSecretStore = {
          async getOrCreateSetupBeaconSecret(_scope, create) {
            let selected = secretBytes();
            try { selected = create(); }
            catch (cause) { expect(cause).toBe(failure); }
            try { create(); }
            catch (cause) { repeated = cause; }
            expect(repeated).toBeInstanceOf(LocalBeaconSecretError);
            expect(repeated).toHaveProperty("code", "invalid_store_result");
            if (replaceError) throw new Error("Store substituted the repeat error");
            return selected;
          },
        };
        const pending = prepareLocalBeaconContribution(scope(), store, source);
        await expect(pending).rejects.toBe(repeated);
        expect(source.fill).toHaveBeenCalledTimes(1);
      }
    }
  });

  it("expires retained creators after creation, reuse, rejection, and malformed store results", async () => {
    for (const outcome of ["created", "existing", "rejected", "invalid"]) {
      let create!: () => RandomSecret;
      const source = rawSource();
      const failure = new Error("Commit failed");
      const pending = prepareLocalBeaconContribution(scope(), {
        async getOrCreateSetupBeaconSecret(_scope, callback) {
          create = callback;
          if (outcome === "created") return create();
          if (outcome === "rejected") throw failure;
          if (outcome === "invalid") return undefined as unknown as RandomSecret;
          return secretBytes();
        },
      }, source);
      if (outcome === "rejected") await expect(pending).rejects.toBe(failure);
      else if (outcome === "invalid") await expect(pending).rejects.toHaveProperty("code", "invalid_store_result");
      else expect((await pending).secret).toEqual(secretBytes());

      expect(() => create()).toThrow(LocalBeaconSecretError);
      expect(() => create()).toThrow("invalid_store_result");
      expect(source.fill).toHaveBeenCalledTimes(outcome === "created" ? 1 : 0);
    }
  });

  it("rejects selected-secret substitution and mutations of creator or RNG-owned bytes", async () => {
    for (const substitute of ["different", "creator", "entropy"]) {
      const source = rawSource();
      const store: DurableSetupBeaconSecretStore = {
        async getOrCreateSetupBeaconSecret(_scope, create) {
          const created = create();
          if (substitute === "different") return secretBytes(0x11);
          if (substitute === "creator") return created.fill(0x11);
          return parseRandomSecret(source.fill.mock.calls[0]![0].fill(0x11));
        },
      };
      await expect(prepareLocalBeaconContribution(scope(), store, source)).rejects.toMatchObject({
        name: "LocalBeaconSecretError", code: "invalid_store_result",
      });
      expect(source.fill).toHaveBeenCalledTimes(1);
    }
  });

  it("isolates generated, callback, persisted, source, and separately returned sensitive bytes", async () => {
    const requested = scope();
    const supplied = secretBytes();
    const source = rawSource(supplied);
    let created!: RandomSecret;
    let stored!: RandomSecret;
    const first = await prepareLocalBeaconContribution(requested, {
      async getOrCreateSetupBeaconSecret(_scope, create) {
        created = create();
        stored = parseRandomSecret(created);
        created.fill(0x11);
        source.fill.mock.calls[0]![0].fill(0x22);
        return stored;
      },
    }, source);
    const second = await prepareLocalBeaconContribution(requested, {
      async getOrCreateSetupBeaconSecret() { return stored; },
    }, { fill: forbidden });

    expect(first.secret).toEqual(supplied);
    for (const bytes of [created, stored, supplied, source.fill.mock.calls[0]![0], second.secret]) {
      expect(first.secret.buffer).not.toBe(bytes.buffer);
    }
    first.secret.fill(0x33);
    first.commitment.fill(0x44);
    expect(stored).toEqual(secretBytes());
    expect(supplied).toEqual(secretBytes());
    expect(created).toEqual(secretBytes(0x11));
    expect(source.fill.mock.calls[0]![0]).toEqual(secretBytes(0x22));
    stored.fill(0x55);
    expect(second.secret).toEqual(secretBytes());
    expect(second.commitment).toEqual(beaconCommitment(requested.gameId, requested.round, 1, supplied));
    expect(source.fill).toHaveBeenCalledTimes(1);
  });
});

describe("local setup beacon preparation guards", () => {
  it.each(["prepare", "restore"] as const)("checks retirement before accessing the %s store", async (operation) => {
    const access = vi.fn();
    const store = Object.defineProperties({}, {
      getOrCreateSetupBeaconSecret: { get: access },
      loadSetupBeaconSecret: { get: access },
    }) as DurableSetupBeaconSecretStore & SetupBeaconSecretReader;
    for (const failure of [new Error("Retired setup"), undefined, null]) {
      const guard = (): undefined => { throw failure; };
      const pending = operation === "prepare"
        ? prepareLocalBeaconContribution(scope(), store, { fill: forbidden }, guard)
        : restoreLocalBeaconContribution(scope(), store, parseHash256(new Uint8Array(32)), guard);
      await expect(pending).rejects.toBe(failure);
    }
    expect(access).not.toHaveBeenCalled();
  });

  it.each(["prepare", "restore"] as const)("rejects async and non-undefined %s guards without unhandled rejections", async (operation) => {
    const store = { getOrCreateSetupBeaconSecret: forbidden, loadSetupBeaconSecret: forbidden };
    for (const invalid of [
      null, 1, () => null, () => false, () => 1, () => ({}),
      async () => undefined, async () => { throw undefined; },
      () => ({ then(_resolve: unknown, reject: (cause: unknown) => void) { reject(new Error("Async guard")); } }),
    ]) {
      const guard = invalid as unknown as () => undefined;
      const pending = operation === "prepare"
        ? prepareLocalBeaconContribution(scope(), store, { fill: forbidden }, guard)
        : restoreLocalBeaconContribution(scope(), store, parseHash256(new Uint8Array(32)), guard);
      await expect(pending).rejects.toThrow(TypeError);
    }
  });

  it.each(["prepare", "restore"] as const)("rejects a guard that becomes asynchronous after %s storage, before hashing", async (operation) => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    const commitment = vi.spyOn(protocol, "beaconCommitment");
    let loaded = false;
    let create!: () => RandomSecret;
    const store = {
      async getOrCreateSetupBeaconSecret(_scope: SetupBeaconScope, callback: () => RandomSecret) {
        create = callback;
        loaded = true;
        return secretBytes();
      },
      async loadSetupBeaconSecret() { loaded = true; return secretBytes(); },
    };
    const guard = (() => loaded ? Promise.reject(undefined) : undefined) as () => undefined;
    const pending = operation === "prepare"
      ? prepareLocalBeaconContribution(requested, store, { fill: forbidden }, guard)
      : restoreLocalBeaconContribution(requested, store, expected, guard);
    await expect(pending).rejects.toThrow("synchronously return undefined");
    expect(commitment).not.toHaveBeenCalled();
    if (operation === "prepare") expect(() => create()).toThrow(LocalBeaconSecretError);
  });

  it("checks inside delayed creators and preserves retired guard failures if the store swallows or substitutes them", async () => {
    const commitment = vi.spyOn(protocol, "beaconCommitment");
    for (const failure of [new Error("Retired setup"), undefined, null]) {
      for (const handling of ["propagate", "swallow", "replace"]) {
        const gate = deferred<void>();
        let active = true;
        const pending = prepareLocalBeaconContribution(scope(), {
          async getOrCreateSetupBeaconSecret(_scope, create) {
            await gate.promise;
            try { return create(); }
            catch (cause) {
              expect(cause).toBe(failure);
              if (handling === "swallow") return secretBytes();
              if (handling === "replace") throw new Error("Substituted store error");
              throw cause;
            }
          },
        }, { fill: forbidden }, () => {
          if (!active) { active = true; throw failure; }
        });
        active = false;
        gate.resolve();
        await expect(pending).rejects.toBe(failure);
      }
    }
    expect(commitment).not.toHaveBeenCalled();
  });

  it("checks after entropy returns and publishes no contribution when the source retires setup", async () => {
    const commitment = vi.spyOn(protocol, "beaconCommitment");
    const failure = new Error("Retired by RNG");
    let active = true;
    const source = { fill: vi.fn((target: Uint8Array) => {
      target.fill(0x5a);
      active = false;
    }) };
    await expect(prepareLocalBeaconContribution(scope(), {
      async getOrCreateSetupBeaconSecret(_scope, create) { return create(); },
    }, source, () => { if (!active) throw failure; })).rejects.toBe(failure);
    expect(source.fill).toHaveBeenCalledTimes(1);
    expect(commitment).not.toHaveBeenCalled();
  });

  it.each(["created", "existing", "restore"] as const)("checks immediately after awaited %s storage before hashing or private output", async (operation) => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    const commitment = vi.spyOn(protocol, "beaconCommitment");
    const gate = deferred<RandomSecret>();
    const source = rawSource();
    const failure = new Error("Retired setup");
    let active = true;
    let selected = secretBytes();
    let create!: () => RandomSecret;
    const store = {
      getOrCreateSetupBeaconSecret: vi.fn((_scope: SetupBeaconScope, callback: () => RandomSecret) => {
        create = callback;
        if (operation === "created") selected = create();
        return gate.promise;
      }),
      loadSetupBeaconSecret: vi.fn(() => gate.promise),
      deleteSetupBeaconSecret: forbidden,
    };
    const guard = (): undefined => { if (!active) throw failure; };
    const pending = operation === "restore"
      ? restoreLocalBeaconContribution(requested, store, expected, guard)
      : prepareLocalBeaconContribution(requested, store, source, guard);
    active = false;
    gate.resolve(selected);
    await expect(pending).rejects.toBe(failure);
    expect(selected).toEqual(secretBytes());
    expect(commitment).not.toHaveBeenCalled();
    expect(source.fill).toHaveBeenCalledTimes(operation === "created" ? 1 : 0);
    expect(store.getOrCreateSetupBeaconSecret).toHaveBeenCalledTimes(operation === "restore" ? 0 : 1);
    expect(store.loadSetupBeaconSecret).toHaveBeenCalledTimes(operation === "restore" ? 1 : 0);
    if (operation !== "restore") expect(() => create()).toThrow(LocalBeaconSecretError);
  });

  it.each([false, true])("allows normal guarded preparation with independent entropy bytes, restored=%s", async (restored) => {
    const requested = scope();
    const events: string[] = [];
    let retained: Uint8Array | undefined;
    const source = { fill: vi.fn((target: Uint8Array) => {
      events.push("draw");
      retained = target;
      target.fill(0x5a);
    }) };
    const guard = (): undefined => { events.push("guard"); retained?.fill(0xff); };
    const local = await prepareLocalBeaconContribution(requested, {
      async getOrCreateSetupBeaconSecret(_scope, create) {
        return restored ? secretBytes() : create();
      },
    }, source, guard);
    expect(local.secret).toEqual(secretBytes());
    expect(local.commitment).toEqual(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    expect(source.fill).toHaveBeenCalledTimes(restored ? 0 : 1);
    if (!restored) {
      const draw = events.indexOf("draw");
      expect(events[draw - 1]).toBe("guard");
      expect(events[draw + 1]).toBe("guard");
    }
    expect(events.at(-1)).toBe("guard");
    const loaded = await restoreLocalBeaconContribution(requested, {
      async loadSetupBeaconSecret() { return local.secret; },
    }, local.commitment, guard);
    expect(loaded).toEqual(local);
    expect(loaded.secret.buffer).not.toBe(local.secret.buffer);
  });

  it.each(["prepare", "restore"] as const)("captures %s dependency methods once, before awaiting or passing control back to a guard", async (operation) => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    const gate = deferred<void>();
    const fill = rawSource().fill;
    const readFill = vi.fn(() => fill);
    const source = Object.defineProperty({}, "fill", { get: readFill, configurable: true }) as RandomSource;
    const selected = vi.fn(async function (this: typeof store, received: SetupBeaconScope, create?: () => RandomSecret) {
      expect(this).toBe(store);
      expect(received).toEqual(requested);
      await gate.promise;
      return create === undefined ? secretBytes() : create();
    });
    const readMethod = vi.fn(() => selected);
    const method = operation === "prepare" ? "getOrCreateSetupBeaconSecret" : "loadSetupBeaconSecret";
    const store = Object.defineProperty({}, method, { get: readMethod, configurable: true }) as DurableSetupBeaconSecretStore & SetupBeaconSecretReader;
    const guard = (): undefined => {
      if (readMethod.mock.calls.length > 0) {
        Object.defineProperty(store, method, { value: forbidden });
        Object.defineProperty(source, "fill", { value: forbidden });
      }
    };
    const pending = operation === "prepare"
      ? prepareLocalBeaconContribution(requested, store, source, guard)
      : restoreLocalBeaconContribution(requested, store, expected, guard);
    gate.resolve();
    const local = await pending;
    expect(local.secret).toEqual(secretBytes());
    expect(local.commitment).toEqual(expected);
    expect(readMethod).toHaveBeenCalledTimes(1);
    expect(readFill).toHaveBeenCalledTimes(operation === "prepare" ? 1 : 0);
    expect(selected).toHaveBeenCalledTimes(1);
    expect(fill).toHaveBeenCalledTimes(operation === "prepare" ? 1 : 0);
  });
});

describe("local setup beacon boundary validation", () => {
  it("classifies malformed returned secrets locally without fallback reads, creation, or RNG", async () => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    const throwingConstructor = Object.defineProperty(new Uint8Array(32), "constructor", {
      get() { throw undefined; },
    });
    const invalid: unknown[] = [
      undefined, null, [], {}, 1n, new Uint8Array(0), new Uint8Array(31), new Uint8Array(33),
      new Uint16Array(32), new Uint8ClampedArray(32), new ArrayBuffer(32),
      new DataView(new ArrayBuffer(32)), new (class extends Uint8Array {})(32),
      new Proxy(new Uint8Array(32), {}), throwingConstructor,
    ];
    for (const candidate of invalid) {
      const store = {
        getOrCreateSetupBeaconSecret: vi.fn(async () => candidate as RandomSecret),
        loadSetupBeaconSecret: vi.fn(async () => candidate as RandomSecret),
      };
      await expect(prepareLocalBeaconContribution(requested, store, { fill: forbidden })).rejects.toMatchObject({
        name: "LocalBeaconSecretError", code: "invalid_store_result",
      });
      await expect(restoreLocalBeaconContribution(requested, store, expected)).rejects.toMatchObject({
        name: "LocalBeaconSecretError", code: candidate === null ? "missing_secret" : "invalid_store_result",
      });
      expect(store.getOrCreateSetupBeaconSecret).toHaveBeenCalledTimes(1);
      expect(store.loadSetupBeaconSecret).toHaveBeenCalledTimes(1);
    }
  });

  it("uses intrinsic byte widths rather than forged length, byteLength, constructor, or slice metadata", async () => {
    const requested = scope();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, secretBytes()));
    const wide = Object.setPrototypeOf(new Uint16Array(32), Uint8Array.prototype) as Uint8Array;
    for (const candidate of [new Uint8Array(31), new Uint8Array(33), wide]) {
      const slice = vi.fn(() => secretBytes());
      Object.defineProperties(candidate, {
        length: { value: 32 }, byteLength: { value: 32 },
        constructor: { value: Uint8Array }, slice: { value: slice },
      });
      const store = {
        async getOrCreateSetupBeaconSecret() { return candidate as RandomSecret; },
        async loadSetupBeaconSecret() { return candidate as RandomSecret; },
      };
      await expect(prepareLocalBeaconContribution(requested, store, { fill: forbidden })).rejects.toHaveProperty(
        "code", "invalid_store_result",
      );
      await expect(restoreLocalBeaconContribution(requested, store, expected)).rejects.toHaveProperty(
        "code", "invalid_store_result",
      );
      expect(slice).not.toHaveBeenCalled();
    }
  });

  it("privately copies valid public fields and offset secrets without reading hostile byte metadata", async () => {
    const requested = scope();
    const original = snapshotSetupBeaconScope(requested);
    const backing = new Uint8Array(48).fill(0x5a);
    const stored = backing.subarray(8, 40) as RandomSecret;
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, stored));
    const digest = parseHash256(expected);
    const getter = vi.fn(() => { throw new Error("Hostile byte metadata accessed"); });
    for (const bytes of [requested.gameId, requested.sender, ...requested.roster, stored, expected]) {
      for (const key of ["length", "byteLength", "byteOffset", "buffer", "slice", Symbol.iterator]) {
        Object.defineProperty(bytes, key, { get: getter });
      }
    }
    const store = {
      getOrCreateSetupBeaconSecret: vi.fn(async (_scope: SetupBeaconScope) => stored),
      loadSetupBeaconSecret: vi.fn(async (_scope: SetupBeaconScope) => stored),
    };
    const prepared = await prepareLocalBeaconContribution(requested, store, { fill: forbidden });
    const restored = await restoreLocalBeaconContribution(requested, store, expected);

    expect(store.getOrCreateSetupBeaconSecret.mock.calls[0]![0]).toEqual(original);
    expect(store.loadSetupBeaconSecret.mock.calls[0]![0]).toEqual(original);
    for (const local of [prepared, restored]) {
      expect(local.secret).toEqual(secretBytes());
      expect(local.commitment).toEqual(digest);
      local.secret.fill(0);
      local.commitment.fill(0);
    }
    expect(backing).toEqual(new Uint8Array(48).fill(0x5a));
    expect(parseHash256(expected)).toEqual(digest);
    expect(getter).not.toHaveBeenCalled();
  });

  it("rejects non-strict or invalid scopes before touching either store or RNG", async () => {
    const requested = scope();
    const accessor = Object.defineProperty(scope(), "sender", { get: forbidden });
    const accessorRoster = scope().roster;
    Object.defineProperty(accessorRoster, "1", { get: forbidden });
    const shortGame = Object.defineProperties(new Uint8Array(15), {
      length: { value: 16 }, byteLength: { value: 16 }, slice: { value: () => requested.gameId },
    });
    const invalid: unknown[] = [
      null, undefined, [], Object.create(requested), accessor,
      ...Object.keys(requested).map((missing) => Object.fromEntries(
        Object.entries(requested).filter(([key]) => key !== missing),
      )),
      { ...requested, phase: "setup.rand" }, { ...requested, phase: "setup.keys" }, { ...requested, seat: 1 },
      ...[-1, -0, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1].map((round) => ({ ...requested, round })),
      { ...requested, gameId: shortGame }, { ...requested, sender: new Uint8Array(31) },
      { ...requested, sender: IDENTITIES[8] }, { ...requested, roster: null },
      { ...requested, roster: IDENTITIES.slice(0, 2) }, { ...requested, roster: IDENTITIES },
      { ...requested, roster: [IDENTITIES[0], IDENTITIES[1], IDENTITIES[1]] },
      { ...requested, roster: [IDENTITIES[0], IDENTITIES[1], new Uint8Array(32)] },
      { ...requested, roster: [IDENTITIES[0], IDENTITIES[1], ,] },
      { ...requested, roster: accessorRoster },
    ];
    const store = { getOrCreateSetupBeaconSecret: forbidden, loadSetupBeaconSecret: forbidden };
    for (const candidate of invalid) {
      await expect(prepareLocalBeaconContribution(candidate as SetupBeaconScope, store, { fill: forbidden })).rejects.toThrow();
      await expect(restoreLocalBeaconContribution(candidate as SetupBeaconScope, store, parseHash256(new Uint8Array(32)))).rejects.toThrow();
    }
  });

  it("requires the appropriate store method before drawing entropy or trying the other API", async () => {
    const expected = parseHash256(new Uint8Array(32));
    for (const store of [undefined, null, {}, { getOrCreateSetupBeaconSecret: 1, loadSetupBeaconSecret: null }]) {
      await expect(prepareLocalBeaconContribution(scope(), store as DurableSetupBeaconSecretStore, { fill: forbidden })).rejects.toThrow(TypeError);
      await expect(restoreLocalBeaconContribution(scope(), store as SetupBeaconSecretReader, expected)).rejects.toThrow(TypeError);
    }
    const reader = { loadSetupBeaconSecret: forbidden };
    const creator = { getOrCreateSetupBeaconSecret: forbidden };
    await expect(prepareLocalBeaconContribution(scope(), reader as unknown as DurableSetupBeaconSecretStore, { fill: forbidden })).rejects.toThrow(TypeError);
    await expect(restoreLocalBeaconContribution(scope(), creator as unknown as SetupBeaconSecretReader, expected)).rejects.toThrow(TypeError);
  });

  it("validates the accepted commitment's intrinsic bytes before loading a secret", async () => {
    const spoofed = Object.defineProperties(new Uint8Array(31), {
      length: { value: 32 }, byteLength: { value: 32 }, slice: { value: () => new Uint8Array(32) },
    });
    for (const candidate of [undefined, null, [], new Uint8Array(31), new Uint8Array(33), new Uint16Array(32), spoofed]) {
      await expect(restoreLocalBeaconContribution(scope(), {
        loadSetupBeaconSecret: forbidden,
      }, candidate as Hash256)).rejects.toThrow(ProtocolFieldError);
    }
  });

  it.each(["prepare", "restore"] as const)("snapshots caller and dependency scopes before awaiting %s", async (operation) => {
    const requested = scope(4, 1);
    const original = snapshotSetupBeaconScope(requested);
    const stored = secretBytes();
    const digest = parseHash256(beaconCommitment(original.gameId, original.round, 1, stored));
    const expected = parseHash256(digest);
    const gate = deferred<void>();
    const source = rawSource();
    let dependency!: SetupBeaconScope;
    const store = {
      getOrCreateSetupBeaconSecret: operation === "prepare"
        ? async (received: SetupBeaconScope, create: () => RandomSecret) => {
          dependency = received;
          await gate.promise;
          return create();
        } : forbidden,
      loadSetupBeaconSecret: operation === "restore"
        ? async (received: SetupBeaconScope) => {
          dependency = received;
          await gate.promise;
          return stored;
        } : forbidden,
    };
    const pending = operation === "prepare"
      ? prepareLocalBeaconContribution(requested, store, source)
      : restoreLocalBeaconContribution(requested, store, expected);

    expect(source.fill).not.toHaveBeenCalled();
    expect(dependency).toEqual(original);
    expect(dependency).not.toBe(requested);
    expect(Object.isFrozen(dependency)).toBe(true);
    expect(Object.isFrozen(dependency.roster)).toBe(true);
    for (const [key, value] of Object.entries({ gameId: original.gameId, round: 99, sender: original.sender, roster: [] })) {
      expect(Reflect.set(dependency, key, value)).toBe(false);
    }
    expect(Reflect.set(dependency.roster, "0", original.roster[1])).toBe(false);
    dependency.gameId.fill(0xaa);
    dependency.sender.set(original.roster[0]!);
    // A frozen roster still contains mutable bytes; rotate identities through those views.
    dependency.roster.forEach((identity, seat) => identity.set(original.roster[(seat + 1) % 4]!));
    expect(requested).toEqual(original);
    const changedDependency = snapshotSetupBeaconScope(dependency);

    requested.gameId.fill(0xbb);
    requested.sender.fill(0xcc);
    requested.roster.reverse();
    requested.roster[0]!.fill(0xdd);
    requested.gameId = parseGameId(new Uint8Array(16).fill(0xee));
    requested.round = 99;
    requested.sender = parseIdentityPublicKey(IDENTITIES[2]);
    requested.roster = scope().roster;
    expected.fill(0xff);
    expect(dependency).toEqual(changedDependency);

    gate.resolve();
    const local = await pending;
    expect(local.secret).toEqual(stored);
    expect(local.commitment).toEqual(digest);
    expect(source.fill).toHaveBeenCalledTimes(operation === "prepare" ? 1 : 0);
  });
});

describe("load-only local setup beacon restoration", () => {
  it("restores a matching accepted commitment with no RNG or get-or-create and independent returned copies", async () => {
    const requested = scope();
    const stored = secretBytes();
    const expected = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, stored));
    const digest = parseHash256(expected);
    const store = {
      loadSetupBeaconSecret: vi.fn(async (_scope: SetupBeaconScope) => stored),
      getOrCreateSetupBeaconSecret: forbidden,
      deleteSetupBeaconSecret: forbidden,
    };
    const first = await restoreLocalBeaconContribution(requested, store, expected);
    const second = await restoreLocalBeaconContribution(requested, store, expected);

    expect(store.loadSetupBeaconSecret).toHaveBeenCalledTimes(2);
    expect(store.loadSetupBeaconSecret.mock.contexts).toEqual([store, store]);
    for (const [received] of store.loadSetupBeaconSecret.mock.calls) {
      expect(received).toEqual(requested);
      expect(received).not.toBe(requested);
    }
    expect(first.secret).toEqual(stored);
    expect(first.commitment).toEqual(expected);
    expect(Object.isFrozen(first)).toBe(true);
    first.secret.fill(0);
    first.commitment.fill(0);
    expect(stored).toEqual(secretBytes());
    expect(expected).toEqual(digest);
    stored.fill(0x11);
    expected.fill(0x22);
    expect(second.secret).toEqual(secretBytes());
    expect(second.commitment).toEqual(digest);
  });

  it("reports missing, corrupt, and mismatched secrets without regeneration, retries, or writes", async () => {
    const requested = scope(4, 1);
    const stored = secretBytes();
    const accepted = parseHash256(beaconCommitment(requested.gameId, requested.round, 1, stored));
    const corrupt = secretBytes();
    corrupt[31] = corrupt[31]! ^ 1;
    const variants: [RandomSecret | null, Hash256, string][] = [
      [null, accepted, "missing_secret"],
      [corrupt, accepted, "commitment_mismatch"],
      [stored, parseHash256(beaconCommitment(parseGameId(new Uint8Array(16)), requested.round, 1, stored)), "commitment_mismatch"],
      [stored, parseHash256(beaconCommitment(requested.gameId, requested.round + 1, 1, stored)), "commitment_mismatch"],
      [stored, parseHash256(beaconCommitment(requested.gameId, requested.round, 2, stored)), "commitment_mismatch"],
      [stored, parseHash256(new Uint8Array(32)), "commitment_mismatch"],
    ];
    for (const [selected, expected, code] of variants) {
      const before = selected?.slice();
      const store = {
        loadSetupBeaconSecret: vi.fn(async () => selected),
        getOrCreateSetupBeaconSecret: forbidden,
        deleteSetupBeaconSecret: forbidden,
      };
      await expect(restoreLocalBeaconContribution(requested, store, expected)).rejects.toMatchObject({
        name: "LocalBeaconSecretError", code,
      });
      expect(store.loadSetupBeaconSecret).toHaveBeenCalledTimes(1);
      if (selected !== null) expect(selected).toEqual(before);
    }
  });
});

function scope(count = 3, senderSeat = 1) {
  const roster = IDENTITIES.slice(0, count).map(parseIdentityPublicKey);
  return {
    gameId: parseGameId(new Uint8Array(16).fill(0x41)),
    round: 0,
    roster,
    sender: parseIdentityPublicKey(roster[senderSeat]),
  } satisfies SetupBeaconScope;
}

function secretBytes(fill = 0x5a): RandomSecret {
  return parseRandomSecret(new Uint8Array(32).fill(fill));
}

function rawSource(bytes = secretBytes()) {
  return {
    fill: vi.fn((target: Uint8Array) => {
      expect(target).toHaveLength(32);
      target.set(bytes);
    }),
  } satisfies RandomSource;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
