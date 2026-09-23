import {
  RISTRETTO_SCALAR_ORDER,
  RistrettoPoint,
  scalarFromBigInt,
  type RandomSource,
  type RistrettoScalar,
} from "@p2pcards/crypto";
import * as deck from "@p2pcards/deck";
import { verifyGameKeyShare } from "@p2pcards/deck";
import { parseGameId, type ProofContext } from "@p2pcards/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  prepareLocalGameKeyShare,
  type DurableGameSecretStore,
} from "./local-key-share";

const CONTEXT: ProofContext = Object.freeze({
  gameId: parseGameId(new Uint8Array(16).fill(0x41)),
  round: 0,
  phase: "setup.keys",
});

afterEach(() => vi.restoreAllMocks());

describe("durable local game key setup", () => {
  it("does not construct or return KEY_SHARE material before the secret commit", async () => {
    let releaseCommit!: () => void;
    let reportSecretCreated!: () => void;
    const commitGate = new Promise<void>((resolve) => {
      releaseCommit = resolve;
    });
    const secretCreated = new Promise<void>((resolve) => {
      reportSecretCreated = resolve;
    });
    const source = scalarSequence([5, 7]);
    const store: DurableGameSecretStore = {
      async getOrCreateGameSecret(_gameId, create) {
        const secret = create();
        reportSecretCreated();
        await commitGate;
        return secret;
      },
    };
    let resolved = false;

    const pending = prepareLocalGameKeyShare(CONTEXT, store, source);
    void pending.then(() => {
      resolved = true;
    });
    await secretCreated;
    expect(source.calls).toBe(1);
    expect(resolved).toBe(false);

    releaseCommit();
    const local = await pending;
    expect(source.calls).toBe(2);
    expect(local.secret).toBe(5n);
    expect(verifyGameKeyShare(CONTEXT, local.share)).toBe(true);
    expect(resolved).toBe(true);
  });

  it("reuses a restored secret and creates only a fresh proof nonce", async () => {
    const restored = scalarFromBigInt(13n);
    const source = scalarSequence([9]);
    const store: DurableGameSecretStore = {
      async getOrCreateGameSecret() {
        return restored;
      },
    };

    const local = await prepareLocalGameKeyShare(CONTEXT, store, source);

    expect(source.calls).toBe(1);
    expect(local.secret).toBe(restored);
    expect(local.share.H.equals(RistrettoPoint.base().multiply(restored))).toBe(true);
    expect(verifyGameKeyShare(CONTEXT, local.share)).toBe(true);
  });

  it("does not return key material when persistence fails", async () => {
    const store: DurableGameSecretStore = {
      async getOrCreateGameSecret() {
        throw new Error("commit failed");
      },
    };

    await expect(prepareLocalGameKeyShare(CONTEXT, store, scalarSequence([2]))).rejects.toThrow(
      "commit failed",
    );
  });

  it("requires the exact setup phase and durable-store interface", async () => {
    await expect(
      prepareLocalGameKeyShare({ ...CONTEXT, phase: "setup.rand" }, {} as DurableGameSecretStore),
    ).rejects.toThrow(TypeError);
    await expect(
      prepareLocalGameKeyShare(CONTEXT, {} as DurableGameSecretStore),
    ).rejects.toThrow(TypeError);
    await expect(
      prepareLocalGameKeyShare({ ...CONTEXT, round: -1 }, {} as DurableGameSecretStore),
    ).rejects.toThrow(RangeError);
  });

  it("checks retirement before accessing the store and preserves thrown guard values", async () => {
    const access = vi.fn();
    const store = Object.defineProperty({}, "getOrCreateGameSecret", { get: access }) as DurableGameSecretStore;
    const source = scalarSequence([5, 7]);
    for (const failure of [new Error("Retired setup"), undefined, null]) {
      await expect(prepareLocalGameKeyShare(CONTEXT, store, source, () => { throw failure; })).rejects.toBe(failure);
    }
    expect(access).not.toHaveBeenCalled();
    expect(source.calls).toBe(0);
  });

  it("rejects non-synchronous or non-undefined guards without unhandled rejections", async () => {
    const store = { getOrCreateGameSecret: vi.fn() };
    const source = scalarSequence([5, 7]);
    for (const guard of [
      null, 1, () => null, () => false, () => 1, () => ({}),
      async () => undefined, async () => { throw undefined; },
      () => ({ then(_resolve: unknown, reject: (cause: unknown) => void) { reject(new Error("Async guard")); } }),
    ]) {
      await expect(prepareLocalGameKeyShare(CONTEXT, store, source, guard as unknown as () => undefined)).rejects.toThrow(TypeError);
    }
    expect(store.getOrCreateGameSecret).not.toHaveBeenCalled();
    expect(source.calls).toBe(0);
  });

  it("rejects a guard that becomes asynchronous after loading and expires the creator before any proof", async () => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    const source = scalarSequence([7]);
    let loaded = false;
    let create!: () => RistrettoScalar;
    const guard = (() => loaded ? Promise.reject(undefined) : undefined) as () => undefined;
    await expect(prepareLocalGameKeyShare(CONTEXT, {
      async getOrCreateGameSecret(_gameId, callback) {
        create = callback;
        loaded = true;
        return scalarFromBigInt(13n);
      },
    }, source, guard)).rejects.toThrow("synchronously return undefined");
    expect(proof).not.toHaveBeenCalled();
    expect(() => create()).toThrow(TypeError);
    expect(source.calls).toBe(0);
  });

  it("checks inside a delayed creator and preserves guard failure even if swallowed or replaced", async () => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    for (const failure of [new Error("Retired setup"), undefined, null]) {
      for (const handling of ["propagate", "swallow", "replace"]) {
        const gate = deferred<void>();
        const source = scalarSequence([5, 7]);
        let active = true;
        const pending = prepareLocalGameKeyShare(CONTEXT, {
          async getOrCreateGameSecret(_gameId, create) {
            await gate.promise;
            try { return create(); }
            catch (cause) {
              expect(cause).toBe(failure);
              if (handling === "swallow") return scalarFromBigInt(5n);
              if (handling === "replace") throw new Error("Substituted store error");
              throw cause;
            }
          },
        }, source, () => {
          if (!active) { active = true; throw failure; }
        });
        active = false;
        gate.resolve();
        await expect(pending).rejects.toBe(failure);
        expect(source.calls).toBe(0);
      }
    }
    expect(proof).not.toHaveBeenCalled();
  });

  it.each([false, true])("checks immediately after a pending key load/commit, created=%s, before proof construction", async (created) => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    const commit = deferred<RistrettoScalar>();
    const source = scalarSequence([5, 7]);
    const retired = new Error("Retired setup");
    let active = true;
    let selected = scalarFromBigInt(13n);
    let create!: () => RistrettoScalar;
    const store = {
      getOrCreateGameSecret: vi.fn((_gameId, callback: () => RistrettoScalar) => {
        create = callback;
        if (created) selected = create();
        return commit.promise;
      }),
      deleteGameSecret: vi.fn(),
    };
    const pending = prepareLocalGameKeyShare(CONTEXT, store, source, () => { if (!active) throw retired; });
    active = false;
    commit.resolve(selected);
    await expect(pending).rejects.toBe(retired);
    expect(proof).not.toHaveBeenCalled();
    expect(() => create()).toThrow(TypeError);
    expect(source.calls).toBe(created ? 1 : 0);
    expect(store.deleteGameSecret).not.toHaveBeenCalled();
  });

  it.each(["secret", "nonce"])("stops after a rejected zero %s draw retires setup, without a retry", async (stage) => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    const failure = new Error("Retired by RNG");
    let active = true;
    const source = { fill: vi.fn((target: Uint8Array) => {
      target.fill(0);
      active = false;
    }) };
    await expect(prepareLocalGameKeyShare(CONTEXT, {
      async getOrCreateGameSecret(_gameId, create) {
        return stage === "secret" ? create() : scalarFromBigInt(13n);
      },
    }, source, () => { if (!active) throw failure; })).rejects.toBe(failure);
    expect(source.fill).toHaveBeenCalledTimes(1);
    expect(proof).toHaveBeenCalledTimes(stage === "secret" ? 0 : 1);
  });

  it.each([false, true])("allows normal guarded preparation with unchanged scalar sampling, restored=%s", async (restored) => {
    const events: string[] = [];
    const values = restored ? [0, 7] : [0, 5, 0, 7];
    const source = { fill: vi.fn((target: Uint8Array) => {
      events.push("draw");
      target.fill(0);
      target[0] = values.shift()!;
    }) };
    const local = await prepareLocalGameKeyShare(CONTEXT, {
      async getOrCreateGameSecret(_gameId, create) {
        return restored ? scalarFromBigInt(13n) : create();
      },
    }, source, () => { events.push("guard"); });
    expect(source.fill).toHaveBeenCalledTimes(restored ? 2 : 4);
    expect(local.secret).toBe(restored ? 13n : 5n);
    expect(verifyGameKeyShare(CONTEXT, local.share)).toBe(true);
    expect(Object.isFrozen(local)).toBe(true);
    events.forEach((event, index) => {
      if (event === "draw") {
        expect(events[index - 1]).toBe("guard");
        expect(events[index + 1]).toBe("guard");
      }
    });
    expect(events.at(-1)).toBe("guard");
  });

  it("snapshots the proof context, dependency methods, and independent store/RNG bytes", async () => {
    const requested = { ...CONTEXT, gameId: parseGameId(CONTEXT.gameId) };
    const gate = deferred<void>();
    const forbidden = vi.fn(() => { throw new Error("Replaced dependency called"); });
    let dependencyGame!: Uint8Array;
    let calls = 0;
    let retained!: Uint8Array;
    const fill = vi.fn(function (this: RandomSource, target: Uint8Array) {
      expect(this).toBe(source);
      retained = target;
      target.fill(0);
      target[0] = ++calls === 1 ? 5 : 7;
    });
    const source = { fill };
    const getOrCreate = vi.fn(async function (this: DurableGameSecretStore, gameId: Uint8Array, create: () => RistrettoScalar) {
      expect(this).toBe(store);
      dependencyGame = gameId;
      await gate.promise;
      return create();
    });
    const store = { getOrCreateGameSecret: getOrCreate };
    const pending = prepareLocalGameKeyShare(requested, store, source, () => { retained?.fill(0xff); });
    expect(dependencyGame).not.toBe(requested.gameId);
    dependencyGame.fill(0x11);
    expect(requested.gameId).toEqual(CONTEXT.gameId);
    requested.gameId.fill(0x22);
    requested.round = 99;
    requested.phase = "setup.rand";
    source.fill = forbidden;
    store.getOrCreateGameSecret = forbidden;
    gate.resolve();
    const local = await pending;
    expect(local.secret).toBe(5n);
    expect(verifyGameKeyShare(CONTEXT, local.share)).toBe(true);
    expect(fill).toHaveBeenCalledTimes(2);
    expect(getOrCreate).toHaveBeenCalledTimes(1);
    expect(forbidden).not.toHaveBeenCalled();
  });

  it("rejects malformed, zero, noncanonical, and substituted stored scalars before any proof", async () => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    for (const candidate of [undefined, null, false, 5, "5", {}, Object(5n), 0n, -1n, RISTRETTO_SCALAR_ORDER]) {
      const source = scalarSequence([7]);
      await expect(prepareLocalGameKeyShare(CONTEXT, {
        async getOrCreateGameSecret() { return candidate as RistrettoScalar; },
      }, source)).rejects.toThrow(TypeError);
      expect(source.calls).toBe(0);
    }
    const source = scalarSequence([5, 7]);
    await expect(prepareLocalGameKeyShare(CONTEXT, {
      async getOrCreateGameSecret(_gameId, create) {
        expect(create()).toBe(5n);
        return scalarFromBigInt(13n);
      },
    }, source)).rejects.toThrow(TypeError);
    expect(source.calls).toBe(1);
    expect(proof).not.toHaveBeenCalled();
  });

  it("preserves creator failures including undefined when the store swallows or substitutes them", async () => {
    const proof = vi.spyOn(deck, "createGameKeyShare");
    for (const failure of [new Error("Entropy unavailable"), undefined, null]) {
      for (const handling of ["propagate", "swallow", "replace"]) {
        const source = { fill: vi.fn(() => { throw failure; }) };
        await expect(prepareLocalGameKeyShare(CONTEXT, {
          async getOrCreateGameSecret(_gameId, create) {
            try { return create(); }
            catch (cause) {
              expect(cause).toBe(failure);
              if (handling === "swallow") return scalarFromBigInt(5n);
              if (handling === "replace") throw new Error("Substituted store error");
              throw cause;
            }
          },
        }, source)).rejects.toBe(failure);
        expect(source.fill).toHaveBeenCalledTimes(1);
      }
    }
    expect(proof).not.toHaveBeenCalled();
  });

  it("rejects repeated creation after success or failure without a second draw, even if swallowed", async () => {
    for (const firstFails of [false, true]) {
      for (const replaceError of [false, true]) {
        const source = { fill: vi.fn((target: Uint8Array) => {
          if (firstFails) throw undefined;
          target.fill(0);
          target[0] = 5;
        }) };
        let repeated: unknown;
        const pending = prepareLocalGameKeyShare(CONTEXT, {
          async getOrCreateGameSecret(_gameId, create) {
            let selected = scalarFromBigInt(5n);
            try { selected = create(); } catch { /* Deliberately swallowed by the store. */ }
            try { create(); } catch (cause) { repeated = cause; }
            expect(repeated).toBeInstanceOf(TypeError);
            if (replaceError) throw new Error("Substituted store error");
            return selected;
          },
        }, source);
        await expect(pending).rejects.toBe(repeated);
        expect(source.fill).toHaveBeenCalledTimes(1);
      }
    }
  });

  it("expires retained creators after creation, reuse, rejection, and invalid store results", async () => {
    for (const outcome of ["created", "existing", "rejected", "invalid"]) {
      let create!: () => RistrettoScalar;
      const source = scalarSequence([5, 7]);
      const pending = prepareLocalGameKeyShare(CONTEXT, {
        async getOrCreateGameSecret(_gameId, callback) {
          create = callback;
          if (outcome === "created") return create();
          if (outcome === "rejected") throw undefined;
          if (outcome === "invalid") return 0n as RistrettoScalar;
          return scalarFromBigInt(13n);
        },
      }, source);
      if (outcome === "rejected") await expect(pending).rejects.toBeUndefined();
      else if (outcome === "invalid") await expect(pending).rejects.toThrow(TypeError);
      else expect(verifyGameKeyShare(CONTEXT, (await pending).share)).toBe(true);
      const draws = source.calls;
      expect(() => create()).toThrow(TypeError);
      expect(() => create()).toThrow(TypeError);
      expect(source.calls).toBe(draws);
    }
  });

  it("preserves a swallowed expired-creator failure during proof preparation without returning material", async () => {
    let create!: () => RistrettoScalar;
    const source = { fill: vi.fn((target: Uint8Array) => {
      expect(() => create()).toThrow("creator invocation");
      target.fill(0);
      target[0] = 7;
    }) };
    await expect(prepareLocalGameKeyShare(CONTEXT, {
      async getOrCreateGameSecret(_gameId, callback) {
        create = callback;
        return scalarFromBigInt(13n);
      },
    }, source)).rejects.toThrow("creator invocation");
    expect(source.fill).toHaveBeenCalledTimes(1);
  });
});

function scalarSequence(values: readonly number[]): RandomSource & { readonly calls: number } {
  let calls = 0;
  return {
    get calls() {
      return calls;
    },
    fill(target) {
      const value = values[calls];
      if (value === undefined) {
        throw new Error("Test scalar source exhausted");
      }
      calls += 1;
      target.fill(0);
      target[0] = value;
    },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((yes) => { resolve = yes; });
  return { promise, resolve };
}
