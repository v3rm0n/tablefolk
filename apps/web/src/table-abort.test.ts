import { expect, it } from "vitest";

import { TableAbortVote } from "./table-abort";

it("requires each connected player to vote for the same set of disconnected seats", () => {
  const votes = new TableAbortVote();
  expect(votes.available).toBe(false);
  votes.update(0b0100);
  expect(votes.available).toBe(true);
  votes.receive(0, 0b0100);
  votes.receive(1, 0b0100);
  votes.receive(2, 0b0100);
  votes.receive(3, 0b0010);
  expect(votes.count).toBe(2);
  expect(votes.ended).toBe(false);
  votes.receive(1, 0b0100);
  votes.receive(3, 0b0100);
  expect(votes.ended).toBe(true);

  votes.update(0);
  votes.update(0b0100);
  expect(votes.count).toBe(0);
  expect(votes.ended).toBe(false);
  votes.update(0b1110);
  expect(votes.available).toBe(false);
});

it("requires independent confirmations from all prior voters before informing a returning seat", () => {
  const votes = new TableAbortVote();
  expect(votes.confirm(0, 0b0100)).toBe(false);
  expect(votes.confirm(2, 0b0100)).toBe(false);
  expect(votes.confirm(1, 0b1000)).toBe(false);
  expect(votes.confirm(1, 0b0100)).toBe(false);
  expect(votes.confirm(3, 0b0100)).toBe(true);
});
