import { asciiToBytes } from "@p2pcards/crypto";

export const DOMAIN_SEPARATORS = Object.freeze({
  room: "p2pcards/v1/room",
  channel: "p2pcards/v1/chan",
  message: "p2pcards/v1/msg",
  card: "p2pcards/v1/card",
  proofOfPossession: "p2pcards/v1/pop",
  decryptionShare: "p2pcards/v1/dleq",
  shuffle: "p2pcards/v1/shuffle",
  beacon: "p2pcards/v1/beacon",
} as const);

export type DomainPurpose = keyof typeof DOMAIN_SEPARATORS;

export function domainSeparator(purpose: DomainPurpose): Uint8Array {
  return asciiToBytes(DOMAIN_SEPARATORS[purpose]);
}
