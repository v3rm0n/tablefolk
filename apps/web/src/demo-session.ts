import { InMemorySignalingNetwork } from "@p2pcards/transport";

import { BrowserLobbyController } from "./lobby-controller";

/** Four isolated identities using the normal lobby and round engines in one page. */
export class DemoSession {
  readonly controllers: readonly BrowserLobbyController[];
  #operation: Promise<void> | null = null;

  constructor(baseUrl: string) {
    const network = new InMemorySignalingNetwork();
    this.controllers = Array.from({ length: 4 }, (_, index) => new BrowserLobbyController({
      baseUrl,
      storage: { databaseName: `p2pcards-demo-player-${index + 1}` },
      createSignaling: () => network.createAdapter(),
      createPeerConnection: (_remote, configuration) => new RTCPeerConnection({ ...configuration, iceServers: [] }),
      manageHistory: false,
    }));
  }

  start(): Promise<void> {
    if (this.#operation !== null) return this.#operation;
    const operation = this.#open();
    this.#operation = operation;
    void operation.finally(() => { if (this.#operation === operation) this.#operation = null; }).catch(() => undefined);
    return operation;
  }

  async #open(): Promise<void> {
    await Promise.all(this.controllers.map(controller => controller.leave()));
    await Promise.all(this.controllers.map(controller => controller.initialize()));
    const host = this.controllers[0]!;
    await host.create();
    const invitation = host.getSnapshot().room?.invitation;
    if (!invitation) throw new Error("The demo table did not produce an invitation");
    for (const guest of this.controllers.slice(1)) await guest.join(invitation);
  }

  async dispose(): Promise<void> {
    await Promise.all(this.controllers.map(controller => controller.dispose()));
  }
}
