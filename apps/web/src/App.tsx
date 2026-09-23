import { LiveSaskuRound } from "./LiveSaskuRound";
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";

import type { BrowserLobbyActions } from "./lobby-types";

export function App({ controller }: { readonly controller: BrowserLobbyActions }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const [invitation, setInvitation] = useState(state.pendingInvitation);
  const [relays, setRelays] = useState("");
  const [copyStatus, setCopyStatus] = useState("");
  const [copySource, setCopySource] = useState("");
  const inviteField = useRef<HTMLInputElement>(null);
  const roundHeading = useRef<HTMLDivElement>(null);
  const playing = Boolean(state.game);
  useEffect(() => { if (playing) { roundHeading.current?.focus({ preventScroll: true }); window.scrollTo({ top: 0 }); } }, [playing]);
  const busy = state.busy !== null;
  const room = state.room;
  const readyCount = room?.seats.filter((seat) => seat.ready).length ?? 0;
  const act = (operation: Promise<void>): void => { void operation.catch(() => undefined); };
  const join = (event: FormEvent): void => {
    event.preventDefault();
    act(controller.join(invitation, relays));
  };
  const copyInvite = async (): Promise<void> => {
    if (room === null) { return; }
    try {
      await navigator.clipboard.writeText(room.invitation);
      setCopySource(room.invitation);
      setCopyStatus("Invitation copied.");
    } catch {
      if (inviteField.current?.value === room.invitation) { inviteField.current.focus(); inviteField.current.select(); }
      setCopySource(room.invitation);
      setCopyStatus("Link selected. Use your browser's copy command.");
    }
  };

  return (
    <main className={`shell${playing ? " shell--playing" : room === null ? " shell--welcome" : ""}`}>
      {state.error !== null && <div className="notice notice--error" role="alert"><strong>Something needs attention.</strong> {state.error}</div>}

      {state.game && controller.playAction && <div ref={roundHeading} tabIndex={-1} className="live-focus"><LiveSaskuRound view={state.game} act={intent => controller.playAction!(intent)} /></div>}
      {room === null ? (
        <section className="welcome" aria-labelledby="welcome-title">
          <div className="welcome__copy">
            <p className="eyebrow">Tablefolk · Sasku</p>
            <h1 id="welcome-title">Play Sasku<br /><em>together.</em></h1>
            <p className="lede">A four-player partnership trick-taking game. Bid for trump, play nine tricks, and score with your partner.</p>
            <div className="welcome__links">
              <a className="reference-link" href="./how-it-works.html">How it works <span aria-hidden="true">→</span></a>
              <a className="reference-link" href="./scoring.html">Scoring reference <span aria-hidden="true">→</span></a>
            </div>
          </div>
          <div className="entry-panel">
            <h2>Start a game</h2>
            <button className="button button--primary" disabled={busy || state.identity === null} onClick={() => act(controller.create(relays))}>
              {state.busy === "hosting" ? "Opening table..." : "Open a table"}<span aria-hidden="true">+</span>
            </button>
            <div className="entry-divider"><span>or join a table</span></div>
            <form onSubmit={join}>
              <label htmlFor="invitation">Invitation link</label>
              <textarea id="invitation" value={invitation} onChange={(event) => setInvitation(event.target.value)} required maxLength={4096}
                placeholder="Paste the invitation from your host" rows={2} disabled={busy} autoCapitalize="none" spellCheck={false} />
              <button className="button button--secondary" disabled={busy || state.identity === null || invitation.trim() === ""}>
                {state.busy === "joining" ? "Joining table..." : "Join this table"}
              </button>
            </form>
            <details className="settings">
              <summary>Connection settings</summary>
              <label htmlFor="relay-urls">Custom Nostr relays <span className="optional">Optional</span></label>
              <textarea id="relay-urls" value={relays} onChange={(event) => setRelays(event.target.value)} rows={3} disabled={busy}
                maxLength={10_240} placeholder="Automatic public relays when blank" autoCapitalize="none" spellCheck={false} />
              <p>One URL per line, up to five. Use the same custom list on every device. Public relays may have their own access policies.</p>
              <p>STUN is configured. TURN is not; some restricted networks may not connect.</p>
              <p>Multiplayer is experimental. All four players must stay connected, and the shuffle proof backend awaits independent review.</p>
              <p>Invitations stay in the URL fragment. Share yours only with the people you want at the table.</p>
            </details>
          </div>
        </section>
      ) : (
        <details className={`table-settings${playing ? " table-settings--playing" : ""}`} open={playing ? undefined : true}>
        <summary>Table & connections <span>{state.peers.filter(peer => peer.state === "authenticated").length} / 3 connected</span></summary>
        <section className="lobby" aria-labelledby="lobby-title">
          <div className="lobby-heading">
            <div><p className="eyebrow">{room.isHost ? "Your table" : "An invited table"}</p><h1 id="lobby-title">{state.phase === "agreed" ? "A lobby, agreed." : "Room for four."}</h1></div>
            <button className="button button--quiet" onClick={() => act(controller.leave())} disabled={state.busy === "leaving"}>Leave table</button>
          </div>
          <div className="lobby-layout">
            <div className="table-panel">
              <div className="table-caption"><span>Four-player Sasku</span><span aria-live="polite">{room.seats.length} / 4 seated</span></div>
              <div className="felt-table" aria-label="Table seats">
                <div className="table-seal" aria-hidden="true"><span>P2P</span><i>{"\u2663"}</i><small>Sasku</small></div>
                {Array.from({ length: 4 }, (_, index) => {
                  const seat = room.seats[index];
                  return <div className={`seat seat--${index + 1}${seat === undefined ? " seat--empty" : ""}`} key={index}>
                    <span className="seat__number">0{index + 1}</span>
                    {seat === undefined ? <><h3>Open seat</h3><p>Waiting for an invitation to arrive.</p></> : <>
                      <h3>{seat.isSelf ? "You" : `Player ${index + 1}`} {seat.isHost && <span className="seat__host">Host</span>}</h3>
                      <details className="seat-identity"><summary>Identity</summary><p className="seat__fingerprint">{seat.fingerprint}</p></details>
                      <p className="seat__connection"><span className={seat.connected ? "status-dot status-dot--verified" : "status-dot"} aria-hidden="true" />{seat.isSelf ? "This browser" : seat.connected ? "Identity verified" : "Not connected"}</p>
                      <span className={`vote ${seat.ready ? "vote--ready" : ""}`}>{seat.ready ? "Ready vote saved" : "Not marked ready"}</span>
                    </>}
                  </div>;
                })}
              </div>
            </div>
            <aside className="lobby-ledger" aria-label="Invitation and lobby agreement">
              <p className="eyebrow">The table ledger</p>
              <h2>{state.phase === "agreed" ? "Four signatures. One roster." : "Bring everyone together."}</h2>
              <label htmlFor="share-invitation">Share this invitation</label>
              <input id="share-invitation" ref={inviteField} readOnly value={room.invitation} onFocus={() => inviteField.current?.select()} />
              <button className="button button--secondary" onClick={() => { void copyInvite(); }}>Copy invitation</button>
              <p className="copy-status" role="status">{copySource === room.invitation ? copyStatus : ""}</p>
              <div className="agreement-status" aria-live="polite">
                <strong>{readyCount} of 4 readiness votes</strong>
                <p>{state.phase === "agreed" ? "The roster and first-round rules are signed. Each player can now start the round." : room.ownReady ? "Your signed vote is saved. Waiting for the remaining players." : "Wait for all four identities and their lobby histories, then sign your readiness vote."}</p>
              </div>
              {state.phase !== "agreed" && <button className="button button--primary" disabled={!room.canReady || busy} onClick={() => act(controller.markReady())}>
                {state.busy === "ready" ? "Saving your vote..." : room.ownReady ? "Your vote is saved" : "Mark ready"}
              </button>}
              {state.phase === "agreed" && !state.game && controller.startRound && <button className="button button--primary" onClick={() => act(controller.startRound!())}>Play first round</button>}
              <p className="privacy-note">First round: player 4 deals, player 1 opens, nine cards per player in seat order. Your ready vote accepts this policy and the Sasku rules.</p>

              <details className="settings"><summary>Signed roster</summary><p>Game ID</p><code>{room.gameId}</code><p>Roster hash</p><code>{room.rosterHash ?? "Waiting for the host's signed roster"}</code></details>
            </aside>
          </div>
          <details className="diagnostics" open={state.peers.some(({ state }) => state !== "authenticated")}>
            <summary>Connection diagnostics <span>{state.peers.filter(({ state }) => state === "authenticated").length} verified links</span></summary>
            <div className="diagnostics__columns">
              <div><h3>Peer links</h3>{state.peers.length === 0 ? <p>No peer connections yet. Guests connect after opening your invitation.</p> : <ul className="connection-list">{state.peers.map((peer) => <li key={peer.publicKey}>
                <div><strong>{peer.fingerprint}</strong><span>{peer.state === "authenticated" ? "Identity verified" : peer.state} / {peer.path} path</span></div>
                <button className="button button--quiet" onClick={() => act(controller.retryPeer(peer.publicKey))} disabled={busy}>Retry connection</button>
              </li>)}</ul>}</div>
              <div><h3>Signaling relays</h3>{state.relays.length === 0 ? <p>No active relay subscriptions.</p> : <ul className="relay-list">{state.relays.map((relay) => <li key={relay.url}><span>{relay.url}</span><strong>{relay.state}</strong>{relay.error !== null && <small>{relay.error}</small>}</li>)}</ul>}<p className="privacy-note">Relays carry encrypted signaling, not game messages. TURN is not configured.</p></div>
            </div>
            {state.events.length > 0 && <ol className="event-log" aria-label="Recent connection events">{state.events.map((event, index) => <li key={`${index}:${event}`}>{event}</li>)}</ol>}
          </details>
        </section>
        </details>
      )}

    </main>
  );
}
