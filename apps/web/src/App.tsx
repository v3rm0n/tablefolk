import { TranscriptControls } from "./TranscriptControls";
import { LiveSaskuRound } from "./LiveSaskuRound";
import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent } from "react";

import type { BrowserLobbyActions } from "./lobby-types";

export function App({ controller, demo = false }: { readonly controller: BrowserLobbyActions; readonly demo?: boolean }) {
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
  const invited = room === null && state.pendingInvitation !== "" && window.location.hash !== "";
  const joining = room !== null && !room.isHost && !room.seats.some(seat => seat.isSelf);
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
      setCopyStatus("Copied to clipboard.");
    } catch {
      if (inviteField.current?.value === room.invitation) { inviteField.current.focus(); inviteField.current.select(); }
      setCopySource(room.invitation);
      setCopyStatus("Link selected — press Copy.");
    }
  };

  return (
    <main className={`shell${playing ? " shell--playing" : room === null ? " shell--welcome" : ""}`}>
      {state.error !== null && <div className="notice notice--error" role="alert">{state.error}</div>}

      {state.game && controller.playAction && <div ref={roundHeading} tabIndex={-1} className="live-focus"><LiveSaskuRound view={state.game} act={intent => controller.playAction!(intent)} /></div>}
      {room === null ? (
        <section className={`welcome${invited ? " welcome--invited" : ""}`} aria-labelledby="welcome-title">
          <div className="welcome__copy">
            {invited ? <>
              <p className="eyebrow">Table invitation</p>
              <h1 id="welcome-title">You're invited to Sasku.</h1>
              <p className="lede">Join this four-player table in your browser.</p>
            </> : <>
              <p className="eyebrow">Tablefolk · Peer-to-peer cards</p>
              <h1 id="welcome-title">Sasku</h1>
              <p className="lede">Estonian four-player partnership trick-taking. Bid for trump, play nine tricks with a 36-card deck, and race to 12 game points.</p>
              <nav className="welcome__links" aria-label="Guides and demo">
                <a className="reference-link" href="./demo.html">Four-player demo</a>
                <a className="reference-link" href="./scoring.html">Scoring reference</a>
                <a className="reference-link" href="./how-it-works.html">How it works</a>
              </nav>
            </>}
          </div>
          <div className="entry-panel">
            {invited ? <>
              <button className="button button--primary" disabled={busy || state.identity === null} onClick={() => act(controller.join(invitation, relays))}>
                {state.busy === "joining" ? "Joining table…" : "Join this table"}
              </button>
              <button className="entry-alternative" disabled={busy || state.identity === null} onClick={() => act(controller.create(relays))}>Start a new game</button>
            </> : <>
              <button className="button button--primary" disabled={busy || state.identity === null} onClick={() => act(controller.create(relays))}>
                {state.busy === "hosting" ? "Opening table…" : "Start a game"}
              </button>
              <div className="entry-divider"><span>or join with a link</span></div>
              <form onSubmit={join}>
                <label htmlFor="invitation">Invitation link</label>
                <textarea id="invitation" value={invitation} onChange={(event) => setInvitation(event.target.value)} required maxLength={4096}
                  placeholder="https://…/#g=…" rows={2} disabled={busy} autoCapitalize="none" spellCheck={false} />
                <button className="button button--secondary" disabled={busy || state.identity === null || invitation.trim() === ""}>
                  {state.busy === "joining" ? "Joining table…" : "Join this table"}
                </button>
              </form>
            </>}
            <details className="settings">
              <summary>Connection settings</summary>
              <label htmlFor="relay-urls">Custom Nostr relays <span className="optional">(optional)</span></label>
              <textarea id="relay-urls" value={relays} onChange={(event) => setRelays(event.target.value)} rows={3} disabled={busy}
                maxLength={10_240} placeholder="Leave blank for default public relays" autoCapitalize="none" spellCheck={false} />
              <p>Up to five <code>wss://</code> URLs, one per line. All four players must use the same relays.</p>
              <p>Browsers connect directly over WebRTC (STUN only, no TURN). All four players must remain online during the match.</p>
            </details>
          </div>
        </section>
      ) : (
        <details className={`table-settings${playing ? " table-settings--playing" : ""}`} open={playing ? undefined : true}>
        <summary>Table &amp; connections <span>{state.peers.filter(peer => peer.state === "authenticated").length} / 3 peers verified</span></summary>
        <section className="lobby" aria-labelledby="lobby-title">
          <div className="lobby-heading">
            <div>
              <p className="eyebrow">{playing ? "Active table" : "Lobby"}</p>
              <h1 id="lobby-title">Sasku</h1>
            </div>
            {!demo && <button className="button button--quiet" onClick={() => act(controller.leave().then(() => setInvitation("")))} disabled={state.busy === "leaving"}>Leave table</button>}
          </div>
          <div className="lobby-layout">
            <div className="table-panel">
              <div className="table-caption" aria-live="polite">{joining ? <span className="joining-status" role="status"><span className="loading-spinner" aria-hidden="true" />Connecting to host…</span> : `${room.seats.length} / 4 seated`}</div>
              <div className="felt-table" aria-label="Table seats">
                {Array.from({ length: 4 }, (_, index) => {
                  const seat = room.seats[index];
                  const partnership = index % 2 === 0 ? "Team 1 + 3" : "Team 2 + 4";
                  return <div className={`seat seat--${index + 1}${seat === undefined ? " seat--empty" : ""}${seat?.isSelf ? " seat--self" : ""}`} key={index}>
                    <div className="seat__header">
                      <span className="seat__number">Seat {index + 1} · {partnership}</span>
                      {seat?.isHost && <span className="seat__host">Host</span>}
                    </div>
                    {seat === undefined ? <h3>{joining ? "Connecting…" : "Open seat"}</h3> : <>
                      <h3>{seat.isSelf ? "You" : `Player ${index + 1}`}</h3>
                      <p className="seat__connection"><span className={seat.connected ? "status-dot status-dot--verified" : "status-dot"} aria-hidden="true" />{seat.isSelf ? "This browser" : seat.connected ? "Connected" : "Connecting…"}</p>
                      <details className="seat-identity"><summary>Key fingerprint</summary><p className="seat__fingerprint">{seat.fingerprint}</p></details>
                      <span className={`vote ${seat.ready ? "vote--ready" : ""}`}>{seat.ready ? "Ready" : "Not ready"}</span>
                    </>}
                  </div>;
                })}
              </div>
            </div>
            <aside className="lobby-actions" aria-label={demo ? "Readiness" : "Invitation and readiness"}>
              {demo ? <p className="demo-lobby-note">All four seats run locally in this tab. Use the tabs above to inspect any player.</p> : <>
                <label htmlFor="share-invitation">Share this invitation</label>
                <input id="share-invitation" ref={inviteField} readOnly value={room.invitation} onFocus={() => inviteField.current?.select()} />
                <button className="button button--secondary" onClick={() => { void copyInvite(); }}>Copy invitation link</button>
                <p className="copy-status" role="status">{copySource === room.invitation ? copyStatus : ""}</p>
              </>}
              {!playing && <div className="agreement-status" aria-live="polite">
                <strong>{readyCount} of 4 ready</strong>
                <p>{!room.ownReady ? "Mark yourself ready when you want to start." : room.seats.length < 4 ? "Send the invitation link to fill the remaining seats." : readyCount < 4 ? "Waiting for all players to mark ready." : "All four ready — dealing the first hand…"}</p>
              </div>}
              {!state.game && <button className="button button--secondary" disabled={busy} onClick={() => act(controller.setReady(!room.ownReady))}>{room.ownReady ? "Not ready" : "Ready"}</button>}
            </aside>
          </div>
          {!demo && <details className="diagnostics">
            <summary>Network diagnostics <span>{state.peers.filter(({ state }) => state === "authenticated").length} verified links</span></summary>
            <div className="roster-details">
              <div><span>Game ID</span><code>{room.gameId}</code></div>
              <div><span>Roster hash</span><code>{room.rosterHash ?? "Waiting for 4 seats…"}</code></div>
            </div>
            <div className="diagnostics__columns">
              <div><h3>Peer connections</h3>{state.peers.length === 0 ? <p>No peers connected yet.</p> : <ul className="connection-list">{state.peers.map((peer) => <li key={peer.publicKey}>
                <div><strong>{peer.fingerprint}</strong><span>{peer.state === "authenticated" ? "Verified" : peer.state} · {peer.path}</span></div>
                <button className="button button--quiet" onClick={() => act(controller.retryPeer(peer.publicKey))} disabled={busy}>Retry</button>
              </li>)}</ul>}</div>
              <div><h3>Signaling relays</h3>{state.relays.length === 0 ? <p>No active relay connections.</p> : <ul className="relay-list">{state.relays.map((relay) => <li key={relay.url}><span>{relay.url}</span><strong>{relay.state}</strong>{relay.error !== null && <small>{relay.error}</small>}</li>)}</ul>}<p className="privacy-note">Relays handle encrypted WebRTC signaling only.</p></div>
            </div>
            {state.events.length > 0 && <ol className="event-log" aria-label="Recent connection events">{state.events.map((event, index) => <li key={`${index}:${event}`}>{event}</li>)}</ol>}
          </details>}
        </section>
        </details>
      )}
      <TranscriptControls key={room?.gameId ?? "welcome"}
        exportBytes={state.game && controller.exportTranscript ? () => controller.exportTranscript!() : undefined} />
    </main>
  );
}
