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
        <section className={`welcome${invited ? " welcome--invited" : ""}`} aria-labelledby="welcome-title">
          <div className="welcome__copy">
            {invited ? <>
              <p className="eyebrow">Invitation received</p>
              <h1 id="welcome-title">You're invited<br /><em>to Sasku.</em></h1>
              <p className="lede">Take your seat in a private four-player game.</p>
            </> : <>
              <h1 id="welcome-title">Sasku</h1>
              <p className="lede">A four-player partnership trick-taking game. Bid for trump, play nine tricks, and score with your partner.</p>
              <div className="welcome__links">
                <a className="reference-link" href="./how-it-works.html">How it works <span aria-hidden="true">→</span></a>
                <a className="reference-link" href="./scoring.html">Scoring reference <span aria-hidden="true">→</span></a>
                <a className="reference-link" href="./demo.html">Demo <span aria-hidden="true">→</span></a>
              </div>
            </>}
          </div>
          <div className="entry-panel">
            {invited ? <>
              <button className="button button--primary" disabled={busy || state.identity === null} onClick={() => act(controller.join(invitation, relays))}>
                {state.busy === "joining" ? "Joining table..." : "Join this table"}<span aria-hidden="true">→</span>
              </button>
              <button className="entry-alternative" disabled={busy || state.identity === null} onClick={() => act(controller.create(relays))}>Start a new game</button>
            </> : <>
              <button className="button button--primary" disabled={busy || state.identity === null} onClick={() => act(controller.create(relays))}>
                {state.busy === "hosting" ? "Opening table..." : "Start a game"}<span aria-hidden="true">+</span>
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
            </>}
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
        <summary>Table <span>{state.peers.filter(peer => peer.state === "authenticated").length} / 3 connected</span></summary>
        <section className="lobby" aria-labelledby="lobby-title">
          <div className="lobby-heading">
            <div><p className="eyebrow">{playing ? "At the table" : "Waiting room"}</p><h1 id="lobby-title">Sasku</h1></div>
            {!demo && <button className="button button--quiet" onClick={() => act(controller.leave().then(() => setInvitation("")))} disabled={state.busy === "leaving"}>Leave table</button>}
          </div>
          <div className="lobby-layout">
            <div className="table-panel">
              <div className="table-caption" aria-live="polite">{joining ? <span className="joining-status" role="status"><span className="loading-spinner" aria-hidden="true" />Loading players…</span> : `${room.seats.length} / 4 seated`}</div>
              <div className="felt-table" aria-label="Table seats">
                {Array.from({ length: 4 }, (_, index) => {
                  const seat = room.seats[index];
                  return <div className={`seat seat--${index + 1}${seat === undefined ? " seat--empty" : ""}`} key={index}>
                    <span className="seat__number">0{index + 1}</span>
                    {seat === undefined ? <h3>{joining ? "Loading…" : "Open seat"}</h3> : <>
                      <h3>{seat.isSelf ? "You" : `Player ${index + 1}`} {seat.isHost && <span className="seat__host">Host</span>}</h3>
                      <details className="seat-identity"><summary>Identity</summary><p className="seat__fingerprint">{seat.fingerprint}</p></details>
                      <p className="seat__connection"><span className={seat.connected ? "status-dot status-dot--verified" : "status-dot"} aria-hidden="true" />{seat.isSelf ? "This browser" : seat.connected ? "Identity verified" : "Not connected"}</p>
                      <span className={`vote ${seat.ready ? "vote--ready" : ""}`}>{seat.ready ? "Ready" : "Not ready"}</span>
                    </>}
                  </div>;
                })}
              </div>
            </div>
            <aside className="lobby-actions" aria-label={demo ? "Readiness" : "Invitation and readiness"}>
              {demo ? <p className="demo-lobby-note">All four players are running locally in this tab. Choose any seat above to see its view.</p> : <>
                <label htmlFor="share-invitation">Share this invitation</label>
                <input id="share-invitation" ref={inviteField} readOnly value={room.invitation} onFocus={() => inviteField.current?.select()} />
                <button className="button button--secondary" onClick={() => { void copyInvite(); }}>Copy invitation</button>
                <p className="copy-status" role="status">{copySource === room.invitation ? copyStatus : ""}</p>
              </>}
              {!playing && <div className="agreement-status" aria-live="polite">
                <strong>{readyCount} of 4 ready</strong>
                <p>{!room.ownReady ? "Mark ready to play." : room.seats.length < 4 ? "Waiting for players." : readyCount < 4 ? "Waiting for everyone to be ready." : "Starting the game…"}</p>
              </div>}
              {!state.game && <button className="button button--secondary" disabled={busy} onClick={() => act(controller.setReady(!room.ownReady))}>{room.ownReady ? "Not ready" : "Ready"}</button>}
            </aside>
          </div>
          {!demo && <details className="diagnostics">
            <summary>Details <span>{state.peers.filter(({ state }) => state === "authenticated").length} verified links</span></summary>
            <div className="roster-details"><h3>Signed roster</h3><p>Game ID</p><code>{room.gameId}</code><p>Roster hash</p><code>{room.rosterHash ?? "Loading…"}</code></div>
            <div className="diagnostics__columns">
              <div><h3>Peer links</h3>{state.peers.length === 0 ? <p>No peer connections yet. Guests connect after opening your invitation.</p> : <ul className="connection-list">{state.peers.map((peer) => <li key={peer.publicKey}>
                <div><strong>{peer.fingerprint}</strong><span>{peer.state === "authenticated" ? "Identity verified" : peer.state} / {peer.path} path</span></div>
                <button className="button button--quiet" onClick={() => act(controller.retryPeer(peer.publicKey))} disabled={busy}>Retry connection</button>
              </li>)}</ul>}</div>
              <div><h3>Signaling relays</h3>{state.relays.length === 0 ? <p>No active relay subscriptions.</p> : <ul className="relay-list">{state.relays.map((relay) => <li key={relay.url}><span>{relay.url}</span><strong>{relay.state}</strong>{relay.error !== null && <small>{relay.error}</small>}</li>)}</ul>}<p className="privacy-note">Relays carry encrypted signaling, not game messages. TURN is not configured.</p></div>
            </div>
            {state.events.length > 0 && <ol className="event-log" aria-label="Recent connection events">{state.events.map((event, index) => <li key={`${index}:${event}`}>{event}</li>)}</ol>}
          </details>}
        </section>
        </details>
      )}

    </main>
  );
}
