import { useEffect, useState } from "react";

import { App } from "./App";
import { DemoSession } from "./demo-session";
import type { BrowserLobbySnapshot } from "./lobby-types";

export function DemoApp({ session }: { readonly session: DemoSession }) {
  const [snapshots, setSnapshots] = useState<readonly BrowserLobbySnapshot[]>(() => session.controllers.map(controller => controller.getSnapshot()));
  const [selected, setSelected] = useState(0);
  const [followTurn, setFollowTurn] = useState(true);
  const [starting, setStarting] = useState(true);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const update = () => setSnapshots(session.controllers.map(controller => controller.getSnapshot()));
    const unsubscribes = session.controllers.map(controller => controller.subscribe(update));
    void session.start().then(() => { update(); setStarting(false); }, cause => {
      setError(cause instanceof Error ? cause.message : "Could not open the demo table"); setStarting(false);
    });
    return () => unsubscribes.forEach(unsubscribe => unsubscribe());
  }, [session]);

  const game = snapshots.find(snapshot => snapshot.game)?.game;
  const turn = game?.state?.hand.turn;
  useEffect(() => {
    if (followTurn && turn !== null && turn !== undefined) setSelected(turn);
  }, [followTurn, turn]);

  const restart = async () => {
    setStarting(true); setError(null); setSelected(0); setFollowTurn(true);
    try { await session.start(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not restart the demo table"); }
    finally { setStarting(false); }
  };

  return <div className="demo-page">
    <header className="demo-toolbar">
      <div className="demo-toolbar__top">
        <div><p className="eyebrow">Local demo</p><h1>Four seats. One tab.</h1><p>Switch between players to inspect their hands and play every turn.</p></div>
        <div className="demo-toolbar__links"><a href="./">Back to game</a><button className="button button--secondary" disabled={starting} onClick={() => void restart()}>New demo table</button></div>
      </div>
      <div className="demo-seats" role="tablist" aria-label="Demo players">
        {snapshots.map((snapshot, index) => {
          const active = game?.state?.hand.turn === index && ["bidding", "choosing_trump", "playing"].includes(game.phase);
          return <button key={index} type="button" role="tab" aria-selected={selected === index} aria-controls="demo-player-view" className={`demo-seat${selected === index ? " is-selected" : ""}${active ? " is-turn" : ""}`}
            onClick={() => { setSelected(index); setFollowTurn(false); }}>
            <strong>Player {index + 1}</strong><span>{active ? "Your turn" : snapshot.game ? "At the table" : snapshot.room ? snapshot.room.ownReady ? "Ready" : "Not ready" : "Opening"}</span>
          </button>;
        })}
      </div>
      <div className="demo-controls">
        <label><input type="checkbox" checked={followTurn} onChange={event => setFollowTurn(event.target.checked)} /> Follow the turn automatically</label>
        {turn !== null && turn !== undefined && !followTurn && <button className="button button--quiet" onClick={() => { setSelected(turn); setFollowTurn(true); }}>Go to player {turn + 1}</button>}
      </div>
    </header>
    {error && <div className="demo-message notice notice--error" role="alert">{error} <button className="button button--secondary" onClick={() => void restart()}>Try again</button></div>}
    {starting ? <div className="demo-message" role="status">Opening four local players…</div> : <div id="demo-player-view" role="tabpanel" aria-label={`Player ${selected + 1} view`}><App key={selected} controller={session.controllers[selected]!} demo /></div>}
  </div>;
}
