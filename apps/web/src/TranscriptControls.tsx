import { useRef, useState, type ChangeEvent } from "react";

import { MAX_TRANSCRIPT_BYTES, verifyTranscript, type TranscriptVerification } from "./transcript";

export function TranscriptControls({ exportBytes }: { readonly exportBytes: (() => Uint8Array) | undefined }) {
  const input = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");

  const download = () => {
    if (!exportBytes) return;
    try {
      const url = URL.createObjectURL(new Blob([new Uint8Array(exportBytes())], { type: "application/cbor" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = "sasku-transcript.cbor";
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setStatus("");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Could not export the transcript.");
    }
  };

  const verify = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file || busy) return;
    if (file.size > MAX_TRANSCRIPT_BYTES) {
      setStatus("Transcript exceeds the file size limit.");
      return;
    }
    setBusy(true);
    setStatus("Verifying transcript…");
    try {
      setStatus(verificationText(await verifyTranscript(new Uint8Array(await file.arrayBuffer()))));
    } catch {
      setStatus("Could not read the transcript file.");
    } finally {
      setBusy(false);
    }
  };

  return <section className="transcript-controls" aria-label="Match transcript">
    {exportBytes && <button className="button button--quiet" type="button" onClick={download}>Export transcript (.cbor)</button>}
    <input type="file" accept=".cbor,application/cbor" hidden ref={input} onChange={event => void verify(event)} />
    <button className="button button--quiet" type="button" disabled={busy} onClick={() => input.current?.click()}>Verify transcript</button>
    {status && <p role="status">{status}</p>}
  </section>;
}

function verificationText(result: TranscriptVerification): string {
  if (result.status === "violation") {
    const round = result.round === undefined ? "" : ` in round ${result.round}`;
    return `Verification failed${round}. ${result.message}`;
  }
  const [first, second] = result.match.totals;
  const score = `Team 1 + 3 scored ${first}. Team 2 + 4 scored ${second}.`;
  if (result.status === "verified") return `Match verified. ${score}`;
  const rounds = result.match.completed.length;
  return `Match incomplete. Verified ${rounds} ${rounds === 1 ? "round" : "rounds"}. ${score}`;
}
