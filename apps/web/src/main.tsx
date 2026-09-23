import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { BrowserLobbyController } from "./lobby-controller";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Application root is missing");
}

const controller = new BrowserLobbyController();
void controller.initialize().catch(() => undefined);
window.addEventListener("pagehide", () => { void controller.dispose(); });
window.addEventListener("pageshow", (event) => { if (event.persisted) { window.location.reload(); } });
import.meta.hot?.dispose(() => { void controller.dispose(); });

createRoot(root).render(<StrictMode><App controller={controller} /></StrictMode>);
