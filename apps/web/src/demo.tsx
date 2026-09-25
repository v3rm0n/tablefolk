import { createRoot } from "react-dom/client";

import { DemoApp } from "./DemoApp";
import { DemoSession } from "./demo-session";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) throw new Error("Demo root is missing");

const session = new DemoSession(window.location.href);
window.addEventListener("pagehide", () => { void session.dispose(); });
window.addEventListener("pageshow", event => { if (event.persisted) window.location.reload(); });
import.meta.hot?.dispose(() => { void session.dispose(); });

createRoot(root).render(<DemoApp session={session} />);
