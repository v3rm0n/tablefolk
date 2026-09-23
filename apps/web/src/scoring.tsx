import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { SaskuScoringReference } from "./SaskuScoringReference";
import "./styles.css";

const root = document.getElementById("root");

if (root === null) {
  throw new Error("Application root is missing");
}

createRoot(root).render(<StrictMode><main className="shell shell--reference">
  <a className="reference-back" href="./">← Back to game</a>
  <SaskuScoringReference />
</main></StrictMode>);
