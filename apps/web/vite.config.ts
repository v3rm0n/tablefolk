import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  base: "./",
  plugins: [
    react(),
    {
      name: "development-html-with-hmr",
      apply: "serve",
      // Vite mounts inline styles and the React refresh preamble in development.
      transformIndexHtml: html => html.replace(/^ *<meta http-equiv="Content-Security-Policy"[^>]*>\n/m, ""),
    },
  ],
  build: {
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        demo: fileURLToPath(new URL("./demo.html", import.meta.url)),
        howItWorks: fileURLToPath(new URL("./how-it-works.html", import.meta.url)),
        scoring: fileURLToPath(new URL("./scoring.html", import.meta.url)),
      },
    },
  },
  worker: {
    format: "es",
  },
});
