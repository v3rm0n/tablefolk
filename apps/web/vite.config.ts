import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import { fileURLToPath } from "node:url";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    rolldownOptions: {
      input: {
        main: fileURLToPath(new URL("./index.html", import.meta.url)),
        scoring: fileURLToPath(new URL("./scoring.html", import.meta.url)),
      },
    },
  },
  worker: {
    format: "es",
  },
});
