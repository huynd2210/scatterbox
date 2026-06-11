import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In dev, the UI runs on Vite's port and proxies to the daemon; the built
// bundle is served by the daemon itself (same origin, no proxy needed).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8420",
      "/ws": { target: "ws://127.0.0.1:8420", ws: true },
    },
  },
});
