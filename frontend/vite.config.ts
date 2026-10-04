import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The command terminal talks only to the local API. No external CDN, no font
// host, no telemetry: the air-gap guarantee would be meaningless otherwise.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/auth": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/documents": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/decrypt": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/sessions": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/ledger": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/forensics": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/investigations": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/evidence": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/commander": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/security-events": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/incidents": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/approvals": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/lockdown": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/unlock": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/recipients": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/devices": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/audit": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/ai": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/security-lab": { target: "http://127.0.0.1:8000", changeOrigin: false },
      "/watermarks": { target: "http://127.0.0.1:8000", changeOrigin: false },
    },
  },
  build: { outDir: "dist", sourcemap: false },
});
