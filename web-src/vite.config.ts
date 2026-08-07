import { defineConfig } from "vite";

// Multi-page app. Keeps the exact URLs the public site already uses
// (/, /daily.html, /event.html?id=, /document.html?id=) so existing
// links — including externally shared ones — never break.
export default defineConfig({
  base: "/",
  build: {
    outDir: "../web/dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        index: "index.html",
        daily: "daily.html",
        event: "event.html",
        document: "document.html",
      },
    },
  },
  server: { port: 5173 },
});
