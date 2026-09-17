import { copyFileSync } from "node:fs";
import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const frontendRoot = fileURLToPath(new URL(".", import.meta.url));
const buildOutput = fileURLToPath(new URL("../node_modules/.adversaryflow-frontend", import.meta.url));

const syncStableAssets = {
  name: "adversaryflow-stable-assets",
  closeBundle(): void {
    for (const filename of ["index.html", "styles.css", "app.js"]) {
      copyFileSync(`${buildOutput}/${filename}`, `${frontendRoot}/${filename}`);
    }
    copyFileSync(`${frontendRoot}/public/favicon.svg`, `${frontendRoot}/favicon.svg`);
  },
};

export default defineConfig({
  root: fileURLToPath(new URL("./src", import.meta.url)),
  publicDir: false,
  plugins: [react(), syncStableAssets],
  build: {
    outDir: buildOutput,
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: (assetInfo) =>
          assetInfo.names.some((name) => name.endsWith(".css"))
            ? "styles.css"
            : "assets/[name]-[hash][extname]",
      },
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:5050",
    },
  },
});
