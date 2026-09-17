import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  root: fileURLToPath(new URL("./src", import.meta.url)),
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: [fileURLToPath(new URL("./src/test/setup.ts", import.meta.url))],
    include: ["**/*.test.{ts,tsx}"],
    css: true,
  },
});
