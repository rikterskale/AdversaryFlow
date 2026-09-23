const { defineConfig } = require("@playwright/test");
const useExternalServer = process.env.PLAYWRIGHT_EXTERNAL_SERVER === "1";

module.exports = defineConfig({
  testDir: "tests/e2e",
  timeout: 30000,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["html", { open: "never" }], ["list"]] : "list",
  projects: [
    { name: "chromium", use: { browserName: "chromium", permissions: ["clipboard-read", "clipboard-write"] } },
    { name: "firefox", use: { browserName: "firefox" } },
    { name: "webkit", use: { browserName: "webkit" } },
  ],
  use: {
    baseURL: "http://127.0.0.1:4173",
    // Pin a Windows UA so command-platform auto-detect is deterministic in CI
    // (Linux/macOS runners would otherwise select linux/macos and empty Windows-only fixtures).
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: useExternalServer ? undefined : {
    command: "node tests/e2e/static-server.js",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
});
