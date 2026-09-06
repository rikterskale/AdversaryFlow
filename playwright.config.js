const { defineConfig } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "tests/e2e",
  timeout: 30000,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["html", { open: "never" }], ["list"]] : "list",
  use: {
    baseURL: "http://127.0.0.1:4173",
    // Pin a Windows UA so command-platform auto-detect is deterministic in CI
    // (Linux/macOS runners would otherwise select linux/macos and empty Windows-only fixtures).
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "python3 -m http.server 4173 --directory frontend",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: !process.env.CI,
  },
});
