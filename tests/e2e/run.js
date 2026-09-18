const { spawn } = require("node:child_process");
const http = require("node:http");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const serverScript = path.join(__dirname, "static-server.js");
const playwrightCli = require.resolve("@playwright/test/cli");
const readyUrl = new URL("http://127.0.0.1:4173/");
const server = spawn(process.execPath, [serverScript], {
  cwd: root,
  stdio: ["ignore", "inherit", "inherit"],
});

let runner;
let stopping = false;

function wait(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}

function probeServer() {
  return new Promise(resolve => {
    const request = http.request(readyUrl, { method: "HEAD" }, response => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.setTimeout(500, () => request.destroy());
    request.on("error", () => resolve(false));
    request.end();
  });
}

async function waitForServer() {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error(`Static test server exited with code ${server.exitCode}. Is port 4173 already in use?`);
    }
    if (await probeServer()) return;
    await wait(100);
  }
  throw new Error("Static test server did not become ready on http://127.0.0.1:4173 within 10 seconds.");
}

function waitForExit(child, timeoutMs) {
  if (child.exitCode !== null) return Promise.resolve(true);
  return Promise.race([
    new Promise(resolve => child.once("exit", () => resolve(true))),
    wait(timeoutMs).then(() => false),
  ]);
}

async function stopChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  if (!(await waitForExit(child, 2_000))) {
    child.kill("SIGKILL");
    await waitForExit(child, 2_000);
  }
}

async function stopAll() {
  if (stopping) return;
  stopping = true;
  await stopChild(runner);
  await stopChild(server);
}

async function main() {
  try {
    await waitForServer();
    runner = spawn(process.execPath, [playwrightCli, "test", ...process.argv.slice(2)], {
      cwd: root,
      env: { ...process.env, PLAYWRIGHT_EXTERNAL_SERVER: "1" },
      stdio: "inherit",
    });
    const exitCode = await new Promise(resolve => runner.once("exit", code => resolve(code)));
    process.exitCode = exitCode ?? 1;
  } catch (error) {
    console.error(`E2E runner failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  } finally {
    await stopAll();
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    stopAll().finally(() => process.exit(signal === "SIGINT" ? 130 : 143));
  });
}

void main();
