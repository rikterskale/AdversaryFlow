"""Exercise the real Flask workflow in macOS Safari using Apple's WebDriver.

Enable /usr/bin/safaridriver with --enable first. Uses only the Python standard
library and the existing fixture service; no emulation commands are executed.
"""
from __future__ import annotations

import base64
import json
import platform
import select
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test-results" / "safari-native"
ELEMENT = "element-6066-11e4-a52e-4f735466cecf"
# WebDriver reports these while React re-renders or a screen is still settling.
# Playwright retries them implicitly; safaridriver returns them immediately.
TRANSIENT_ERRORS = ("stale element reference", "element not interactable", "element click intercepted", "no such element")


def button_present(text: str) -> str:
    return ("return Array.from(document.querySelectorAll('button'))"
            f".some(b => (b.getAttribute('aria-label') || b.textContent || '').includes({json.dumps(text)}));")


def request(url: str, method: str = "GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(exc.read().decode()) from exc


class Safari:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}"
        self.session = ""

    def command(self, method: str, path: str, body=None):
        prefix = f"/session/{self.session}" if self.session else ""
        return request(self.base + prefix + path, method, body)["value"]

    def script(self, script: str, *args):
        return self.command("POST", "/execute/sync", {"script": script, "args": args})

    def wait(self, script: str, *args):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = self.script(script, *args)
            if result:
                return result
            time.sleep(0.2)
        raise AssertionError(f"Safari condition timed out: {script}")

    def element(self, selector: str, using: str = "css selector") -> str:
        deadline = time.monotonic() + 30
        while True:
            try:
                result = self.command("POST", "/element", {"using": using, "value": selector})
                return result[ELEMENT]
            except RuntimeError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def retry(self, action, deadline: float):
        while True:
            try:
                return action()
            except RuntimeError as exc:
                if time.monotonic() >= deadline or not any(error in str(exc) for error in TRANSIENT_ERRORS):
                    raise
                time.sleep(0.2)

    def poll(self, script: str, seconds: float) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.script(script):
                return True
            time.sleep(0.2)
        return False

    def click(self, text: str, *, exact: bool = False, until: str | None = None):
        """Click a button like Playwright: wait until it is enabled, centre it, retry transient errors.

        safaridriver dispatches a native click at the element's last-computed
        centre and returns immediately. Right after a screen change (notably the
        sticky review action bar after resuming a plan) that click can be lost,
        so screen transitions pass ``until`` and are re-clicked until it holds.
        """
        predicate = (f"@aria-label='{text}' or normalize-space(.)='{text}'" if exact
                     else f"contains(@aria-label, '{text}') or contains(normalize-space(.), '{text}')")
        selector = f"//button[{predicate}]"
        deadline = time.monotonic() + 30

        def attempt() -> None:
            element = self.element(selector, "xpath")
            ref = {ELEMENT: element}
            if not self.script("return !arguments[0].disabled;", ref):
                raise RuntimeError("element not interactable: button is disabled")
            self.script("arguments[0].scrollIntoView({block: 'center', inline: 'nearest'});", ref)
            self.command("POST", f"/element/{element}/click", {})

        while True:
            self.retry(attempt, deadline)
            if until is None or self.poll(until, 3):
                return
            if time.monotonic() >= deadline:
                raise AssertionError(f"Safari click on {text!r} did not reach: {until}")

    def fill(self, selector: str, text: str):
        def attempt() -> None:
            element = self.element(selector)
            self.script("arguments[0].scrollIntoView({block: 'center', inline: 'nearest'});", {ELEMENT: element})
            self.command("POST", f"/element/{element}/clear", {})
            self.command("POST", f"/element/{element}/value", {"text": text})

        self.retry(attempt, time.monotonic() + 30)

    def screenshot(self, name: str):
        (OUTPUT / f"{name}.png").write_bytes(base64.b64decode(self.command("GET", "/screenshot")))


def service_url(process: subprocess.Popen) -> str:
    deadline = time.monotonic() + 30
    assert process.stdout is not None
    while time.monotonic() < deadline:
        if select.select([process.stdout], [], [], 1)[0]:
            line = process.stdout.readline()
            if line.startswith("READY "):
                return line.strip().split(" ", 1)[1]
        if process.poll() is not None:
            raise RuntimeError("Fixture service exited before it was ready")
    raise RuntimeError("Fixture service did not start")


def exercise(browser: Safari, base: str):
    browser.command("POST", "/url", {"url": base})
    browser.fill("#auth-token", "browser-fixture-token")
    browser.click("Connect securely")
    browser.click("Begin emulation plan", until=button_present("Zeta Group"))
    browser.click("Zeta Group")
    browser.click("Continue", until=button_present("Build plan"))
    browser.click("Windows", exact=True)
    browser.click("Build plan", until=button_present("Finish & export"))
    note = '[aria-label="Evidence note for T1059.001"]'
    browser.fill(note, "Native Safari evidence")
    browser.script("const s=document.querySelector('[aria-label=\"Outcome for T1059.001\"]'); s.value='passed'; s.dispatchEvent(new Event('change',{bubbles:true}));")
    browser.click("Finish & export", until=button_present("Generate report"))
    browser.click("Generate report", exact=True)
    browser.wait("return Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Regenerate report'));")
    frame = browser.element("iframe")
    browser.command("POST", "/frame", {"id": {"element-6066-11e4-a52e-4f735466cecf": frame}})
    browser.wait("return document.body.textContent.includes('Zeta Group');")
    browser.command("POST", "/frame/parent", {})

    # Observe generated Blobs while allowing the real browser download to run.
    browser.script("window.savedArtifacts=[]; const original=URL.createObjectURL; URL.createObjectURL=function(blob){blob.text().then(text=>window.savedArtifacts.push({type:blob.type,text}));return original.call(this,blob);};")
    browser.click("Save JSON plan", exact=True)
    browser.wait("return window.savedArtifacts.some(a=>a.type.includes('json'));")
    saved = browser.script("return JSON.parse(window.savedArtifacts.find(a=>a.type.includes('json')).text);")
    assert saved["scope"]["command_platform"] == "windows"
    assert saved["scope"]["allow_high_risk"] is False
    assert "T1059.001" in saved["summary"]["marked_run"]
    (OUTPUT / "saved-plan.json").write_text(json.dumps(saved, indent=2), encoding="utf-8")
    browser.click("Download PDF engagement report", exact=True)
    browser.wait("return window.savedArtifacts.some(a=>a.text.startsWith('%PDF-'));")
    browser.screenshot("export")
    print("PASS Safari: authentication, plan, evidence, HTML report, JSON/PDF downloads", flush=True)

    browser.click("Scope engagement", exact=True, until=button_present("Build plan"))
    browser.click("Linux", exact=True)
    browser.click("Build plan", until=button_present("Finish & export"))
    browser.wait("return document.querySelector('[aria-label=\"Evidence note for T1082\"]');")
    assert not browser.script("return [...document.querySelectorAll('.evidence__note')].some(e=>e.value==='Native Safari evidence');")
    browser.click("Scope engagement", exact=True, until=button_present("Build plan"))
    browser.click("Windows", exact=True)
    browser.click("Build plan", until=button_present("Finish & export"))
    browser.wait("return document.querySelector(arguments[0])?.value==='Native Safari evidence';", note)
    browser.command("POST", "/refresh", {})
    browser.click("Resume Zeta Group plan", until=button_present("Finish & export"))
    browser.wait("return document.querySelector(arguments[0])?.value==='Native Safari evidence';", note)
    print("PASS Safari: platform separation, restoration, persisted resume", flush=True)

    request(base + "/test-control", "POST", {"action": "csrf"})
    browser.click("Finish & export", until=button_present("Generate report"))
    browser.click("Generate report", exact=True)
    browser.wait("return Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Regenerate report'));")
    request(base + "/test-control", "POST", {"action": "token"})
    browser.click("Regenerate report", exact=True)
    browser.fill("#auth-token", "rotated-fixture-token")
    browser.click("Connect securely")
    browser.wait("return !document.querySelector('#auth-token');")
    browser.click("Retry report generation", exact=True)
    browser.wait("return Array.from(document.querySelectorAll('button')).some(b=>b.textContent.includes('Regenerate report'));")
    browser.screenshot("reconnected")
    print("PASS Safari: CSRF renewal and token reconnect without evidence loss", flush=True)


def main() -> int:
    if platform.system() != "Darwin":
        raise SystemExit("Native Safari validation requires macOS; WebKit is tested separately by Playwright.")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    browser = Safari(port)
    with (OUTPUT / "service.log").open("w", encoding="utf-8") as service_log, (OUTPUT / "driver.log").open("w", encoding="utf-8") as driver_log:
        service = subprocess.Popen([sys.executable, "-u", "-m", "tests.e2e.real_server"], cwd=ROOT, stdout=subprocess.PIPE, stderr=service_log, text=True)
        driver = subprocess.Popen(["/usr/bin/safaridriver", "--port", str(port)], stdout=driver_log, stderr=driver_log)
        try:
            base = service_url(service)
            deadline = time.monotonic() + 30
            while True:
                try:
                    session = browser.command("POST", "/session", {"capabilities": {"alwaysMatch": {"browserName": "safari"}}})
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.2)
            browser.session = session["sessionId"]
            details = {"platform": platform.platform(), "capabilities": session["capabilities"]}
            print(json.dumps(details), flush=True)
            (OUTPUT / "environment.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
            exercise(browser, base)
            return 0
        except Exception:
            if browser.session:
                browser.screenshot("failure")
                (OUTPUT / "failure.html").write_text(browser.script("return document.documentElement.outerHTML;"), encoding="utf-8")
            raise
        finally:
            try:
                if browser.session:
                    browser.command("DELETE", "")
            finally:
                for process in (driver, service):
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
