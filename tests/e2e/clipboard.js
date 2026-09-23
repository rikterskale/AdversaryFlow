// Keep the real clipboard write and its browser permission behavior. Firefox
// and WebKit do not expose Chromium's clipboard-read permission grant, so
// observe the successfully written value without attempting a second read.
async function observeClipboard(page) {
  await page.addInitScript(() => {
    const writeText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = async value => {
      await writeText(value);
      window.__copiedText = value;
    };
  });
}

async function copiedText(page, browserName) {
  return browserName === "chromium"
    ? page.evaluate(() => navigator.clipboard.readText())
    : page.evaluate(() => window.__copiedText);
}

module.exports = { observeClipboard, copiedText };
