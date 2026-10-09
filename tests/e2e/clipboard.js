// Keep the real clipboard write and its browser permission behavior. Observe
// each page's successfully written value: the OS clipboard is shared between
// parallel headed workers, so a later read can see another test's write.
async function observeClipboard(page) {
  await page.addInitScript(() => {
    const writeText = navigator.clipboard.writeText.bind(navigator.clipboard);
    navigator.clipboard.writeText = async value => {
      await writeText(value);
      window.__copiedText = value;
    };
  });
}

async function copiedText(page) {
  return page.evaluate(() => window.__copiedText);
}

module.exports = { observeClipboard, copiedText };
