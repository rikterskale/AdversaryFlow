import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it, vi } from "vitest";

import { Dialog } from "./Dialog";

it("keeps the focused field across parent updates and restores the opener only on close", () => {
  const opener = document.createElement("button");
  document.body.appendChild(opener);
  opener.focus();
  const firstClose = vi.fn();
  const nextClose = vi.fn();
  const content = (open: boolean, onClose: () => void) => <Dialog open={open} title="Edit record" onClose={onClose}><input aria-label="Record note" /></Dialog>;
  const view = render(content(true, firstClose));
  const input = screen.getByLabelText("Record note");
  input.focus();
  view.rerender(content(true, nextClose));
  expect(input).toHaveFocus();
  fireEvent.keyDown(input, { key: "Escape" });
  expect(nextClose).toHaveBeenCalledOnce();
  expect(firstClose).not.toHaveBeenCalled();
  view.rerender(content(false, nextClose));
  expect(opener).toHaveFocus();
  opener.remove();
});
