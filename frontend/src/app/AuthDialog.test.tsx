import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AuthDialog, normalizeApiToken } from "./AuthDialog";

const TOKEN = "UCXcUZ7OGyrXJ4M7fl7jsQDl9DPT_ZiAGItIcjkHR8E";

describe("normalizeApiToken", () => {
  it.each([
    [TOKEN, TOKEN],
    [`  ${TOKEN}\n`, TOKEN],
    [`${TOKEN} (generated for this container start)`, TOKEN],
    [`${TOKEN} (supplied through ADVERSARYFLOW_API_TOKEN)`, TOKEN],
    [`API token: ${TOKEN} (generated for this container start)`, TOKEN],
    [`  API token: ${TOKEN}`, TOKEN],
    [`"${TOKEN}"`, TOKEN],
    [`'${TOKEN}'`, TOKEN],
  ])("accepts the startup banner copy %j", (raw, expected) => {
    expect(normalizeApiToken(raw)).toBe(expected);
  });

  it("does not rewrite operator-chosen tokens that only resemble the banner", () => {
    expect(normalizeApiToken("abc (custom)")).toBe("abc (custom)");
    expect(normalizeApiToken("\"abc")).toBe("\"abc");
  });
});

describe("AuthDialog", () => {
  it("submits the bare token when the whole banner line is pasted", () => {
    const onConnect = vi.fn();
    render(<AuthDialog message="" onClose={vi.fn()} onConnect={onConnect} open />);
    fireEvent.change(screen.getByLabelText("API token"), { target: { value: `API token: ${TOKEN} (generated for this container start)` } });
    fireEvent.click(screen.getByRole("button", { name: "Connect securely" }));
    expect(onConnect).toHaveBeenCalledWith(TOKEN);
  });

  it("still asks for a value when only the label or note is pasted", () => {
    const onConnect = vi.fn();
    render(<AuthDialog message="" onClose={vi.fn()} onConnect={onConnect} open />);
    fireEvent.change(screen.getByLabelText("API token"), { target: { value: "API token:  " } });
    fireEvent.click(screen.getByRole("button", { name: "Connect securely" }));
    expect(onConnect).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the API token to continue.");
  });
});
