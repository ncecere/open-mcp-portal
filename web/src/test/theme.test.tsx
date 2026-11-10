/*
 * Dark mode: System / Light / Dark in the account menu, kept in this
 * browser and applied to <html data-theme>; public/color-mode.js applies it
 * before the first paint; System follows the system's setting.
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { act, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { colorModeScript, COLOR_MODE_STORAGE_KEY } from "@/components/ui/color-mode/color-mode";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

/** A matchMedia whose prefers-color-scheme is `dark`, with a way to change it. */
function systemScheme(dark: boolean) {
  const listeners = new Set<() => void>();
  const state = { dark };
  vi.stubGlobal("matchMedia", (q: string) => ({
    get matches() {
      return q.includes("prefers-color-scheme: dark") ? state.dark : false;
    },
    media: q,
    addEventListener: (_: string, l: () => void) => listeners.add(l),
    removeEventListener: (_: string, l: () => void) => listeners.delete(l),
    addListener: () => {},
    removeListener: () => {},
  }));
  return (next: boolean) => {
    state.dark = next;
    listeners.forEach((l) => l());
  };
}

const theme = () => document.documentElement.dataset.theme;

afterEach(() => {
  delete document.documentElement.dataset.theme;
});

async function openThemeMenu() {
  await userEvent.click(await screen.findByRole("button", { name: /Una User/ }));
  return screen.findByRole("group", { name: "Theme" });
}

describe("the Theme setting in the account menu", () => {
  it("offers System, Light and Dark, applies the choice and keeps it in this browser", async () => {
    systemScheme(false);
    mockApi(shellRoutes());
    const { unmount } = renderApp("/");
    await openThemeMenu();
    const item = (name: string) => screen.getByRole("menuitemradio", { name });
    expect(item("System")).toHaveAttribute("aria-checked", "true");
    expect(theme()).toBe("light");

    await userEvent.click(item("Dark"));
    expect(theme()).toBe("dark");
    expect(localStorage.getItem(COLOR_MODE_STORAGE_KEY)).toBe("dark");
    await waitFor(() => expect(item("Dark")).toHaveAttribute("aria-checked", "true"));

    // A new page view keeps it.
    unmount();
    delete document.documentElement.dataset.theme;
    renderApp("/");
    await waitFor(() => expect(theme()).toBe("dark"));
    await openThemeMenu();
    expect(screen.getByRole("menuitemradio", { name: "Dark" })).toHaveAttribute("aria-checked", "true");

    await userEvent.click(screen.getByRole("menuitemradio", { name: "Light" }));
    expect(theme()).toBe("light");
    expect(localStorage.getItem(COLOR_MODE_STORAGE_KEY)).toBe("light");

    await userEvent.click(screen.getByRole("menuitemradio", { name: "System" }));
    expect(localStorage.getItem(COLOR_MODE_STORAGE_KEY)).toBeNull();
    expect(theme()).toBe("light");
  });

  it("System follows the system's setting while the app is open; a choice doesn't", async () => {
    const setSystem = systemScheme(true);
    mockApi(shellRoutes());
    renderApp("/");
    await screen.findByRole("button", { name: /Una User/ });
    await waitFor(() => expect(theme()).toBe("dark"));
    act(() => setSystem(false));
    expect(theme()).toBe("light");

    await openThemeMenu();
    await userEvent.click(screen.getByRole("menuitemradio", { name: "Dark" }));
    act(() => setSystem(false));
    expect(theme()).toBe("dark");
  });

  it("has no axe violations in dark, with the menu open and on representative pages", async () => {
    systemScheme(true);
    mockApi(shellRoutes("platform_admin"));
    const { unmount } = renderApp("/");
    await openThemeMenu();
    expect(theme()).toBe("dark");
    expect(await axe(document.body)).toHaveNoViolations();
    unmount();

    const page = renderApp("/teams/platform-tools/settings");
    expect(await screen.findByRole("heading", { level: 1, name: "Team settings" })).toBeInTheDocument();
    expect(await screen.findByRole("table", { name: "Team members" })).toBeInTheDocument();
    expect(theme()).toBe("dark");
    expect(await axe(page.container)).toHaveNoViolations();
  });
});

describe("before the first paint (public/color-mode.js)", () => {
  const file = readFileSync(path.resolve(__dirname, "../../public/color-mode.js"), "utf8").trim();
  const run = () => new Function(file)();

  it("is bitop-ui's colorModeScript, so the first paint and the app agree", () => {
    expect(file).toBe(colorModeScript);
    const index = readFileSync(path.resolve(__dirname, "../../index.html"), "utf8");
    // A same-origin file in <head> before the app (the CSP allows no inline script).
    expect(index.indexOf('<script src="/color-mode.js"></script>')).toBeGreaterThan(-1);
    expect(index.indexOf('<script src="/color-mode.js"></script>')).toBeLessThan(index.indexOf('type="module"'));
  });

  it("uses the stored choice, else the system's setting", () => {
    systemScheme(true);
    run();
    expect(theme()).toBe("dark");
    localStorage.setItem(COLOR_MODE_STORAGE_KEY, "light");
    run();
    expect(theme()).toBe("light");
    systemScheme(false);
    localStorage.removeItem(COLOR_MODE_STORAGE_KEY);
    run();
    expect(theme()).toBe("light");
    localStorage.setItem(COLOR_MODE_STORAGE_KEY, "dark");
    run();
    expect(theme()).toBe("dark");
  });
});
