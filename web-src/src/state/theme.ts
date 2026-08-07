// Theme state — explicit toggle wins over the system preference.

import { createStore } from "./store";

export type Theme = "light" | "dark";

const KEY = "aih.theme";

function detect(): Theme {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    // storage unavailable — fall through to system preference
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export const themeStore = createStore<Theme>("light");

function apply(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // ignore
  }
}

export function initTheme(): void {
  const theme = detect();
  themeStore.set(theme);
  apply(theme);
}

export function toggleTheme(): void {
  themeStore.set((prev) => {
    const next = prev === "dark" ? "light" : "dark";
    apply(next);
    return next;
  });
}
