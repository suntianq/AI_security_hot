// Read state — set of document ids persisted to localStorage.

import { createStore } from "./store";

const KEY = "aih.read";

function load(): Set<number> {
  try {
    const raw = localStorage.getItem(KEY);
    const arr: unknown = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(arr) ? arr.filter((x): x is number => typeof x === "number") : []);
  } catch {
    return new Set();
  }
}

function persist(set: Set<number>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify([...set]));
  } catch {
    // storage unavailable (private mode) — keep in-memory state only
  }
}

export const readStore = createStore<Set<number>>(load());

export function isRead(id: number): boolean {
  return readStore.get().has(id);
}

export function markRead(id: number): void {
  readStore.set((prev) => {
    if (prev.has(id)) return prev;
    const next = new Set(prev);
    next.add(id);
    persist(next);
    return next;
  });
}
