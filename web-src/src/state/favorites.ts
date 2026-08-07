// Favorite state — set of document ids persisted to localStorage.

import { createStore } from "./store";

const KEY = "aih.fav";

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
    // storage unavailable — keep in-memory state only
  }
}

export const favStore = createStore<Set<number>>(load());

export function isFav(id: number): boolean {
  return favStore.get().has(id);
}

export function toggleFavorite(id: number): boolean {
  let now = false;
  favStore.set((prev) => {
    const next = new Set(prev);
    if (next.has(id)) {
      next.delete(id);
      now = false;
    } else {
      next.add(id);
      now = true;
    }
    persist(next);
    return next;
  });
  return now;
}
