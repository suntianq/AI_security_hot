// Minimal pub/sub store — the whole state engine.

export type Listener<T> = (value: T, prev: T) => void;

export interface Store<T> {
  get(): T;
  set(next: T | ((prev: T) => T)): void;
  subscribe(fn: Listener<T>): () => void;
}

export function createStore<T>(initial: T): Store<T> {
  let value = initial;
  const listeners = new Set<Listener<T>>();
  return {
    get: () => value,
    set(next) {
      const prev = value;
      const resolved = typeof next === "function" ? (next as (p: T) => T)(prev) : next;
      if (Object.is(resolved, prev)) return;
      value = resolved;
      for (const fn of listeners) fn(value, prev);
    },
    subscribe(fn) {
      listeners.add(fn);
      return () => {
        listeners.delete(fn);
      };
    },
  };
}
