// App-wide data stores and loaders.

import { createStore } from "./store";
import { getFeed, getOverview } from "../api/endpoints";
import type { ModuleItem, Overview } from "../api/types";

export const overviewStore = createStore<Overview | null>(null);

export interface FeedState {
  items: ModuleItem[];
  next_before: string | null;
  loading: boolean;
}

export const feedStore = createStore<FeedState>({
  items: [],
  next_before: null,
  loading: false,
});

export interface UiState {
  loading: boolean;
  error: string | null;
}

export const uiStore = createStore<UiState>({ loading: true, error: null });

export async function loadOverview(): Promise<void> {
  uiStore.set({ loading: true, error: null });
  try {
    const overview = await getOverview();
    overviewStore.set(overview);
    uiStore.set({ loading: false, error: null });
  } catch (e) {
    uiStore.set({ loading: false, error: e instanceof Error ? e.message : String(e) });
  }
}

export async function loadFeedNext(
  query: { module?: string; tech?: string; source?: string; since?: string },
): Promise<void> {
  const state = feedStore.get();
  if (state.loading || state.next_before === null && state.items.length > 0) return;
  feedStore.set({ ...state, loading: true });
  try {
    const res = await getFeed({
      limit: 50,
      before: state.next_before ?? undefined,
      since: query.since,
      module: query.module || undefined,
      tech_direction: query.tech || undefined,
      source: query.source || undefined,
    });
    feedStore.set((prev) => ({
      items: [...prev.items, ...res.items],
      next_before: res.next_before,
      loading: false,
    }));
  } catch (e) {
    feedStore.set({ ...feedStore.get(), loading: false });
    console.error("feed load failed", e);
  }
}

export function resetFeed(): void {
  feedStore.set({ items: [], next_before: null, loading: false });
}
