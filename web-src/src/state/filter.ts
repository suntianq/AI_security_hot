// Feed filter state — mirrored to/from the URL query string.

import { createStore } from "./store";
import { readQuery, updateQuery } from "../lib/url";

export type View = "home" | "all";
export type Sort = "latest" | "multi";
export type Range = "today" | "24h" | "3d" | "7d";

export interface FilterState {
  view: View;
  module: string; // "" = all modules
  tech: string; // "" = all tech
  source: string; // "" = all sources
  sort: Sort;
  range: Range;
  heat: number; // 0 = no threshold
}

function parseView(value: string | null): View {
  return value === "all" || value === "home" ? value : "home";
}

function parseSort(value: string | null): Sort {
  return value === "multi" || value === "latest" ? value : "latest";
}

function parseRange(value: string | null): Range {
  return value === "24h" || value === "3d" || value === "7d" || value === "today"
    ? value
    : "today";
}

export function readFilterFromUrl(): FilterState {
  const q = readQuery();
  const heat = Number(q.get("heat") ?? "0");
  return {
    view: parseView(q.get("view")),
    module: q.get("category") ?? "",
    tech: q.get("tech") ?? "",
    source: q.get("source") ?? "",
    sort: parseSort(q.get("sort")),
    range: parseRange(q.get("range")),
    heat: Number.isFinite(heat) && heat > 0 ? heat : 0,
  };
}

export function syncFilterToUrl(state: FilterState): void {
  updateQuery({
    view: state.view !== "home" ? state.view : undefined,
    category: state.module || undefined,
    tech: state.tech || undefined,
    source: state.source || undefined,
    sort: state.sort !== "latest" ? state.sort : undefined,
    range: state.range !== "today" ? state.range : undefined,
    heat: state.heat > 0 ? String(state.heat) : undefined,
  });
}

export const filterStore = createStore<FilterState>(readFilterFromUrl());

export function applyFilter(patch: Partial<FilterState>): void {
  filterStore.set((prev) => {
    const next = { ...prev, ...patch };
    syncFilterToUrl(next);
    return next;
  });
}
