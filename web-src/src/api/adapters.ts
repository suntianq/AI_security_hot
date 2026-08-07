// API → frontend ViewModel. UI components only ever see ViewModels.

import type { ModuleItem } from "./types";

export interface NewsViewModel {
  id: number;
  title: string;
  summary: string;
  sourceId: string; // endpoint id
  sourceName: string;
  module: string;
  tags: string[];
  publishedAt: string | null;
  fetchedAt: string;
  url: string;
  read: boolean;
  favorite: boolean;
  relatedCount: number; // 0 or (n-1) additional sources reporting the same URL
}

export function toViewModel(
  item: ModuleItem,
  read: Set<number>,
  fav: Set<number>,
  urlSources: Record<string, string[]>,
): NewsViewModel {
  const related = (urlSources[item.url] ?? []).length;
  return {
    id: item.document_id,
    title: item.title,
    summary: item.summary,
    sourceId: item.source,
    sourceName: item.source_name,
    module: item.module ?? "",
    tags: item.tech ?? [],
    publishedAt: item.published_at ?? null,
    fetchedAt: item.fetched,
    url: item.url,
    read: read.has(item.document_id),
    favorite: fav.has(item.document_id),
    relatedCount: related > 1 ? related - 1 : 0,
  };
}
