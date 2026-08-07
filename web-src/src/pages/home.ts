// Home page — today's hotspots, stats, and the latest-selected feed.
// Views: home (overview) / all (/api/feed, infinite scroll).
// The page shell renders once; only the feed re-renders on filter changes,
// so filter interactions (dropdowns) never get torn down.

import { initApp } from "../bootstrap";
import {
  feedStore,
  loadFeedNext,
  loadOverview,
  overviewStore,
  resetFeed,
  uiStore,
} from "../state/app";
import { applyFilter, filterStore } from "../state/filter";
import { readStore } from "../state/readState";
import { toViewModel, type NewsViewModel } from "../api/adapters";
import { hotBlockHtml } from "../components/hot/HotEvents";
import { mountFilterBar } from "../components/filter/FilterBar";
import { mountFeedList } from "../components/feed/FeedList";
import { emptyStateHtml, errorStateHtml, skeletonFeedHtml } from "../components/common/States";
import { esc } from "../lib/dom";
import { rangeCutoff } from "../lib/time";
import type { ModuleItem, Overview } from "../api/types";

const content = initApp({ activeNav: "home", variant: "full" });
void loadOverview();

overviewStore.subscribe(render);
uiStore.subscribe(render);
filterStore.subscribe(renderFeed);
feedStore.subscribe(renderFeed);
readStore.subscribe(renderFeed);

function render(): void {
  const ui = uiStore.get();
  const overview = overviewStore.get();
  if (ui.error && !overview) {
    content.innerHTML = errorStateHtml(ui.error, () => void loadOverview());
    return;
  }
  if (!overview) {
    content.innerHTML = skeletonFeedHtml();
    return;
  }
  const hotspots =
    filterStore.get().heat > 0
      ? overview.hotspots.filter((h) => h.score >= filterStore.get().heat)
      : overview.hotspots;
  const totalDocs = overview.modules.reduce((n, m) => n + m.items.length, 0);
  const multiSources = overview.hotspots.filter((h) => h.source_count >= 2).length;
  const sourceCount = new Set(overview.modules.flatMap((m) => m.items.map((i) => i.source))).size;

  content.innerHTML = `
    <div class="page-title">${esc(overview.date)} · ${esc(overview.weekday)}</div>
    <div class="section-title mt-lg"><span class="bar"></span>今日热点<span class="count">${hotspots.length} 条</span></div>
    ${hotspots.length ? hotBlockHtml(hotspots, overview.labels) : emptyStateHtml("今日暂无热点", "稍后再来看看。")}
    <div class="stats-bar">
      <div class="stat-item"><span class="stat-num">${totalDocs}</span><span class="stat-label">今日收录</span></div>
      <div class="stat-item"><span class="stat-num">${hotspots.length}</span><span class="stat-label">热点事件</span></div>
      <div class="stat-item"><span class="stat-num">${multiSources}</span><span class="stat-label">多源热点</span></div>
      <div class="stat-item"><span class="stat-num">${sourceCount}</span><span class="stat-label">信息源</span></div>
    </div>
    <div class="section-title"><span class="bar"></span>最新精选<span class="count" id="feedCount"></span></div>
    <div id="filterBar"></div>
    <div id="feed"></div>
  `;
  mountFilterBar(content.querySelector<HTMLElement>("#filterBar") as HTMLElement, {
    onChange: handleFilterChange,
  });
  renderFeed();
}

function handleFilterChange(partial: Partial<ReturnType<typeof filterStore.get>>): void {
  applyFilter(partial);
  renderFeed();
}

let lastFeedQuery = "";

function renderFeed(): void {
  const overview = overviewStore.get();
  const filter = filterStore.get();
  if (!overview) return;
  const feedEl = content.querySelector<HTMLElement>("#feed");
  const countEl = content.querySelector<HTMLElement>("#feedCount");
  if (!feedEl) return;

  if (filter.view === "all") {
    const queryKey = JSON.stringify(feedQuery(filter));
    if (queryKey !== lastFeedQuery) {
      lastFeedQuery = queryKey;
      resetFeed();
      void loadFeedNext(feedQuery(filter));
    }
    const feed = feedStore.get();
    if (countEl) countEl.textContent = `${feed.items.length} 条`;
    const vms = feed.items.map((item) => toViewModel(item, readStore.get(), {}));
    mountFeedList(feedEl, vms, overview.labels.tech, () => void loadFeedNext(feedQuery(filter)));
    return;
  }

  lastFeedQuery = "";
  const vms = sortItems(
    overviewViewModels(overview).filter((vm) => matchesFilter(vm, filter)),
    filter.sort,
  );
  if (countEl) countEl.textContent = `${vms.length} 条`;
  mountFeedList(feedEl, vms, overview.labels.tech);
}

function overviewViewModels(o: Overview): NewsViewModel[] {
  const read = readStore.get();
  const out: ModuleItem[] = [];
  for (const mod of o.modules) {
    for (const item of mod.items) out.push({ ...item, module: mod.id });
  }
  return out
    .map((item) => toViewModel(item, read, o.url_sources))
    .sort((a, b) => b.fetchedAt.localeCompare(a.fetchedAt));
}

function matchesFilter(
  vm: NewsViewModel,
  filter: ReturnType<typeof filterStore.get>,
): boolean {
  if (filter.module && vm.module !== filter.module) return false;
  if (filter.tech && !vm.tags.includes(filter.tech)) return false;
  if (filter.source && vm.sourceId !== filter.source) return false;
  return true;
}

function sortItems(items: NewsViewModel[], sort: "latest" | "multi"): NewsViewModel[] {
  if (sort === "multi") {
    return [...items].sort(
      (a, b) => b.relatedCount - a.relatedCount || b.fetchedAt.localeCompare(a.fetchedAt),
    );
  }
  return items; // already sorted by fetched desc
}

function feedQuery(filter: ReturnType<typeof filterStore.get>): {
  module?: string;
  tech?: string;
  source?: string;
  since?: string;
} {
  return {
    module: filter.module || undefined,
    tech: filter.tech || undefined,
    source: filter.source || undefined,
    since: rangeCutoff(filter.range),
  };
}
