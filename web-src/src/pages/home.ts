// Home page — today's hotspots, stats, and the latest-selected feed.
// Views: home (overview) / all (/api/feed, infinite scroll) / fav (favorites).

import { initApp } from "../bootstrap";
import {
  feedStore,
  loadFeedNext,
  loadOverview,
  overviewStore,
  resetFeed,
  uiStore,
} from "../state/app";
import { filterStore } from "../state/filter";
import { readStore } from "../state/readState";
import { favStore } from "../state/favorites";
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

subscribe();
function subscribe(): void {
  overviewStore.subscribe(render);
  uiStore.subscribe(render);
  filterStore.subscribe(render);
  feedStore.subscribe(render);
  readStore.subscribe(render);
  favStore.subscribe(render);
}

let lastFeedQuery = "";

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
  const filter = filterStore.get();
  if (filter.view === "all") {
    const queryKey = JSON.stringify(feedQuery(filter));
    if (queryKey !== lastFeedQuery) {
      lastFeedQuery = queryKey;
      resetFeed();
      void loadFeedNext(feedQuery(filter));
    }
    renderAll(overview, filter);
    return;
  }
  lastFeedQuery = "";
  if (filter.view === "fav") renderFav(overview, filter);
  else renderHome(overview, filter);
}

// ---------- view: home ----------
function renderHome(o: Overview, filter: ReturnType<typeof filterStore.get>): void {
  const hotspots = filter.heat > 0 ? o.hotspots.filter((h) => h.score >= filter.heat) : o.hotspots;
  const vms = sortItems(
    filterViewModels(o).filter((vm) => matchesFilter(vm, filter)),
    filter.sort,
  );
  const totalDocs = o.modules.reduce((n, m) => n + m.items.length, 0);
  const multiSources = o.hotspots.filter((h) => h.source_count >= 2).length;
  const sourceCount = new Set(o.modules.flatMap((m) => m.items.map((i) => i.source))).size;

  content.innerHTML = `
    <div class="page-title">${esc(o.date)} · ${esc(o.weekday)}</div>
    <div class="section-title mt-lg"><span class="bar"></span>今日热点<span class="count">${hotspots.length} 条</span></div>
    ${hotspots.length ? hotBlockHtml(hotspots, o.labels) : emptyStateHtml("今日暂无热点", "稍后再来看看。")}
    <div class="stats-bar">
      <div class="stat-item"><span class="stat-num">${totalDocs}</span><span class="stat-label">今日收录</span></div>
      <div class="stat-item"><span class="stat-num">${hotspots.length}</span><span class="stat-label">热点事件</span></div>
      <div class="stat-item"><span class="stat-num">${multiSources}</span><span class="stat-label">多源热点</span></div>
      <div class="stat-item"><span class="stat-num">${sourceCount}</span><span class="stat-label">信息源</span></div>
    </div>
    <div class="section-title"><span class="bar"></span>最新精选<span class="count">${vms.length} 条</span></div>
    <div id="filterBar"></div>
    <div id="feed"></div>
  `;
  mountFilterBar(content.querySelector<HTMLElement>("#filterBar") as HTMLElement);
  mountFeedList(content.querySelector<HTMLElement>("#feed") as HTMLElement, vms, o.labels.tech);
}

// ---------- view: all (cursor feed) ----------
function renderAll(o: Overview, filter: ReturnType<typeof filterStore.get>): void {
  const feed = feedStore.get();
  content.innerHTML = `
    <div class="page-title">全部动态</div>
    <div class="section-title mt-lg"><span class="bar"></span>资讯流<span class="count">${feed.items.length} 条</span></div>
    <div id="filterBar"></div>
    <div id="feed"></div>
    ${feed.loading ? '<div class="dim" style="padding:16px 4px">加载中…</div>' : ""}
  `;
  mountFilterBar(content.querySelector<HTMLElement>("#filterBar") as HTMLElement);
  const feedEl = content.querySelector<HTMLElement>("#feed") as HTMLElement;
  const vms = feed.items.map((item) => toViewModel(item, readStore.get(), favStore.get(), {}));
  mountFeedList(feedEl, vms, o.labels.tech, () => void loadFeedNext(feedQuery(filter)));
}

// ---------- view: fav ----------
function renderFav(o: Overview, filter: ReturnType<typeof filterStore.get>): void {
  const fav = favStore.get();
  const vms = filterViewModels(o)
    .filter((vm) => fav.has(vm.id))
    .filter((vm) => matchesFilter(vm, filter));
  content.innerHTML = `
    <div class="page-title">收藏</div>
    <div class="section-title mt-lg"><span class="bar"></span>已收藏<span class="count">${vms.length} 条</span></div>
    <div id="filterBar"></div>
    <div id="feed"></div>
  `;
  mountFilterBar(content.querySelector<HTMLElement>("#filterBar") as HTMLElement);
  mountFeedList(content.querySelector<HTMLElement>("#feed") as HTMLElement, vms, o.labels.tech);
}

// ---------- helpers ----------
function filterViewModels(o: Overview): NewsViewModel[] {
  const read = readStore.get();
  const fav = favStore.get();
  const out: ModuleItem[] = [];
  for (const mod of o.modules) {
    for (const item of mod.items) out.push({ ...item, module: mod.id });
  }
  return out
    .map((item) => toViewModel(item, read, fav, o.url_sources))
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
