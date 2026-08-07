// Daily briefing — digest stats, 今日必看 hotspots, per-domain sections,
// plus the archive date switcher for history browsing.

import { initApp } from "../bootstrap";
import { getArchive, getArchives } from "../api/endpoints";
import { hotBlockHtml } from "../components/hot/HotEvents";
import { mountFeedList } from "../components/feed/FeedList";
import { toViewModel } from "../api/adapters";
import { errorStateHtml, emptyStateHtml, skeletonFeedHtml } from "../components/common/States";
import { readStore } from "../state/readState";
import { favStore } from "../state/favorites";
import { esc } from "../lib/dom";
import { weekdayCn } from "../lib/time";
import type { Overview } from "../api/types";

const content = initApp({ activeNav: "daily", variant: "detail" });
void load();

async function load(): Promise<void> {
  content.innerHTML = skeletonFeedHtml();
  try {
    const { dates } = await getArchives();
    if (!dates.length) {
      content.innerHTML = emptyStateHtml("每日简报尚未生成", "worker 会自动生成每日归档。");
      return;
    }
    let date = new URLSearchParams(location.search).get("date") ?? dates[0];
    if (!dates.includes(date)) date = dates[0];
    const payload = await getArchive(date);
    render(payload, date, dates);
  } catch (e) {
    content.innerHTML = errorStateHtml(
      e instanceof Error ? e.message : String(e),
      () => void load(),
    );
  }
}

function render(payload: Overview, date: string, dates: string[]): void {
  const read = readStore.get();
  const fav = favStore.get();
  const totalDocs = payload.modules.reduce((n, m) => n + m.items.length, 0);
  const multiSources = payload.hotspots.filter((h) => h.source_count >= 2).length;
  const sourceCount = new Set(payload.modules.flatMap((m) => m.items.map((i) => i.source))).size;

  content.innerHTML = `
    <div class="page-title">每日热点简报</div>
    <div class="dim mt-sm">${esc(payload.date)} · ${esc(payload.weekday)}</div>
    <div id="dateTabs" class="mt-md"></div>
    <div class="daily-stats">
      <div class="stat-item"><span class="stat-num">${totalDocs}</span><span class="stat-label">当日收录</span></div>
      <div class="stat-item"><span class="stat-num">${payload.hotspots.length}</span><span class="stat-label">热点事件</span></div>
      <div class="stat-item"><span class="stat-num">${multiSources}</span><span class="stat-label">多源热点</span></div>
      <div class="stat-item"><span class="stat-num">${sourceCount}</span><span class="stat-label">信息源</span></div>
    </div>
    <div class="daily-section">
      <div class="section-title"><span class="bar"></span>今日必看<span class="count">${payload.hotspots.length} 条</span></div>
      ${payload.hotspots.length ? hotBlockHtml(payload.hotspots, payload.labels) : emptyStateHtml("当日暂无热点")}
    </div>
    ${payload.modules
      .map(
        (mod, i) => `
          <div class="daily-section">
            <div class="section-title"><span class="bar"></span>${esc(mod.label)}
              <span class="count">${mod.items.length} 条</span>
            </div>
            <div id="mod-${i}"></div>
          </div>`,
      )
      .join("")}
  `;

  renderTabs(date, dates);
  payload.modules.forEach((mod, i) => {
    const el = content.querySelector<HTMLElement>(`#mod-${i}`);
    if (!el) return;
    const vms = mod.items.map((item) =>
      toViewModel({ ...item, module: mod.id }, read, fav, payload.url_sources),
    );
    mountFeedList(el, vms, payload.labels.tech, undefined, true);
  });
}

function renderTabs(active: string, dates: string[]): void {
  const tabs = content.querySelector<HTMLElement>("#dateTabs");
  if (!tabs) return;
  tabs.innerHTML = dates
    .map(
      (d) => `
        <button class="pill ${d === active ? "active" : ""}" data-date="${esc(d)}">
          ${esc(d.slice(5))} ${esc(weekdayCn(d))}
        </button>`,
    )
    .join("");
  tabs.addEventListener("click", (event) => {
    const btn = (event.target as HTMLElement | null)?.closest<HTMLElement>("[data-date]");
    if (!btn || btn.dataset.date === active) return;
    const next = btn.dataset.date as string;
    const url = new URL(location.href);
    url.searchParams.set("date", next);
    history.pushState(null, "", url.toString());
    void getArchive(next).then((payload) => render(payload, next, dates));
  });
}
