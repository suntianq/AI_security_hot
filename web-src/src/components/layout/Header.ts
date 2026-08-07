// Sticky top header: brand, centered search trigger, actions, mobile menu.

import { themeStore, toggleTheme } from "../../state/theme";
import { openSearch } from "../search/SearchDialog";
import { overviewStore } from "../../state/app";
import { fmtHHMM } from "../../lib/time";
import type { ActiveNav } from "../../types";

export function renderHeader(container: HTMLElement, activeNav: ActiveNav): void {
  container.innerHTML = `
    <div class="app-header">
      <div class="header-inner">
        <button class="icon-btn menu-btn" data-action="menu" aria-label="菜单">☰</button>
        <a class="brand" href="/">
          <span class="logo">AI</span>Security Hot
          <span class="tagline">每日热点情报</span>
        </a>
        <button class="search-trigger" data-action="search">
          <span>🔍</span> 搜索标题、摘要、标签、来源…
          <span class="kbd">⌘K</span>
        </button>
        <div class="header-actions">
          ${backLink(activeNav)}
          <span class="header-updated" id="headerUpdated"></span>
          <button class="icon-btn" data-action="refresh" title="刷新" aria-label="刷新">↻</button>
          <button class="icon-btn" data-action="theme" title="切换主题" aria-label="切换主题">◐</button>
        </div>
      </div>
    </div>
  `;

  container.addEventListener("click", (event) => {
    const target = (event.target as HTMLElement | null)?.closest<HTMLElement>("[data-action]");
    if (!target) return;
    const action = target.dataset.action;
    if (action === "search") openSearch();
    else if (action === "theme") toggleTheme();
    else if (action === "refresh") location.reload();
    else if (action === "menu") {
      document.body.classList.toggle("mobile-open");
      if (!qsScrim()) {
        const scrim = document.createElement("div");
        scrim.className = "mobile-scrim";
        scrim.addEventListener("click", () => document.body.classList.remove("mobile-open"));
        document.body.append(scrim);
      }
    }
  });

  themeStore.subscribe(() => {
    const btn = container.querySelector<HTMLElement>('[data-action="theme"]');
    if (btn) btn.title = themeStore.get() === "dark" ? "切换为浅色" : "切换为深色";
  });

  const update = overviewStore.get();
  const updated = container.querySelector<HTMLElement>("#headerUpdated");
  if (updated && update) updated.textContent = `最后更新 ${fmtHHMM(update.generated_at)}`;
  overviewStore.subscribe((o) => {
    const el = container.querySelector<HTMLElement>("#headerUpdated");
    if (el && o) el.textContent = `最后更新 ${fmtHHMM(o.generated_at)}`;
  });
}

function backLink(activeNav: ActiveNav): string {
  if (activeNav === "event" || activeNav === "document") {
    const href = history.length > 1 ? "javascript:history.back()" : "/";
    return `<a class="icon-btn" href="${href}" title="返回" aria-label="返回">←</a>`;
  }
  return "";
}

function qsScrim(): HTMLElement | null {
  return document.querySelector<HTMLElement>(".mobile-scrim");
}
