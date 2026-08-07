// Global search dialog — Cmd/Ctrl+K, debounced, grouped results.
// 热点事件 matched client-side on loaded hotspots; 资讯 via /api/search.

import { esc } from "../../lib/dom";
import { searchAll } from "../../api/endpoints";
import { overviewStore } from "../../state/app";
import type { ModuleItem, SearchResponse } from "../../api/types";

let overlay: HTMLElement | null = null;
let input: HTMLInputElement | null = null;
let debounceTimer = 0;

export function openSearch(): void {
  ensureDialog();
  if (!overlay) return;
  overlay.hidden = false;
  input?.focus();
  input?.select();
}

export function initSearchShortcut(): void {
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openSearch();
    } else if (event.key === "Escape") {
      closeSearch();
    }
  });
}

function closeSearch(): void {
  if (overlay) overlay.hidden = true;
}

function ensureDialog(): void {
  if (overlay) return;
  overlay = document.createElement("div");
  overlay.className = "search-overlay";
  overlay.hidden = true;
  overlay.innerHTML = `
    <div class="search-dialog" role="dialog" aria-modal="true" aria-label="搜索">
      <div class="search-input-row">
        <span>🔍</span>
        <input class="search-input" type="search" placeholder="搜索标题、摘要、标签、来源…" autocomplete="off" />
        <button class="filter-toggle" data-action="close">Esc</button>
      </div>
      <div class="search-results"></div>
      <div class="search-hint">Enter 打开 · Esc 关闭</div>
    </div>`;
  input = overlay.querySelector<HTMLInputElement>(".search-input");
  const results = overlay.querySelector<HTMLElement>(".search-results");

  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeSearch();
    if ((event.target as HTMLElement | null)?.closest('[data-action="close"]')) closeSearch();
  });

  input?.addEventListener("input", () => {
    window.clearTimeout(debounceTimer);
    const q = input?.value.trim() ?? "";
    if (q.length < 2) {
      if (results) results.innerHTML = q ? `<div class="search-empty">至少输入 2 个字符</div>` : "";
      return;
    }
    debounceTimer = window.setTimeout(() => void runSearch(q, results), 250);
  });

  input?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      const link = overlay?.querySelector<HTMLAnchorElement>(".search-item");
      if (link) link.click();
    }
  });

  document.body.append(overlay);
}

async function runSearch(q: string, results: HTMLElement | null): Promise<void> {
  if (!results) return;
  const overview = overviewStore.get();
  const hotHits = (overview?.hotspots ?? [])
    .filter((h) => h.title.toLowerCase().includes(q.toLowerCase()) || h.summary.toLowerCase().includes(q.toLowerCase()))
    .slice(0, 5);
  let docs: SearchResponse | null = null;
  try {
    docs = await searchAll({ q, limit: 10 });
  } catch {
    docs = null;
  }
  const hotHtml = hotHits.length
    ? `<div class="search-group-title">热点事件</div>
       ${hotHits
         .map(
           (h) => `
             <a class="search-item" href="/event.html?id=${h.id}">
               <div class="search-item-title">${esc(h.title)}</div>
               <div class="search-item-meta">热度 ${h.score} · ${h.source_count} 个信源</div>
             </a>`,
         )
         .join("")}`
    : "";
  const docItems = docs?.items ?? [];
  const docHtml = docItems.length
    ? `<div class="search-group-title">资讯</div>
       ${docItems
         .map(
           (d: ModuleItem) => `
             <a class="search-item" href="/document.html?id=${d.document_id}">
               <div class="search-item-title">${esc(d.title)}</div>
               <div class="search-item-meta">${esc(d.source_name)} · ${esc(d.module ?? "")}</div>
             </a>`,
         )
         .join("")}`
    : "";
  if (!hotHtml && !docHtml) {
    results.innerHTML = `<div class="search-empty">没有找到「${esc(q)}」相关内容</div>`;
    return;
  }
  results.innerHTML = `${hotHtml}${docHtml}`;
}
