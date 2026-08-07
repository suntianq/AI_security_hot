// Right panel (home only): 热门标签 + 多源热点. No fake trend data.

import { overviewStore } from "../../state/app";
import { esc } from "../../lib/dom";
import type { Overview } from "../../api/types";

export function renderRightPanel(container: HTMLElement): void {
  const render = (): void => {
    const o = overviewStore.get();
    if (!o) {
      container.innerHTML = "";
      return;
    }
    container.innerHTML = `
      <div class="panel-block">${renderTags(o)}</div>
      <div class="panel-block">${renderMultiHot(o)}</div>
    `;
  };
  render();
  overviewStore.subscribe(render);
}

function renderTags(o: Overview): string {
  const counts = new Map<string, number>();
  for (const mod of o.modules) {
    for (const item of mod.items) {
      for (const tag of item.tech ?? []) counts.set(tag, (counts.get(tag) ?? 0) + 1);
    }
  }
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!top.length) return `<div class="panel-title">热门标签</div><div class="dim">暂无标签</div>`;
  return `
    <div class="panel-title">热门标签</div>
    ${top
      .map(
        ([tag, count]) => `
          <a class="panel-row" href="/?tech=${esc(tag)}">
            <span class="row-name"># ${esc(o.labels.tech[tag] ?? tag)}</span>
            <span class="row-count">${count}</span>
          </a>`,
      )
      .join("")}
  `;
}

function renderMultiHot(o: Overview): string {
  const multi = o.hotspots.filter((h) => h.source_count >= 2).slice(0, 6);
  if (!multi.length) return `<div class="panel-title">多源热点</div><div class="dim">暂无多源热点</div>`;
  return `
    <div class="panel-title">多源热点</div>
    ${multi
      .map(
        (h, i) => `
          <a class="panel-row" href="/event.html?id=${h.id}">
            <span class="row-num">${String(i + 1).padStart(2, "0")}</span>
            <span class="row-name">${esc(h.title)}</span>
            <span class="row-count">${h.source_count} 源</span>
          </a>`,
      )
      .join("")}
  `;
}
