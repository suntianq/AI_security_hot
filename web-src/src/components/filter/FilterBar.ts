// Feed filter bar — category pills + sort + collapsible advanced panel.
// Advanced filters (time range, source) only apply to the /api/feed view;
// the overview (home) view is inherently today's data.

import { esc } from "../../lib/dom";
import { overviewStore } from "../../state/app";
import { applyFilter, filterStore, type Range, type Sort } from "../../state/filter";
import type { Overview } from "../../api/types";

const RANGES: { id: Range; label: string }[] = [
  { id: "today", label: "今天" },
  { id: "24h", label: "24 小时" },
  { id: "3d", label: "3 天" },
  { id: "7d", label: "7 天" },
];

// Single render — the page drives re-renders via its own store subscriptions.
export function mountFilterBar(container: HTMLElement): void {
  renderInto(container);
}

function barHtml(
  filter: ReturnType<typeof filterStore.get>,
  overview: Overview | null,
): string {
  const mods = overview?.modules ?? [];
  const pills = [{ id: "", label: "全部" }, ...mods.map((m) => ({ id: m.id, label: m.label }))];
  const isFeed = filter.view === "all";
  const panelOpen = containerState.panelOpen;

  return `
    <div class="filter-bar">
      ${pills
        .map(
          (p) => `
            <button class="pill ${filter.module === p.id ? "active" : ""}" data-action="module" data-id="${p.id}">
              ${esc(p.label)}
            </button>`,
        )
        .join("")}
      <div class="filter-actions">
        <button class="pill pill-sub ${filter.sort === "multi" ? "active" : ""}" data-action="sort" data-sort="multi" ${isFeed ? "hidden" : ""}>最多来源</button>
        <button class="filter-toggle ${panelOpen ? "open" : ""}" data-action="toggle-filter">筛选${panelOpen ? " ▴" : " ▾"}</button>
      </div>
    </div>
    ${isFeed && panelOpen ? panelHtml(filter, overview) : ""}
  `;
}

function panelHtml(
  filter: ReturnType<typeof filterStore.get>,
  overview: Overview | null,
): string {
  const sources = overview?.labels.source ?? {};
  return `
    <div class="filter-panel">
      <div class="filter-field">
        <label>时间</label>
        <div style="display:flex;gap:4px">
          ${RANGES.map(
            (r) => `
              <button class="pill pill-sub ${filter.range === r.id ? "active" : ""}" data-action="range" data-range="${r.id}">
                ${r.label}
              </button>`,
          ).join("")}
        </div>
      </div>
      <div class="filter-field">
        <label>来源</label>
        <select data-action="source">
          <option value="">全部来源</option>
          ${Object.entries(sources)
            .map(
              ([id, name]) =>
                `<option value="${esc(id)}" ${filter.source === id ? "selected" : ""}>${esc(name)}</option>`,
            )
            .join("")}
        </select>
      </div>
    </div>`;
}

const containerState = { panelOpen: false };

function handle(el: HTMLElement, container: HTMLElement): void {
  const action = el.dataset.action;
  if (action === "module") applyFilter({ module: el.dataset.id ?? "" });
  else if (action === "sort") applyFilter({ sort: (el.dataset.sort ?? "latest") as Sort });
  else if (action === "range") applyFilter({ range: (el.dataset.range ?? "today") as Range });
  else if (action === "source") applyFilter({ source: (el as HTMLSelectElement).value });
  else if (action === "toggle-filter") {
    containerState.panelOpen = !containerState.panelOpen;
    renderInto(container);
  }
}

function renderInto(container: HTMLElement): void {
  const filter = filterStore.get();
  const overview = overviewStore.get();
  container.innerHTML = barHtml(filter, overview);
  container.querySelectorAll<HTMLElement>("[data-action]").forEach((node) => {
    node.addEventListener("click", () => handle(node, container));
  });
}
