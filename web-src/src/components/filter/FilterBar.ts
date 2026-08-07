// Self-contained filter bar. Mounted once; re-renders ITSELF on filter
// changes so the page never recreates it (which used to close the source
// dropdown). Source <select> listens to `change`, not `click`.

import { esc } from "../../lib/dom";
import { overviewStore } from "../../state/app";
import { filterStore, type FilterState, type Range, type Sort } from "../../state/filter";
import type { Overview } from "../../api/types";

const RANGES: { id: Range; label: string }[] = [
  { id: "today", label: "今天" },
  { id: "24h", label: "24 小时" },
  { id: "3d", label: "3 天" },
  { id: "7d", label: "7 天" },
];

export interface FilterBarCallbacks {
  onChange: (partial: Partial<FilterState>) => void;
}

export function mountFilterBar(container: HTMLElement, cb: FilterBarCallbacks): void {
  let panelOpen = false;

  const render = (): void => {
    const filter = filterStore.get();
    const overview = overviewStore.get();
    const isAll = filter.view === "all";
    const mods = overview?.modules ?? [];
    container.innerHTML = `
      <div class="filter-bar">
        ${modulePills(mods, filter)}
        <div class="filter-actions">
          ${isAll ? "" : sortPill(filter)}
          <button class="filter-toggle ${panelOpen ? "open" : ""}" data-action="filter-toggle">
            筛选${panelOpen ? " ▴" : " ▾"}
          </button>
        </div>
      </div>
      ${panelOpen ? (isAll ? allPanel(overview, filter) : homePanel(overview, filter)) : ""}
    `;
    bind(container, cb, () => {
      panelOpen = !panelOpen;
      render();
    });
  };

  render();
  filterStore.subscribe(render);
}

function modulePills(mods: Overview["modules"], filter: FilterState): string {
  const pills = [{ id: "", label: "全部" }, ...mods.map((m) => ({ id: m.id, label: m.label }))];
  return pills
    .map(
      (p) => `
        <button class="pill ${filter.module === p.id ? "active" : ""}" data-action="module" data-id="${esc(p.id)}">
          ${esc(p.label)}
        </button>`,
    )
    .join("");
}

function sortPill(filter: FilterState): string {
  return `
    <button class="pill pill-sub ${filter.sort === "multi" ? "active" : ""}" data-action="sort" data-sort="multi">
      最多来源
    </button>`;
}

function homePanel(overview: Overview | null, filter: FilterState): string {
  const techs = Object.entries(overview?.labels.tech ?? {});
  const sources = overview?.labels.source ?? {};
  return `
    <div class="filter-panel">
      <div class="filter-field">
        <label>技术方向</label>
        <div style="display:flex;gap:4px;flex-wrap:wrap">
          <button class="pill pill-sub ${filter.tech === "" ? "active" : ""}" data-action="tech" data-id="">全部</button>
          ${techs
            .map(
              ([id, label]) => `
                <button class="pill pill-sub ${filter.tech === id ? "active" : ""}" data-action="tech" data-id="${esc(id)}">
                  ${esc(label)}
                </button>`,
            )
            .join("")}
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

function allPanel(overview: Overview | null, filter: FilterState): string {
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

function bind(
  container: HTMLElement,
  cb: FilterBarCallbacks,
  onToggle: () => void,
): void {
  container.querySelectorAll<HTMLElement>('[data-action="module"]').forEach((el) => {
    el.addEventListener("click", () => cb.onChange({ module: el.dataset.id ?? "" }));
  });
  container.querySelectorAll<HTMLElement>('[data-action="sort"]').forEach((el) => {
    el.addEventListener("click", () => cb.onChange({ sort: (el.dataset.sort ?? "latest") as Sort }));
  });
  container.querySelectorAll<HTMLElement>('[data-action="range"]').forEach((el) => {
    el.addEventListener("click", () => cb.onChange({ range: (el.dataset.range ?? "today") as Range }));
  });
  container.querySelectorAll<HTMLElement>('[data-action="tech"]').forEach((el) => {
    el.addEventListener("click", () => cb.onChange({ tech: el.dataset.id ?? "" }));
  });
  const source = container.querySelector<HTMLSelectElement>('select[data-action="source"]');
  if (source) {
    source.addEventListener("change", () => cb.onChange({ source: source.value }));
  }
  const toggle = container.querySelector<HTMLElement>('[data-action="filter-toggle"]');
  if (toggle) toggle.addEventListener("click", onToggle);
}
