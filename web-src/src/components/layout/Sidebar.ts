// Left sidebar: primary nav + module categories from the overview payload.

import { overviewStore } from "../../state/app";
import { filterStore } from "../../state/filter";
import { esc } from "../../lib/dom";
import type { ActiveNav } from "../../types";

interface NavItem {
  key: string;
  label: string;
  icon: string;
  href: string;
}

const NAV: NavItem[] = [
  { key: "home", label: "首页", icon: "⌂", href: "/" },
  { key: "all", label: "全部动态", icon: "≡", href: "/?view=all" },
  { key: "daily", label: "每日简报", icon: "◫", href: "/daily.html" },
];

export function renderSidebar(container: HTMLElement, activeNav: ActiveNav): void {
  const render = (): void => {
    const filter = filterStore.get();
    const overview = overviewStore.get();
    const activeKey = activeNav === "daily" ? "daily" : filter.view;

    const navHtml = NAV.map((item) => {
      const isActive = item.key === activeKey;
      return `
        <a class="nav-item ${isActive ? "active" : ""}" href="${item.href}">
          <span class="nav-ico">${item.icon}</span>${item.label}
        </a>`;
    }).join("");

    const cats = (overview?.modules ?? [])
      .map(
        (m) => `
          <a class="nav-item ${filter.module === m.id ? "active" : ""}" href="/?category=${esc(m.id)}">
            ${esc(m.label)}
            <span class="nav-count">${m.items.length}</span>
          </a>`,
      )
      .join("");

    container.innerHTML = `
      <div class="sidebar-section">
        <div class="sidebar-label">导航</div>
        ${navHtml}
      </div>
      ${overview ? `
        <div class="sidebar-section">
          <div class="sidebar-label">分类</div>
          ${cats}
        </div>` : ""}
    `;
  };
  render();
  overviewStore.subscribe(render);
  filterStore.subscribe(render);
}
