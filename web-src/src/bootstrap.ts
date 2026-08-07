// Shared app shell — header + sidebar (+ right panel) + global search/theme.
// Each MPA page calls initApp() and renders its content into the returned
// element.

import "./main.css";
import { initTheme } from "./state/theme";
import { initSearchShortcut } from "./components/search/SearchDialog";
import { renderHeader } from "./components/layout/Header";
import { renderSidebar } from "./components/layout/Sidebar";
import { renderRightPanel } from "./components/layout/RightPanel";
import type { ActiveNav, Variant } from "./types";

export function initApp(opts: { activeNav: ActiveNav; variant: Variant }): HTMLElement {
  initTheme();
  initSearchShortcut();

  const app = document.querySelector<HTMLElement>("#app");
  if (!app) throw new Error("#app mount not found");
  app.innerHTML = "";

  const header = document.createElement("div");
  renderHeader(header, opts.activeNav);
  app.append(header);

  const body = document.createElement("div");
  let content: HTMLElement;

  if (opts.variant === "reading") {
    body.className = "wrap-detail";
    content = document.createElement("div");
    content.id = "pageContent";
    body.append(content);
  } else {
    body.className = "app-grid";
    const sidebar = document.createElement("aside");
    sidebar.className = "sidebar";
    content = document.createElement("main");
    content.className = "main";
    content.id = "pageContent";
    body.append(sidebar, content);
    if (opts.variant === "full") {
      const right = document.createElement("aside");
      right.className = "right-panel";
      body.append(right);
      renderRightPanel(right);
    }
    renderSidebar(sidebar, opts.activeNav);
  }

  app.append(body);
  return content;
}
