// Date-grouped feed list with sticky, collapsible headers.

import { esc } from "../../lib/dom";
import { feedItemHtml } from "./FeedItem";
import { relativeDayLabel, shanghaiDateKey, weekdayCn } from "../../lib/time";
import { markRead } from "../../state/readState";
import type { NewsViewModel } from "../../api/adapters";

export interface FeedGroup {
  key: string;
  label: string;
  items: NewsViewModel[];
}

export function groupByDate(items: NewsViewModel[]): FeedGroup[] {
  const map = new Map<string, NewsViewModel[]>();
  for (const item of items) {
    const key = shanghaiDateKey(item.fetchedAt) || "其他";
    const list = map.get(key);
    if (list) list.push(item);
    else map.set(key, [item]);
  }
  const keys = [...map.keys()].sort((a, b) => (a === "其他" ? 1 : b === "其他" ? -1 : b.localeCompare(a)));
  return keys.map((key) => ({
    key,
    label: key === "其他" ? "其他" : `${relativeDayLabel(key)} · ${key} ${weekdayCn(key)}`,
    items: map.get(key) ?? [],
  }));
}

export function mountFeedList(
  container: HTMLElement,
  items: NewsViewModel[],
  techLabels: Record<string, string>,
  onLoadMore?: () => void,
  flat = false,
): void {
  const html = flat
    ? items.map((item) => feedItemHtml(item, techLabels)).join("")
    : groupByDate(items)
        .map(
          (group) => `
            <section class="feed-group" data-key="${esc(group.key)}">
              <div class="feed-group-head">
                <span class="chevron">▼</span>${esc(group.label)}
                <span class="group-count">${group.items.length} 条</span>
              </div>
              <div class="feed-group-body">
                ${group.items.map((item) => feedItemHtml(item, techLabels)).join("")}
              </div>
            </section>`,
        )
        .join("");
  container.innerHTML = html;

  container.addEventListener("click", (event) => {
    const target = event.target as HTMLElement | null;
    const item = target?.closest<HTMLElement>(".feed-item");
    const link = target?.closest<HTMLElement>("a");
    if (item && !link) {
      const id = Number(item.dataset.id);
      markRead(id);
      location.href = `/document.html?id=${id}`;
    }
    const head = target?.closest<HTMLElement>(".feed-group-head");
    if (head) {
      head.closest<HTMLElement>(".feed-group")?.classList.toggle("collapsed");
    }
  });

  if (onLoadMore) {
    const sentinel = document.createElement("div");
    sentinel.className = "feed-sentinel";
    sentinel.dataset.testid = "load-more";
    container.append(sentinel);
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) onLoadMore();
      },
      { rootMargin: "600px" },
    );
    observer.observe(sentinel);
  }
}
