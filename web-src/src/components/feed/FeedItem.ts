// A single feed row. Title > summary > metadata > tags (weakest).
// Read items dim; 原文 link reveals on hover.

import { esc } from "../../lib/dom";
import { techTagsHtml } from "../common/Tag";
import { fmtHHMM } from "../../lib/time";
import type { NewsViewModel } from "../../api/adapters";

export function feedItemHtml(vm: NewsViewModel, techLabels: Record<string, string>): string {
  const readCls = vm.read ? " read" : "";
  return `
    <div class="feed-item${readCls}" data-id="${vm.id}">
      <div class="feed-item-top">
        <span class="feed-item-source">${esc(vm.sourceName)}</span>
        <span class="feed-item-time">${fmtHHMM(vm.fetchedAt)}</span>
        ${vm.relatedCount > 0 ? `<span class="dim">另有 ${vm.relatedCount} 家信源</span>` : ""}
      </div>
      <a class="feed-item-title" href="/document.html?id=${vm.id}">${esc(vm.title)}</a>
      ${vm.summary ? `<div class="feed-item-summary">${esc(vm.summary)}</div>` : ""}
      <div class="feed-item-meta">${techTagsHtml(vm.tags, techLabels)}</div>
      <div class="feed-item-actions">
        <a class="ext-link" href="${esc(vm.url)}" target="_blank" rel="noopener" title="查看原文">↗</a>
      </div>
    </div>`;
}
