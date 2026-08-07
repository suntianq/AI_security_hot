// Today's hotspot block — Top 1 hero + Top 2-5 compact rows.

import { esc } from "../../lib/dom";
import { heatScoreHtml } from "../common/HeatScore";
import { techTagsHtml } from "../common/Tag";
import { fmtHHMM } from "../../lib/time";
import type { Hotspot, Labels } from "../../api/types";

export function hotBlockHtml(hotspots: Hotspot[], labels: Labels): string {
  if (!hotspots.length) return "";
  const [top, ...rest] = hotspots;
  return `
    ${heroHtml(top, labels)}
    ${rest.length ? compactHtml(rest) : ""}`;
}

function heroHtml(hot: Hotspot, labels: Labels): string {
  const topicLabel = hot.topic ? labels.tech[hot.topic] ?? hot.topic : "";
  return `
    <div class="hot-hero" onclick="location.href='/event.html?id=${hot.id}'" data-action="nav">
      <div class="hot-hero-rank">TOP 1 · ${esc(topicLabel || "热点")}</div>
      <div class="hot-hero-title">${esc(hot.title)}</div>
      ${hot.summary ? `<div class="hot-hero-summary">${esc(hot.summary)}</div>` : ""}
      <div class="hot-hero-meta">
        ${heatScoreHtml(hot.score)}
        <span class="src-count">${hot.source_count} 个信源</span>
        ${hot.last ? `<span>更新于 ${fmtHHMM(hot.last)}</span>` : ""}
      </div>
      ${hot.topic ? `<div class="hot-hero-tags">${techTagsHtml([hot.topic], labels.tech)}</div>` : ""}
    </div>`;
}

function compactHtml(rest: Hotspot[]): string {
  return `
    <div class="hot-compact">
      ${rest
        .map((h, i) => {
          const rank = String(i + 2).padStart(2, "0");
          const rankCls = i + 2 <= 3 ? ` r${i + 2}` : "";
          return `
            <div class="hot-row" onclick="location.href='/event.html?id=${h.id}'">
              <span class="hot-row-rank${rankCls}">${rank}</span>
              <div class="hot-row-body">
                <div class="hot-row-title">${esc(h.title)}</div>
                <div class="hot-row-meta">
                  ${heatScoreHtml(h.score)}
                  <span>${h.source_count} 源</span>
                </div>
              </div>
            </div>`;
        })
        .join("")}
    </div>`;
}
