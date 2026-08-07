// Event detail page sections — header, summary, evidence timeline.

import { esc } from "../../lib/dom";
import { heatScoreHtml } from "../common/HeatScore";
import { fmtDateTime } from "../../lib/time";
import type { EventDetail } from "../../api/types";

export function eventHeaderHtml(e: EventDetail, techLabels: Record<string, string>): string {
  const topic = e.topic ? techLabels[e.topic] ?? e.topic : "";
  const sources = new Set(e.evidence.map((ev) => ev.source_name)).size;
  return `
    <div class="page-title">${esc(e.title)}</div>
    <div class="event-meta">
      ${topic ? `<span class="tag ${esc(e.topic ?? "")}">${esc(topic)}</span>` : ""}
      ${e.score != null ? heatScoreHtml(e.score) : ""}
      ${e.event_type ? `<span class="tag">${esc(e.event_type)}</span>` : ""}
      ${e.first_seen_at ? `<span>首次 ${fmtDateTime(e.first_seen_at)}</span>` : ""}
      ${e.last_seen_at ? `<span>最近 ${fmtDateTime(e.last_seen_at)}</span>` : ""}
      <span>${sources} 个信源 · ${e.evidence.length} 篇证据</span>
    </div>`;
}

export function eventSummaryHtml(e: EventDetail): string {
  return e.summary ? `<div class="event-summary">${esc(e.summary)}</div>` : "";
}

export function eventTimelineHtml(e: EventDetail): string {
  const items = e.evidence ?? [];
  return `
    <div class="section-title"><span class="bar"></span>事件时间线 · 相关报道
      <span class="count">${items.length} 篇</span>
    </div>
    <div class="timeline">
      ${items
        .map(
          (ev) => `
            <div class="tl-item" onclick="location.href='/document.html?id=${ev.document_id}'">
              <div class="tl-time">
                ${fmtDateTime(ev.published_at)}
                · <span class="tl-source">${esc(ev.source_name)}</span>
              </div>
              <div class="tl-title">${esc(ev.title)}</div>
              ${ev.relation_reason ? `<div class="tl-reason">${esc(ev.relation_reason)}</div>` : ""}
            </div>`,
        )
        .join("") || '<div class="dim">无证据文档</div>'}
    </div>`;
}
