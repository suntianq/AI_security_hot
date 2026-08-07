// Document detail page — meta + 查看原文 + Markdown/LaTeX body.

import { initApp } from "../bootstrap";
import { getDocument } from "../api/endpoints";
import { renderDocumentBody } from "../components/document/DocumentBody";
import { techTagsHtml, companyTagsHtml } from "../components/common/Tag";
import { errorStateHtml, skeletonFeedHtml } from "../components/common/States";
import { esc } from "../lib/dom";
import { fmtDateTime } from "../lib/time";
import { markRead } from "../state/readState";
import { TECH_LABELS } from "../lib/labels";

const content = initApp({ activeNav: "document", variant: "reading" });
const id = new URLSearchParams(location.search).get("id");
if (!id) {
  content.innerHTML = errorStateHtml("缺少 id 参数", () => {
    location.href = "/";
  });
} else {
  markRead(Number(id));
  void load(id);
}

async function load(documentId: string): Promise<void> {
  content.innerHTML = skeletonFeedHtml();
  try {
    const doc = await getDocument(documentId);
    content.innerHTML = `
      <div class="page-title">${esc(doc.title)}</div>
      <div class="event-meta">
        <span class="acc">${esc(doc.source_name)}</span>
        ${doc.published_at ? `<span>${fmtDateTime(doc.published_at)}</span>` : ""}
        ${techTagsHtml(doc.tech_directions, TECH_LABELS)}
        ${companyTagsHtml(doc.company_models)}
        ${doc.event_type ? `<span class="tag">${esc(doc.event_type)}</span>` : ""}
      </div>
      <div class="mt-md">
        <a class="btn btn-primary" href="${esc(doc.url)}" target="_blank" rel="noopener">
          查看原文 ↗
        </a>
      </div>
      <div class="article-card mt-lg">
        <div class="doc-body">${renderDocumentBody(doc.body)}</div>
      </div>
    `;
  } catch (e) {
    content.innerHTML = errorStateHtml(
      e instanceof Error ? e.message : String(e),
      () => void load(documentId),
    );
  }
}
