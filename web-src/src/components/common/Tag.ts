// Tag chips — tech direction tags (weakest visual level in the feed).

import { esc } from "../../lib/dom";

export function techTagsHtml(tech: string[] | undefined, labels: Record<string, string>): string {
  const tags = (tech ?? []).filter((t) => t && t !== "cve");
  if (!tags.length) return "";
  return tags
    .map((t) => `<span class="tag ${esc(t)}">${esc(labels[t] ?? t)}</span>`)
    .join("");
}

export function companyTagsHtml(companies: string[] | undefined): string {
  const items = (companies ?? []).filter(Boolean);
  if (!items.length) return "";
  return items
    .map((c) => `<span class="tag-co">${esc(c)}</span>`)
    .join("");
}
