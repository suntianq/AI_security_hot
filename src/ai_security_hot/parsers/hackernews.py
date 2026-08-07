"""Hacker News API item parser — structured item JSON to a document.

The HN API item payload carries the story's own HTML ``text`` (submitter
content) plus structured metadata. HTML entities are decoded and tags stripped
so the stored body is clean readable text instead of the raw RSS summary
metadata (Comments URL / Points / # Comments) the old RSS feed produced.
"""

from __future__ import annotations

import html as html_mod
import json
import re

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import (
    canonicalize_url,
    extract_identifiers,
    score_parse_quality,
)

HN_ITEM_URL = "https://news.ycombinator.com/item?id="

_TAG_RE = re.compile(r"<[^>]+>")
_BR_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_MULTI_NL_RE = re.compile(r"\n{3,}")


class HackerNewsParser(Parser):
    version = "hackernews-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        item = _load_item(raw)
        title = str(item.get("title") or "").strip() or "Untitled"
        body = clean_hackernews_html(item.get("text"))
        url = item.get("url") or f"{HN_ITEM_URL}{raw.native_id}"
        published = raw.published_at
        ids = extract_identifiers(f"{title}\n{body}")
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=body or None,
            canonical_url=canonicalize_url(str(url)),
            author=item.get("by"),
            org="Hacker News",
            published_at=published,
            published_at_utc=published,
            language=raw.language or "en",
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=published is not None,
                body_text=body,
                min_body_len=10,
            ),
        )


def clean_hackernews_html(text: str | None) -> str:
    """Decode HTML entities and strip tags into plain text (``<br>``→newline)."""
    if not text:
        return ""
    text = html_mod.unescape(text)
    text = _BR_RE.sub("\n", text)
    text = _TAG_RE.sub("", text)
    return _MULTI_NL_RE.sub("\n\n", text).strip()


def _load_item(raw: RawItem) -> dict:
    try:
        payload = json.loads(raw.raw_text or "{}")
    except (ValueError, TypeError):
        payload = {}
    return payload if isinstance(payload, dict) else {}
