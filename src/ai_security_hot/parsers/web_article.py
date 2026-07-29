"""Web article parser — trafilatura extraction with parse_quality (修正 4).

Reads the HTML snapshot from the BlobStore (the connector stored it there to
keep the DB row small), extracts title/body/date, and scores whether the
parse hit the source's minimum publish bar.
"""

from __future__ import annotations

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.article import extract_article
from ai_security_hot.parsers.normalize import (
    canonicalize_url,
    extract_identifiers,
    score_parse_quality,
)
from ai_security_hot.storage.blob import get_blob_store


class WebArticleParser(Parser):
    version = "web-article-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        if raw.blob_ref:
            html = get_blob_store().get(raw.blob_ref).decode("utf-8", errors="replace")
        else:
            html = raw.raw_text or ""

        art = extract_article(html)
        title, body, published = art.title, art.body, art.published

        ids = extract_identifiers(f"{title or ''}\n{body or ''}")
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title or "",
            body_text=body,
            canonical_url=canonicalize_url(raw.canonical_url or raw.final_url),
            published_at=published,
            published_at_utc=published,
            language=raw.language,
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=published is not None,
                body_text=body,
                min_body_len=80,  # a real article page should have substantial text
            ),
        )
