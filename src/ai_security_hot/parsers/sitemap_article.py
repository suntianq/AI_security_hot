"""Sitemap article parser — reads the structured JSON produced by SitemapConnector.

The connector already extracted title/body/date via trafilatura and stored them
in ``raw_text`` as JSON.  This parser just maps those fields into a
NormalizedDocument, scans for identifiers, and scores parse quality.
"""

from __future__ import annotations

import json

from dateutil import parser as dateparser

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import (
    canonicalize_url,
    extract_identifiers,
    score_parse_quality,
)


class SitemapArticleParser(Parser):
    version = "sitemap-article-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        data = json.loads(raw.raw_text or "{}")
        title = data.get("title", "")
        body = data.get("body")
        published = None
        if data.get("published"):
            try:
                published = dateparser.parse(data["published"])
            except (ValueError, OverflowError):
                published = None
        if not published and data.get("lastmod"):
            try:
                published = dateparser.parse(data["lastmod"])
            except (ValueError, OverflowError):
                published = None

        ids = extract_identifiers(f"{title}\n{body or ''}")
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=body,
            canonical_url=canonicalize_url(data.get("url") or raw.canonical_url or raw.final_url),
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
                min_body_len=80,
            ),
        )
