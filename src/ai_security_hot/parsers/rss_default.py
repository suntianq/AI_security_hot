"""Default RSS parser — maps an RSS RawItem to a NormalizedDocument."""

from __future__ import annotations

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import (
    canonicalize_url,
    extract_identifiers,
    score_parse_quality,
)


class RssDefaultParser(Parser):
    version = "rss-default-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        text = raw.raw_text or ""
        title, _, body = text.partition("\n\n")
        ids = extract_identifiers(text)
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title.strip(),
            body_text=body.strip() or None,
            canonical_url=canonicalize_url(raw.canonical_url or raw.final_url),
            published_at=raw.published_at,
            published_at_utc=raw.published_at,
            language=raw.language,
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=raw.published_at is not None,
                body_text=body,
                min_body_len=10,
            ),
        )
