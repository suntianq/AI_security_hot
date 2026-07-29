"""arXiv parser (arxiv-v1) — official-API Atom record → rich document.

Extracts abstract (body), authors, categories, PDF link and arXiv id from the
JSON preserved by ArxivConnector. Abstract is scanned for CVE/CWE etc.
"""

from __future__ import annotations

import json

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import extract_identifiers, score_parse_quality


class ArxivParser(Parser):
    version = "arxiv-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        rec = json.loads(raw.raw_text or "{}")
        title = rec.get("title", "")
        abstract = rec.get("summary", "")
        ids = extract_identifiers(f"{title}\n{abstract}")
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=abstract or None,
            canonical_url=rec.get("abs_url") or raw.canonical_url or raw.final_url,
            published_at=raw.published_at,
            published_at_utc=raw.published_at,
            language="en",
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            entities={
                "authors": rec.get("authors", []),
                "categories": rec.get("categories", []),
                "arxiv_id": [rec["arxiv_id"]] if rec.get("arxiv_id") else [],
                "pdf_url": [rec["pdf_url"]] if rec.get("pdf_url") else [],
            },
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=raw.published_at is not None,
                body_text=abstract,
                min_body_len=100,  # a real abstract is substantial
            ),
        )
