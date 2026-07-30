"""Parser for AI HOT v1 selected items."""

from __future__ import annotations

import json

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import extract_identifiers, score_parse_quality


class AIHotParser(Parser):
    version = "aihot-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        item = json.loads(raw.raw_text or "{}")
        translated = str(item.get("title") or "").strip()
        original = str(item.get("originalTitle") or translated).strip()
        summary = str(item.get("summary") or "").strip()
        source = item.get("source") or {}
        text = f"{original}\n{translated}\n{summary}"
        ids = extract_identifiers(text)
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=original,
            title_zh=translated if translated and translated != original else None,
            body_text=summary or None,
            canonical_url=raw.canonical_url or raw.final_url,
            org=source.get("name"),
            published_at=raw.published_at,
            published_at_utc=raw.published_at,
            language=raw.language,
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            raw_metadata={
                "aihot_id": raw.native_id,
                "category": str(item.get("category") or ""),
                "score": str(item.get("score") or ""),
            },
            parse_quality=score_parse_quality(
                title=original,
                published_at_present=raw.published_at is not None,
                body_text=summary,
                min_body_len=10,
            ),
        )
