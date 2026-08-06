"""Black Hat Briefings parser (blackhat-v1) — session JSON → rich document.

Keeps the full session record (track, format, takeaway, speakers, room) in
``entities`` / ``raw_metadata`` so downstream classification and reporting can
use them without re-fetching. The description (HTML) is stripped to plain
text for body_text.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import extract_identifiers, score_parse_quality


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    clean = re.sub(r"<[^>]+>", " ", text)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def _speaker_names(speakers: list | None) -> list[str]:
    """Flatten speaker refs; full speaker details live in the shared speakers list."""
    if not isinstance(speakers, list):
        return []
    names: list[str] = []
    for sp in speakers:
        if isinstance(sp, dict) and sp.get("person_id"):
            names.append(str(sp["person_id"]))
    return names


class BlackHatParser(Parser):
    version = "blackhat-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        rec = json.loads(raw.raw_text or "{}")
        title = rec.get("title", "") or ""
        description = _strip_html(rec.get("description"))
        takeaway = _strip_html(rec.get("takeaway"))
        body = "\n".join(part for part in (description, takeaway) if part)

        ids = extract_identifiers(f"{title}\n{description}")
        published = raw.published_at
        if published is None:
            try:
                published = datetime.fromisoformat(
                    (rec.get("iso_start_date") or "").replace("Z", "+00:00")
                )
            except ValueError:
                published = None

        # Structured session metadata that classification/reporting can use.
        entities: dict[str, list[str]] = {
            "speaker_ids": _speaker_names(rec.get("speakers")),
            "tracks": [t for t in (rec.get("track_1"), rec.get("track_2")) if t],
            "format": [rec["format"]] if rec.get("format") else [],
            "duration": [rec["duration"]] if rec.get("duration") else [],
            "tags": (
                [str(t.get("name")) for t in (rec.get("public_tags") or {}).get("tag", [])]
                if isinstance(rec.get("public_tags"), dict)
                else []
            ),
        }
        raw_metadata = {
            "room": str(rec.get("room") or ""),
            "program": str(rec.get("program") or ""),
            "iso_start_date": str(rec.get("iso_start_date") or ""),
            "iso_end_date": str(rec.get("iso_end_date") or ""),
            "session_id": str(rec.get("id") or ""),
        }

        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=body or None,
            canonical_url=raw.canonical_url or raw.final_url,
            author=rec.get("speaker_names") or None,
            published_at=published,
            published_at_utc=published,
            language="en",
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            entities=entities,
            raw_metadata=raw_metadata,
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=published is not None,
                body_text=body,
                min_body_len=60,
            ),
        )
