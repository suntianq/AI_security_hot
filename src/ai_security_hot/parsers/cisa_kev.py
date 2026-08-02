"""CISA KEV parser — one known-exploited vulnerability record → document."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import extract_identifiers, score_parse_quality


class CisaKevParser(Parser):
    version = "cisa-kev-v1"

    def parse(self, raw: RawItem) -> NormalizedDocument:
        rec = json.loads(raw.raw_text or "{}")
        cve = rec.get("cveID", raw.native_id)
        title = f"{cve}: {rec.get('vulnerabilityName', '')}".strip(": ")
        body = rec.get("shortDescription", "")
        date_added = rec.get("dateAdded")
        pub = None
        if date_added:
            pub = datetime.fromisoformat(date_added).replace(tzinfo=UTC)
        # KEV record's sole CVE identity is cveID; only CWE ids come from the
        # structured cwes field (do not scan the description for secondary CVE
        # mentions — that would fan one record out into multiple events).
        cwe_ids = extract_identifiers(str(rec.get("cwes") or ""))["cwe"]
        ids = {
            "cve": [cve] if cve else [],
            "ghsa": [],
            "cnvd": [],
            "cwe": cwe_ids,
        }
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=body or None,
            canonical_url=raw.canonical_url or raw.final_url,
            org=rec.get("vendorProject"),
            published_at=pub,
            published_at_utc=pub,
            language="en",
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            entities={
                "vendors": [rec["vendorProject"]] if rec.get("vendorProject") else [],
                "products": [rec["product"]] if rec.get("product") else [],
            },
            raw_metadata={
                "known_ransomware": str(rec.get("knownRansomwareCampaignUse", "")),
                "required_action": str(rec.get("requiredAction", "")),
            },
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=pub is not None,
                body_text=body,
                min_body_len=10,
            ),
        )
