"""NVD CVE 2.0 parser — one CVE record (the `.cve` object) → document."""

from __future__ import annotations

import json
from datetime import UTC

from dateutil import parser as dateparser

from ai_security_hot.connectors.base import Parser
from ai_security_hot.domain.enums import UpstreamRecordStatus
from ai_security_hot.domain.models import NormalizedDocument, RawItem
from ai_security_hot.parsers.normalize import extract_identifiers, score_parse_quality


class NvdParser(Parser):
    version = "nvd-v2"

    @staticmethod
    def _record_status(raw_status: object) -> tuple[str, str | None]:
        value = str(raw_status).strip() if raw_status is not None else ""
        normalized = value.casefold()
        if normalized == "rejected":
            return UpstreamRecordStatus.REJECTED.value, value
        if normalized == "withdrawn":
            return UpstreamRecordStatus.WITHDRAWN.value, value
        if value:
            return UpstreamRecordStatus.PUBLISHED.value, value
        return UpstreamRecordStatus.UNKNOWN.value, None

    def parse(self, raw: RawItem) -> NormalizedDocument:
        rec = json.loads(raw.raw_text or "{}")
        cve = rec.get("id", raw.native_id)
        record_status, record_status_raw = self._record_status(rec.get("vulnStatus"))

        # English description preferred
        desc = ""
        for d in rec.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        pub = None
        if rec.get("published"):
            try:
                pub = dateparser.parse(rec["published"])
                if pub and pub.tzinfo is None:
                    pub = pub.replace(tzinfo=UTC)
            except (ValueError, OverflowError):
                pub = None

        # CWE ids live under weaknesses[].description[].value.
        # IMPORTANT: only CWE ids are scanned from the structured fields. The
        # record's OWN CVE id is its sole identity — the description may mention
        # other CVE/GHSA/CNVD ids as related context, but those are NOT this
        # record's identity, so we must not scan the description for them
        # (otherwise one NVD record fans out into one event per mentioned id).
        cwe_text = " ".join(
            wd.get("value", "")
            for w in rec.get("weaknesses", [])
            for wd in w.get("description", [])
        )
        cwe_ids = extract_identifiers(cwe_text)["cwe"]
        ids = {
            "cve": [cve] if cve else [],
            "ghsa": [],
            "cnvd": [],
            "cwe": cwe_ids,
        }

        title = f"{cve}: {desc[:80]}" if desc else cve
        return NormalizedDocument(
            raw_item_native_id=raw.native_id,
            endpoint_id=raw.endpoint_id,
            title_original=title,
            body_text=desc or None,
            canonical_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
            published_at=pub,
            published_at_utc=pub,
            language="en",
            cve_ids=ids["cve"],
            ghsa_ids=ids["ghsa"],
            cnvd_ids=ids["cnvd"],
            cwe_ids=ids["cwe"],
            record_status=record_status,
            record_status_raw=record_status_raw,
            raw_metadata={"vuln_status": record_status_raw or ""},
            parse_quality=score_parse_quality(
                title=title,
                published_at_present=pub is not None,
                body_text=desc,
                min_body_len=20,
            ),
        )
