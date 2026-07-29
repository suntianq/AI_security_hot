"""Shared normalization helpers: identifier extraction + parse_quality scoring."""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", re.IGNORECASE)
_CNVD = re.compile(r"CNVD-\d{4}-\d{4,6}", re.IGNORECASE)
_CWE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)

_STRIP_QUERY_KEYS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref"}


def extract_identifiers(text: str) -> dict[str, list[str]]:
    """Pull structured vuln identifiers from free text (MVP 6.3)."""

    def uniq(pat: re.Pattern[str]) -> list[str]:
        return sorted({m.upper() for m in pat.findall(text)})

    return {
        "cve": uniq(_CVE),
        "ghsa": uniq(_GHSA),
        "cnvd": uniq(_CNVD),
        "cwe": uniq(_CWE),
    }


def canonicalize_url(url: str) -> str:
    """Drop UTM/share params and fragments (system-design 6.1)."""
    parsed = urlparse(url)
    query = "&".join(
        p
        for p in parsed.query.split("&")
        if p and p.split("=", 1)[0].lower() not in _STRIP_QUERY_KEYS
    )
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, ""))


def score_parse_quality(
    *,
    title: str | None,
    published_at_present: bool,
    body_text: str | None,
    min_body_len: int = 40,
) -> float:
    """Score 0..1 whether a parse hit the source's minimum publish bar (修正 4).

    A parse that returns HTTP 200 but has no title/body is NOT a success
    (MVP §3). Weights: title 0.4, published time 0.2, usable body 0.4.
    """
    score = 0.0
    if title and title.strip():
        score += 0.4
    if published_at_present:
        score += 0.2
    if body_text and len(body_text.strip()) >= min_body_len:
        score += 0.4
    return round(score, 3)
