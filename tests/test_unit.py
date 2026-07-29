"""Unit tests — SSRF guard and normalization helpers (no network)."""

from __future__ import annotations

import pytest

from ai_security_hot.connectors.ssrf import SSRFError, validate_url
from ai_security_hot.parsers.normalize import (
    canonicalize_url,
    extract_identifiers,
    score_parse_quality,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/x",
        "http://127.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "https://10.0.0.5/internal",
        "ftp://example.com/x",
        "file:///etc/passwd",
    ],
)
def test_ssrf_blocks_forbidden(url: str) -> None:
    with pytest.raises(SSRFError):
        validate_url(url)


def test_ssrf_allows_public_https() -> None:
    validate_url("https://openai.com/news/rss.xml")  # no raise


def test_extract_identifiers() -> None:
    text = "See CVE-2025-12345 and GHSA-aaaa-bbbb-cccc plus CWE-79 and CNVD-2024-1234"
    ids = extract_identifiers(text)
    assert ids["cve"] == ["CVE-2025-12345"]
    assert ids["ghsa"] == ["GHSA-AAAA-BBBB-CCCC"]
    assert ids["cwe"] == ["CWE-79"]
    assert ids["cnvd"] == ["CNVD-2024-1234"]


def test_canonicalize_strips_utm() -> None:
    url = "https://x.com/a?utm_source=twitter&id=5&ref=hn#frag"
    assert canonicalize_url(url) == "https://x.com/a?id=5"


def test_parse_quality_scoring() -> None:
    assert score_parse_quality(title="T", published_at_present=True, body_text="x" * 100) == 1.0
    assert score_parse_quality(title=None, published_at_present=False, body_text=None) == 0.0
    # title + body but no date => 0.8
    assert score_parse_quality(title="T", published_at_present=False, body_text="x" * 100) == 0.8


def test_rule_classifier_basic() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x", endpoint_id="e",
        title_original="Prompt injection in LangChain agents",
        body_text="A jailbreak of the MCP tool-calling agent from Anthropic Claude.",
        canonical_url="http://x",
    )
    c = rc.classify(doc, source_id="arxiv", connector="arxiv")
    assert "security_for_ai" in c.tech_directions  # prompt injection / jailbreak
    assert "agent" in c.tech_directions            # MCP / agent
    assert "anthropic" in c.company_models         # Claude
    assert c.event_type == "research"              # source=arxiv
    assert c.method == "rule"
    assert c.rule_version and c.input_hash         # provenance recorded


def test_rule_classifier_cve_is_vulnerability() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x", endpoint_id="e", title_original="Some flaw",
        body_text="details", canonical_url="http://x", cve_ids=["CVE-2025-1"],
    )
    c = rc.classify(doc)
    assert c.event_type == "vulnerability"  # hard signal: CVE present


def test_rule_classifier_no_match_is_empty() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x", endpoint_id="e", title_original="A nice sunny day",
        body_text="nothing technical here", canonical_url="http://x",
    )
    c = rc.classify(doc)
    assert c.tech_directions == []     # general content, not force-tagged
    assert c.company_models == []


def test_inject_date_params() -> None:
    from ai_security_hot.connectors.rest import _inject_date_params

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
    cfg = {
        "start": {"param": "pubStartDate", "offset_days": 30},
        "end": {"param": "pubEndDate", "offset_days": 0},
        "format": "%Y-%m-%dT%H:%M:%S.000",
    }
    result = _inject_date_params(base, cfg)
    assert "pubStartDate=" in result
    assert "pubEndDate=" in result
    assert "resultsPerPage=200" in result
    assert "rest/json/cves/2.0?" in result


def test_inject_date_params_incremental() -> None:
    from datetime import UTC, datetime
    from urllib.parse import unquote

    from ai_security_hot.connectors.rest import _inject_date_params

    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=200"
    cfg = {
        "start": {"param": "pubStartDate", "offset_days": 30},
        "end": {"param": "pubEndDate", "offset_days": 0},
        "format": "%Y-%m-%dT%H:%M:%S.000",
    }
    last_success = datetime(2026, 7, 15, 10, 0, 0, tzinfo=UTC)
    result = _inject_date_params(base, cfg, last_success_at=last_success)
    # incremental: start should use last_success_at, not now-30d
    assert "pubStartDate=2026-07-15T10%3A00%3A00.000" in result or \
           "pubStartDate=2026-07-15T10:00:00.000" in unquote(result)
    assert "pubEndDate=" in result


def test_inject_date_params_no_config() -> None:
    from ai_security_hot.connectors.rest import _inject_date_params

    url = "https://example.com/api"
    assert _inject_date_params(url, {}) == url
