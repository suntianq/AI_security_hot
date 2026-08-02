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


def test_source_registry_key_endpoints() -> None:
    from ai_security_hot.config.sources import load_registry

    registry = load_registry()
    expected = {
        "aihot-selected-api": (
            "https://aihot.virxact.com/api/v1/selected/snapshot",
            "aihot",
            "aihot-v1",
        ),
        "apple-ml-research-rss": (
            "https://machinelearning.apple.com/rss.xml",
            "rss",
            "rss-default-v1",
        ),
        "nvidia-blog-rss": ("https://blogs.nvidia.com/feed/", "rss", "rss-default-v1"),
        "wiz-blog-rss": ("https://www.wiz.io/feed/rss.xml", "rss", "rss-default-v1"),
        "hackernews-rss": ("https://hnrss.org/frontpage", "rss", "rss-default-v1"),
        "huggingface-blog-rss": ("https://huggingface.co/blog/feed.xml", "rss", "rss-default-v1"),
        "google-security-rss": ("https://blog.google/security/rss/", "rss", "rss-default-v1"),
    }

    assert len(registry.sources) == 17
    assert len(registry.endpoints) == 19
    assert len({source.id for source in registry.sources}) == len(registry.sources)
    assert len({endpoint.id for endpoint in registry.endpoints}) == len(registry.endpoints)
    for endpoint_id, (url, connector, parser) in expected.items():
        endpoint = registry.endpoint(endpoint_id)
        assert endpoint.url == url
        assert endpoint.connector.value == connector
        assert endpoint.parser == parser

    legacy_aihot = registry.endpoint("aihot-selected-rss")
    assert legacy_aihot.enabled is False
    assert legacy_aihot.replaced_by == "aihot-selected-api"

    nvd = registry.endpoint("nvd-recent")
    assert nvd.connector.value == "nvd"
    assert nvd.parser == "nvd-v2"
    assert nvd.state_version == "3"
    assert nvd.options["nvd"]["bootstrap_days"] == 120
    assert nvd.options["nvd"]["segment_days"] == 7
    assert nvd.options["nvd"]["target_results"] == 20000


def test_url_change_resets_endpoint_checkpoint_and_health() -> None:
    from datetime import UTC, datetime

    from ai_security_hot.models.tables import SourceEndpoint
    from ai_security_hot.storage.repositories import (
        _reset_endpoint_state_for_url_change,
    )

    row = SourceEndpoint(
        id="feed",
        source_id="source",
        connector="rss",
        parser="rss-default-v1",
        url="https://old.example/feed",
        enabled=True,
        priority="P1",
        trust_tier="B",
        egress_route="direct",
        policy={},
        consecutive_failures=3,
        status="degraded",
    )
    row.etag = "old-etag"
    row.last_modified = "old-date"
    row.cursor = "old-cursor"
    row.last_error = "network failed"
    row.last_success_at = datetime(2026, 7, 1, tzinfo=UTC)
    now = datetime(2026, 7, 30, tzinfo=UTC)

    _reset_endpoint_state_for_url_change(row, now=now)

    assert row.etag is None
    assert row.last_modified is None
    assert row.cursor is None
    assert row.last_success_at is None
    assert row.consecutive_failures == 0
    assert row.status == "active"
    assert row.last_error is None
    assert row.next_run_at == now


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


def test_current_document_visibility_keeps_lifecycle_and_upstream_status_separate() -> None:
    from ai_security_hot.storage.repositories import is_current_document

    assert is_current_document("active", "published") is True
    assert is_current_document("active", "unknown") is True
    assert is_current_document("active", "rejected") is False
    assert is_current_document("active", "withdrawn") is False
    assert is_current_document("retired", "published") is False
    assert is_current_document("superseded", "published") is False


def test_rule_classifier_basic() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x",
        endpoint_id="e",
        title_original="Prompt injection in LangChain agents",
        body_text="A jailbreak of the MCP tool-calling agent from Anthropic Claude.",
        canonical_url="http://x",
    )
    c = rc.classify(doc, source_id="arxiv", connector="arxiv")
    assert "security_for_ai" in c.tech_directions  # prompt injection / jailbreak
    assert "agent" in c.tech_directions  # MCP / agent
    assert "anthropic" in c.company_models  # Claude
    assert c.event_type == "research"  # source=arxiv
    assert c.method == "rule"
    assert c.rule_version and c.input_hash  # provenance recorded


def test_rule_classifier_cve_is_vulnerability() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x",
        endpoint_id="nvd-recent",
        title_original="CVE-2025-1: RCE in an LLM agent",
        body_text="Remote code execution in an agentic language model.",
        canonical_url="http://x",
        cve_ids=["CVE-2025-1"],
    )
    c = rc.classify(doc, source_id="nvd", connector="rest")
    assert c.event_type == "vulnerability"  # hard signal: CVE present
    assert c.tech_directions == ["cve"]


def test_rule_classifier_news_and_papers_get_topic_labels() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x",
        endpoint_id="arxiv-ai-llm",
        title_original="A new large language model for tool-using agents",
        body_text="We study an LLM agent and its tool calling workflow.",
        canonical_url="http://x",
    )
    c = rc.classify(doc, source_id="arxiv", connector="arxiv")
    assert "llm" in c.tech_directions
    assert "agent" in c.tech_directions
    assert "cve" not in c.tech_directions


def test_rule_classifier_no_match_is_empty() -> None:
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    rc = RuleClassifier()
    doc = NormalizedDocument(
        raw_item_native_id="x",
        endpoint_id="e",
        title_original="A nice sunny day",
        body_text="nothing technical here",
        canonical_url="http://x",
    )
    c = rc.classify(doc)
    assert c.tech_directions == []  # general content, not force-tagged
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
    assert (
        "pubStartDate=2026-07-15T10%3A00%3A00.000" in result
        or "pubStartDate=2026-07-15T10:00:00.000" in unquote(result)
    )
    assert "pubEndDate=" in result


def test_inject_date_params_no_config() -> None:
    from ai_security_hot.connectors.rest import _inject_date_params

    url = "https://example.com/api"
    assert _inject_date_params(url, {}) == url


def test_inject_date_params_uses_overlap() -> None:
    from datetime import UTC, datetime
    from urllib.parse import unquote

    from ai_security_hot.connectors.rest import _inject_date_params

    cfg = {
        "start": {"param": "pubStartDate", "offset_days": 30},
        "end": {"param": "pubEndDate", "offset_days": 0},
        "overlap_minutes": 15,
        "format": "%Y-%m-%dT%H:%M:%S.000",
    }
    result = unquote(
        _inject_date_params(
            "https://example.com/api",
            cfg,
            last_success_at=datetime(2026, 7, 15, 10, 0, tzinfo=UTC),
        )
    )
    assert "pubStartDate=2026-07-15T09:45:00.000" in result


def test_nvd_parser_no_fanout_from_description() -> None:
    """An NVD record whose description mentions other CVEs/GHSAs must only carry
    its own CVE id — otherwise one record fans out into one event per mention."""
    from datetime import UTC, datetime

    from ai_security_hot.domain.enums import ConnectorKind
    from ai_security_hot.domain.models import RawItem
    from ai_security_hot.parsers.nvd import NvdParser

    rec = {
        "id": "CVE-2026-3258",
        "published": "2026-01-01T00:00:00Z",
        "descriptions": [
            {"lang": "en", "value": "Related to CVE-2026-7805 and GHSA-GPHH-9Q3H-JGPP."}
        ],
        "weaknesses": [{"description": [{"value": "CWE-79"}]}],
    }
    raw = RawItem(
        endpoint_id="nvd-recent", source_id="nvd", native_id="CVE-2026-3258",
        request_url="x", final_url="x", http_status=200,
        fetched_at=datetime.now(UTC), content_hash="x",
        connector_kind=ConnectorKind.NVD, connector_version="v1",
        raw_text=__import__("json").dumps(rec),
    )
    doc = NvdParser().parse(raw)
    assert doc.cve_ids == ["CVE-2026-3258"]  # own id only
    assert doc.ghsa_ids == []  # secondary GHSA mention is NOT the record's identity
    assert doc.cwe_ids == ["CWE-79"]
