"""Unit tests for the CVE follow policy (CVSS + followed software filter)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ai_security_hot.config import cve_follow
from ai_security_hot.config.cve_follow import CveFollowConfig, is_followed_cve
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem
from ai_security_hot.parsers.nvd import NvdParser


def _raw_nvd(payload: dict) -> RawItem:
    return RawItem(
        endpoint_id="nvd-recent",
        source_id="nvd",
        native_id=str(payload["id"]),
        request_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        final_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        http_status=200,
        fetched_at=datetime(2026, 8, 7, 6, 0, tzinfo=UTC),
        language="en",
        content_hash="x" * 64,
        connector_kind=ConnectorKind.NVD,
        connector_version="nvd-v2",
        raw_text=json.dumps(payload, ensure_ascii=False),
    )


def test_nvd_parser_extracts_cvss_and_products() -> None:
    payload = {
        "id": "CVE-2026-99999",
        "descriptions": [{"lang": "en", "value": "Heap overflow in Linux kernel."}],
        "metrics": {
            "cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
            ],
            "cvssMetricV2": [{"cvssData": {"baseScore": 10.0}}],
        },
        "affected": [
            {
                "affectedData": [
                    {"product": "Linux Kernel", "vendor": "Linux"},
                    {"product": "Kubernetes"},
                ]
            }
        ],
        "published": "2026-08-07T00:00:00",
        "vulnStatus": "Analyzed",
    }
    doc = NvdParser().parse(_raw_nvd(payload))
    assert doc.entities["cvss"] == ["9.8"]  # highest CVSS version (v3.1) wins over v2
    assert "linux kernel" in doc.entities["products"]
    assert "kubernetes" in doc.entities["products"]
    assert "linux" in doc.entities["vendors"]


def test_followed_cve_requires_cvss_and_keyword(monkeypatch: pytest.MonkeyPatch) -> None:
    config = CveFollowConfig(cvss_min=7.0, follow=["linux", "openssl"])
    monkeypatch.setattr(cve_follow, "get_cve_follow_config", lambda: config)

    # high cvss + linux product → kept
    assert (
        is_followed_cve({"cvss": ["9.8"], "products": ["linux kernel"]}, "Title", "Body") is True
    )
    # high cvss but no followed software → dropped
    assert (
        is_followed_cve({"cvss": ["9.8"], "products": ["oracle weblogic"]}, "Title", "Body")
        is False
    )
    # linux software but low cvss → dropped
    assert (
        is_followed_cve({"cvss": ["4.3"], "products": ["linux kernel"]}, "Title", "Body") is False
    )
    # keyword in the description body still counts
    assert (
        is_followed_cve({"cvss": ["8.0"], "products": []}, "Title", "Bugs in openssl ssl") is True
    )
    # no cvss data → dropped (cannot meet the threshold)
    assert is_followed_cve({"products": ["linux"]}, "Title", "Body") is False


def test_followed_cve_empty_follow_keeps_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cve_follow, "get_cve_follow_config", lambda: CveFollowConfig(follow=[]))
    assert is_followed_cve({}, "Anything", "No data") is True
