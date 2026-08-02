"""M2 event-intelligence tests (pure, deterministic, no database/network)."""

from __future__ import annotations

from datetime import UTC, datetime

from ai_security_hot.events.intelligence import (
    DedupDecision,
    IntelDocument,
    build_event_drafts,
    deduplicate_documents,
    normalize_title,
    strong_event_keys,
)

NOW = datetime(2026, 7, 30, tzinfo=UTC)


def _doc(
    document_id: int,
    title: str,
    *,
    url: str | None = None,
    source_id: str | None = None,
    endpoint_id: str | None = None,
    trust_tier: str = "B",
    identifiers: dict | None = None,
    body: str | None = "A sufficiently useful normalized article body.",
    published_at: datetime | None = NOW,
    tech_directions: list[str] | None = None,
    event_type: str | None = "news",
    parse_quality: float = 0.8,
) -> IntelDocument:
    return IntelDocument(
        id=document_id,
        endpoint_id=endpoint_id or f"endpoint-{document_id}",
        source_id=source_id or f"source-{document_id}",
        trust_tier=trust_tier,
        title=title,
        body=body,
        canonical_url=url or f"https://example.com/{document_id}",
        published_at=published_at,
        fetched_at=NOW,
        identifiers=identifiers or {},
        tech_directions=tech_directions or [],
        event_type=event_type,
        parse_quality=parse_quality,
    )


def test_title_normalization_is_width_case_and_punctuation_insensitive() -> None:
    assert (
        normalize_title("\uff23\uff4c\uff41\uff55\uff44\uff45\uff1aAgent-Security!")
        == "claude agent security"
    )


def test_exact_url_duplicate_keeps_best_trust_tier_as_master() -> None:
    documents = [
        _doc(1, "Original report", url="https://example.com/report", trust_tier="C"),
        _doc(2, "Updated report title", url="https://example.com/report/", trust_tier="A"),
    ]

    decisions = deduplicate_documents(documents)

    assert decisions[2].near_dup_of is None
    assert decisions[1] == DedupDecision(1, 2, "exact_url", 1.0)


def test_near_title_duplicate_is_detected() -> None:
    documents = [
        _doc(1, "Anthropic releases Claude agent security controls for enterprises"),
        _doc(2, "Anthropic releases new Claude agent security controls for enterprises"),
    ]

    decisions = deduplicate_documents(documents)

    assert sum(decision.near_dup_of is not None for decision in decisions.values()) == 1
    duplicate = next(decision for decision in decisions.values() if decision.near_dup_of)
    assert duplicate.duplicate_kind == "near_title"
    assert duplicate.duplicate_score and duplicate.duplicate_score >= 0.94


def test_disjoint_cves_are_never_fuzzy_merged() -> None:
    documents = [
        _doc(
            1,
            "CVE-2026-1001 remote code execution in Example Server plugin",
            url="https://example.com/shared-catalogue",
            identifiers={"cve": ["CVE-2026-1001"]},
        ),
        _doc(
            2,
            "CVE-2026-1002 remote code execution in Example Server plugin",
            url="https://example.com/shared-catalogue",
            identifiers={"cve": ["CVE-2026-1002"]},
        ),
    ]

    decisions = deduplicate_documents(documents)

    assert all(decision.near_dup_of is None for decision in decisions.values())


def test_invalid_or_oversized_identifier_is_not_an_event_key() -> None:
    document = _doc(
        1,
        "Untrusted identifier metadata",
        identifiers={"cve": ["not-a-cve", "CVE-2026-" + "1" * 500]},
    )

    assert strong_event_keys(document) == ()


def test_arxiv_event_key_ignores_paper_version() -> None:
    document = _doc(1, "Agent security paper", url="https://arxiv.org/abs/2607.26998v3")

    assert strong_event_keys(document)[0].fingerprint == "arxiv:2607.26998"


def test_same_cve_becomes_one_multi_source_event() -> None:
    documents = [
        _doc(
            1,
            "CVE-2026-1001 in Example Server",
            source_id="nvd",
            trust_tier="A",
            identifiers={"cve": ["CVE-2026-1001"]},
            tech_directions=["cve"],
            event_type="vulnerability",
        ),
        _doc(
            2,
            "Example Server exploitation analysis",
            source_id="research-blog",
            trust_tier="B",
            identifiers={"cve": ["CVE-2026-1001"]},
            tech_directions=["cve"],
        ),
    ]
    decisions = deduplicate_documents(documents)

    drafts = build_event_drafts(documents, decisions)

    event = drafts["cve:CVE-2026-1001"]
    assert event.event_type == "vulnerability"
    assert event.topic == "cve"
    assert event.evidence_level == "A"
    assert len(event.memberships) == 2
    assert event.score >= 80
    assert {link.relation_reason for link in event.memberships} == {"identifier:cve"}


def test_duplicate_component_without_strong_key_becomes_one_fallback_event() -> None:
    documents = [
        _doc(1, "A detailed report about Claude agent security", trust_tier="B"),
        _doc(2, "A detailed report about Claude agent security", trust_tier="C"),
    ]
    decisions = deduplicate_documents(documents)

    drafts = build_event_drafts(documents, decisions)

    assert len(drafts) == 1
    event = next(iter(drafts.values()))
    assert event.fingerprint.startswith("document:")
    assert len(event.memberships) == 2
    assert {member.evidence_level for member in event.memberships} == {"B", "C"}


def test_distinct_cves_become_distinct_events() -> None:
    documents = [
        _doc(1, "First issue", identifiers={"cve": ["CVE-2026-1001"]}),
        _doc(2, "Second issue", identifiers={"cve": ["CVE-2026-1002"]}),
    ]
    decisions = deduplicate_documents(documents)

    drafts = build_event_drafts(documents, decisions)

    assert set(drafts) == {"cve:CVE-2026-1001", "cve:CVE-2026-1002"}


def test_abnormal_component_never_builds_cartesian_evidence_links() -> None:
    documents = [
        _doc(
            document_id,
            f"CVE-2026-{document_id:04d} issue",
            identifiers={"cve": [f"CVE-2026-{document_id:04d}"]},
        )
        for document_id in range(1, 23)
    ]
    decisions = {
        doc.id: DedupDecision(
            doc.id, None if doc.id == 1 else 1, "exact_url" if doc.id != 1 else None, 1.0
        )
        for doc in documents
    }

    drafts = build_event_drafts(documents, decisions)

    assert len(drafts) == len(documents)
    assert sum(len(event.memberships) for event in drafts.values()) == len(documents)


def test_structured_vuln_doc_gets_namespaced_cve_key() -> None:
    # An NVD/KEV structured-vuln doc gets a cve-nvd: key so its event never
    # collides with a news article that merely mentions the same CVE id.
    nvd = _doc(
        1,
        "CVE-2026-1234: some flaw",
        endpoint_id="nvd-recent",
        identifiers={"cve": ["CVE-2026-1234"]},
    )
    keys = [key.fingerprint for key in strong_event_keys(nvd)]
    assert "cve-nvd:CVE-2026-1234" in keys
    assert not any(key.startswith("cve:") for key in keys)


def test_news_doc_mentioning_cve_keeps_general_key() -> None:
    # A news article that mentions a CVE stays on the general cve: key, separate
    # from the NVD vuln-db event for the same CVE.
    news = _doc(
        2,
        "Vendor patches CVE-2026-1234 in latest release",
        endpoint_id="portswigger-research-rss",
        identifiers={"cve": ["CVE-2026-1234"]},
    )
    keys = [key.fingerprint for key in strong_event_keys(news)]
    assert "cve:CVE-2026-1234" in keys
    assert not any(key.startswith("cve-nvd:") for key in keys)
