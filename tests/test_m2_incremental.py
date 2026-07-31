"""M2.1 signatures, conservative candidates and evaluation tests."""

from __future__ import annotations

from datetime import UTC, datetime

from ai_security_hot.events.evaluation import evaluate_records
from ai_security_hot.events.intelligence import (
    IntelDocument,
    deduplicate_documents,
    strong_event_keys,
)
from ai_security_hot.events.signatures import (
    SIGNATURE_VERSION,
    assess_candidate,
    build_document_signature,
    extract_document_identities,
    minhash_similarity,
    simhash_distance,
)

NOW = datetime(2026, 7, 31, tzinfo=UTC)


def _doc(
    document_id: int,
    title: str,
    *,
    url: str | None = None,
    body: str | None = None,
    identifiers: dict | None = None,
    entities: dict | None = None,
    event_type: str | None = "news",
) -> IntelDocument:
    return IntelDocument(
        id=document_id,
        endpoint_id=f"endpoint-{document_id}",
        source_id=f"source-{document_id}",
        trust_tier="B",
        title=title,
        body=body or f"Detailed evidence for {title}. " * 20,
        canonical_url=url or f"https://example.com/{document_id}",
        published_at=NOW,
        fetched_at=NOW,
        identifiers=identifiers or {},
        tech_directions=["security_for_ai"],
        event_type=event_type,
        parse_quality=0.9,
        entities=entities or {},
    )


def test_signature_is_versioned_deterministic_and_bounded() -> None:
    document = _doc(
        1,
        "Anthropic launches Claude agent security controls for enterprise developers",
    )

    left = build_document_signature(document)
    right = build_document_signature(document)

    assert SIGNATURE_VERSION == "signature-v3"
    assert left == right
    assert simhash_distance(left.simhash, right.simhash) == 0
    assert minhash_similarity(left.minhash, right.minhash) == 1.0
    assert len(left.block_tokens) <= 40


def test_strong_record_fragment_is_part_of_url_signature() -> None:
    feed = "https://example.com/catalogue.json"
    left = _doc(
        1,
        "First vulnerability record",
        url=f"{feed}#CVE-2026-1001",
        identifiers={"cve": ["CVE-2026-1001"]},
    )
    right = _doc(
        2,
        "Second vulnerability record",
        url=f"{feed}#CVE-2026-1002",
        identifiers={"cve": ["CVE-2026-1002"]},
    )

    assert build_document_signature(left).url_hash != build_document_signature(right).url_hash


def test_similar_but_not_exact_document_enters_review_queue() -> None:
    left = _doc(
        1,
        "Anthropic launches new Claude Code security scanner for enterprise developers",
    )
    right = _doc(
        2,
        "Anthropic unveils Claude Code security scanning for enterprise development teams",
    )

    assessment = assess_candidate(left, right)
    cached_assessment = assess_candidate(
        left,
        right,
        left_signature=build_document_signature(left),
        right_signature=build_document_signature(right),
    )

    assert assessment.decision == "review"
    assert assessment.reason == "semantic_candidate"
    assert 0.82 <= assessment.score < 0.94
    assert cached_assessment == assessment


def test_approved_review_merges_candidate_but_not_strong_conflict() -> None:
    left = _doc(
        1,
        "Anthropic launches new Claude Code security scanner for enterprise developers",
    )
    right = _doc(
        2,
        "Anthropic unveils Claude Code security scanning for enterprise development teams",
    )

    before = deduplicate_documents([left, right])
    after = deduplicate_documents([left, right], approved_pairs={(left.id, right.id)})

    assert all(decision.near_dup_of is None for decision in before.values())
    duplicate = next(decision for decision in after.values() if decision.near_dup_of)
    assert duplicate.duplicate_kind == "review_approved"

    conflict_left = _doc(
        3,
        "Identical release headline for a security update",
        url="https://github.com/acme/agent/releases/tag/v1.2.0",
    )
    conflict_right = _doc(
        4,
        "Identical release headline for a security update",
        url="https://github.com/acme/agent/releases/tag/v1.3.0",
    )
    blocked = deduplicate_documents(
        [conflict_left, conflict_right],
        approved_pairs={(conflict_left.id, conflict_right.id)},
    )

    assert all(decision.near_dup_of is None for decision in blocked.values())


def test_strong_release_conflict_blocks_even_high_title_similarity() -> None:
    left = _doc(
        1,
        "Project security release fixes critical agent vulnerability",
        url="https://github.com/acme/agent/releases/tag/v1.2.0",
    )
    right = _doc(
        2,
        "Project security release fixes critical agent vulnerability",
        url="https://github.com/acme/agent/releases/tag/v1.3.0",
    )

    assessment = assess_candidate(left, right)

    assert assessment.decision == "separate"
    assert assessment.conflict == "conflict:github_release"


def test_model_and_package_versions_are_event_keys_only_for_releases() -> None:
    entities = {
        "model_versions": [{"model": "Claude Sonnet", "version": "4.5"}],
        "packages": [{"name": "agent-sdk", "version": "2.1.0"}],
    }
    mention = _doc(1, "A benchmark mentions current model versions", entities=entities)
    release = _doc(
        2,
        "New model and package versions released",
        entities=entities,
        event_type="release",
    )

    assert strong_event_keys(mention) == ()
    assert {key.kind for key in strong_event_keys(release)} == {
        "model_release",
        "package_release",
    }


def test_repository_string_is_one_identity_not_character_identities() -> None:
    document = _doc(
        1,
        "Repository publishes a security advisory",
        entities={"repositories": "https://github.com/acme/agent"},
    )

    repositories = [
        identity
        for identity in extract_document_identities(document)
        if identity.kind == "repository"
    ]

    assert len(repositories) == 1
    assert repositories[0].value == "https://github.com/acme/agent"


def test_quality_metrics_report_false_merges_and_source_coverage() -> None:
    records = [
        {
            "case_id": "dedupe-positive",
            "task": "dedupe_pair",
            "should_merge": True,
            "left": {"title": "Same sufficiently long security announcement title"},
            "right": {"title": "Same sufficiently long security announcement title"},
        },
        {
            "case_id": "dedupe-conflict",
            "task": "dedupe_pair",
            "should_merge": False,
            "left": {
                "title": "Same vulnerability catalogue description for two records",
                "identifiers": {"cve": ["CVE-2026-1001"]},
            },
            "right": {
                "title": "Same vulnerability catalogue description for two records",
                "identifiers": {"cve": ["CVE-2026-1002"]},
            },
        },
        {
            "case_id": "rank-first-party",
            "task": "ranking_event",
            "score": 90,
            "relevant": True,
            "first_party": True,
        },
        {
            "case_id": "rank-secondary",
            "task": "ranking_event",
            "score": 80,
            "relevant": True,
            "first_party": False,
        },
    ]

    result = evaluate_records(records, top_n=2)

    assert result["dedupe"]["precision"] == 1.0
    assert result["dedupe"]["recall"] == 1.0
    assert result["dedupe"]["wrong_merge_rate"] == 0.0
    assert result["top_n_relevance"] == 1.0
    assert result["first_party_coverage"] == 0.5


def test_quality_metrics_can_be_scoped_to_reviewed_labels() -> None:
    records = [
        {
            "case_id": "reviewed-ranking",
            "task": "ranking_event",
            "review_status": "reviewed",
            "score": 90,
            "relevant": True,
            "first_party": True,
        },
        {
            "case_id": "seed-ranking",
            "task": "ranking_event",
            "review_status": "seed_needs_review",
            "score": 100,
            "relevant": False,
            "first_party": False,
        },
    ]

    result = evaluate_records(records, top_n=1, review_status="reviewed")

    assert result["dataset_cases_total"] == 2
    assert result["dataset_cases"] == 1
    assert result["metrics_scope"] == "reviewed"
    assert result["labels_reviewed_only"] is True
    assert result["top_n_relevance"] == 1.0
