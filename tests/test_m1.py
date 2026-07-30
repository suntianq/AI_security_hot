"""M1 protocol and hybrid-classification contract tests (offline)."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import unquote

import httpx
import pytest
import respx

from ai_security_hot.classify.llm import HybridClassifier
from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.aihot import AIHotConnector
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.connectors.fetch import FetchContext, _is_retryable
from ai_security_hot.domain.models import NormalizedDocument
from ai_security_hot.llm.provider import ModelResponse
from ai_security_hot.parsers.aihot import AIHotParser


def _aihot_policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-aihot",
            "source_id": "aihot",
            "connector": "aihot",
            "parser": "aihot-v1",
            "url": "https://example.com/api/v1/selected/snapshot",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "aihot": {
                    "fields": "default",
                    "snapshot_limit": 1,
                    "changes_limit": 100,
                    "changes_url": "https://example.com/api/v1/selected/changes",
                }
            },
        }
    )


def _nvd_policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-nvd-window",
            "source_id": "nvd",
            "connector": "nvd",
            "parser": "nvd-v1",
            "url": "https://example.com/cves?resultsPerPage=2000",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "nvd": {
                    "bootstrap_days": 14,
                    "segment_days": 7,
                    "overlap_minutes": 15,
                    "target_results": 20000,
                    "minimum_window_minutes": 60,
                    "catchup_interval_minutes": 1,
                },
                "rest": {
                    "list_key": "vulnerabilities",
                    "nested_key": "cve",
                    "id_field": "id",
                    "pagination": {
                        "start_param": "startIndex",
                        "start_key": "startIndex",
                        "page_size_key": "resultsPerPage",
                        "total_key": "totalResults",
                        "max_pages": 50,
                    },
                },
            },
        }
    )


def _item(native_id: str, title: str) -> dict:
    return {
        "id": native_id,
        "title": f"中文 {title}",
        "originalTitle": title,
        "summary": "An AI security summary.",
        "source": {"name": "Example"},
        "links": {
            "aihot": f"https://example.com/item/{native_id}",
            "original": f"https://source.example/{native_id}",
        },
        "publishedAt": "2026-07-30T00:00:00Z",
        "discoveredAt": "2026-07-30T01:00:00Z",
        "category": "industry",
        "score": 80,
        "selected": True,
    }


@respx.mock
def test_nvd_bootstrap_shrinks_dense_window_and_persists_cursor(monkeypatch) -> None:
    from ai_security_hot.connectors.nvd import NvdConnector

    fixed_now = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(NvdConnector, "_now", staticmethod(lambda: fixed_now))
    calls: list[str] = []
    preflight_totals = iter([30000, 10000])

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(unquote(str(request.url)))
        if request.url.params.get("resultsPerPage") == "1":
            return httpx.Response(200, json={"totalResults": next(preflight_totals)})
        return httpx.Response(
            200,
            json={
                "startIndex": 0,
                "resultsPerPage": 2000,
                "totalResults": 1,
                "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
            },
        )

    respx.get(url__startswith="https://example.com/cves").mock(side_effect=handler)
    ctx = FetchContext()
    try:
        result = NvdConnector(ctx).poll(_nvd_policy(), Checkpoint())
    finally:
        ctx.close()

    # 14-day bootstrap starts July 16. Dense 7-day candidate is bisected
    # to 3.5 days, and that exact boundary becomes the durable next cursor.
    assert len(calls) == 3
    assert "lastModStartDate=2026-07-16T12:00:00.000Z" in calls[0]
    assert "lastModEndDate=2026-07-23T12:00:00.000Z" in calls[0]
    assert "lastModEndDate=2026-07-20T00:00:00.000Z" in calls[1]
    assert result.checkpoint.cursor == "nvd-window-v1:2026-07-20T00:00:00+00:00"
    assert result.next_poll_minutes == 1
    assert result.items[0].native_id == "CVE-2026-0001"
    assert result.items[0].connector_kind.value == "nvd"


@respx.mock
def test_nvd_steady_window_uses_overlap_and_normal_schedule(monkeypatch) -> None:
    from ai_security_hot.connectors.nvd import NvdConnector

    fixed_now = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(NvdConnector, "_now", staticmethod(lambda: fixed_now))
    route = respx.get(url__startswith="https://example.com/cves").mock(
        return_value=httpx.Response(200, json={"totalResults": 0})
    )
    ctx = FetchContext()
    try:
        result = NvdConnector(ctx).poll(
            _nvd_policy(),
            Checkpoint(
                cursor="nvd-steady-v1",
                last_success_at=fixed_now - timedelta(hours=1),
            ),
        )
    finally:
        ctx.close()

    url = unquote(str(route.calls[0].request.url))
    assert "lastModStartDate=2026-07-30T10:45:00.000Z" in url
    assert "lastModEndDate=2026-07-30T12:00:00.000Z" in url
    assert result.items == []
    assert result.checkpoint.cursor == "nvd-steady-v1"
    assert result.next_poll_minutes is None


@respx.mock
def test_aihot_snapshot_paginates_and_detects_missing_membership() -> None:
    route = respx.get(url__startswith="https://example.com/api/v1/selected/snapshot").mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "cursor": "watermark-1",
                    "items": [_item("one", "One")],
                    "hasMore": True,
                    "nextPage": "page-2",
                },
            ),
            httpx.Response(
                200,
                json={
                    "cursor": "watermark-1",
                    "items": [_item("two", "Two")],
                    "hasMore": False,
                    "nextPage": None,
                },
            ),
        ]
    )
    result = AIHotConnector(FetchContext()).poll(
        _aihot_policy(),
        Checkpoint(active_native_ids={"gone"}),
    )

    assert route.call_count == 2
    assert result.checkpoint.cursor == "watermark-1"
    assert [(item.native_id, item.operation) for item in result.items] == [
        ("one", "upsert"),
        ("two", "upsert"),
        ("gone", "withdraw"),
    ]
    document = AIHotParser().parse(result.items[0])
    assert document.title_original == "One"
    assert document.title_zh == "中文 One"
    assert document.canonical_url == "https://source.example/one"


@respx.mock
def test_aihot_changes_apply_upsert_and_remove() -> None:
    respx.get(url__startswith="https://example.com/api/v1/selected/changes").mock(
        return_value=httpx.Response(
            200,
            json={
                "cursor": "cursor-2",
                "changes": [
                    {
                        "op": "upsert",
                        "changedAt": "2026-07-30T02:00:00Z",
                        "item": _item("new", "New"),
                    },
                    {"op": "remove", "changedAt": "2026-07-30T02:01:00Z", "id": "old"},
                ],
                "hasMore": False,
            },
        )
    )
    result = AIHotConnector(FetchContext()).poll(
        _aihot_policy(),
        Checkpoint(cursor="cursor-1", active_native_ids={"old"}),
    )
    assert result.checkpoint.cursor == "cursor-2"
    assert [(item.native_id, item.operation) for item in result.items] == [
        ("new", "upsert"),
        ("old", "withdraw"),
    ]


@respx.mock
def test_aihot_409_rebuilds_snapshot_without_retrying_409() -> None:
    changes = respx.get(url__startswith="https://example.com/api/v1/selected/changes").mock(
        return_value=httpx.Response(409, json={"type": "snapshot_required"})
    )
    snapshot = respx.get(url__startswith="https://example.com/api/v1/selected/snapshot").mock(
        return_value=httpx.Response(
            200,
            json={
                "cursor": "rebuilt",
                "items": [_item("one", "One")],
                "hasMore": False,
                "nextPage": None,
            },
        )
    )
    result = AIHotConnector(FetchContext()).poll(_aihot_policy(), Checkpoint(cursor="stale"))
    assert changes.call_count == 1
    assert snapshot.call_count == 1
    assert result.checkpoint.cursor == "rebuilt"


def test_http_retry_policy_rejects_409_and_accepts_503() -> None:
    request = httpx.Request("GET", "https://example.com")
    conflict = httpx.HTTPStatusError(
        "conflict", request=request, response=httpx.Response(409, request=request)
    )
    unavailable = httpx.HTTPStatusError(
        "unavailable", request=request, response=httpx.Response(503, request=request)
    )
    assert _is_retryable(conflict) is False
    assert _is_retryable(unavailable) is True


class _FakeProvider:
    name = "fake"
    model = "fake-v1"

    def __init__(self, output: dict) -> None:
        self.output = output
        self.calls = 0

    def complete(self, **_kwargs) -> ModelResponse:
        self.calls += 1
        return ModelResponse(json.dumps(self.output), {"total_tokens": 42})


def _news_doc() -> NormalizedDocument:
    return NormalizedDocument(
        raw_item_native_id="1",
        endpoint_id="news",
        title_original="Agent security evaluation",
        body_text="A study of prompt injection in an LLM agent.",
        canonical_url="https://example.com/news",
    )


def test_hybrid_classifier_validates_and_merges_rules() -> None:
    provider = _FakeProvider(
        {
            "tech_directions": ["security_for_ai"],
            "company_models": ["anthropic"],
            "event_type": "research",
            "confidence": 0.91,
        }
    )
    classifier = HybridClassifier(provider)
    outcome = classifier.classify_with_metadata(_news_doc(), source_id="arxiv", connector="arxiv")
    assert provider.calls == 1
    assert "agent" in outcome.classification.tech_directions
    assert "security_for_ai" in outcome.classification.tech_directions
    assert outcome.classification.company_models == ["anthropic"]
    assert outcome.classification.method == "hybrid"
    assert outcome.usage == {"total_tokens": 42}


def test_hybrid_classifier_rejects_unknown_labels() -> None:
    provider = _FakeProvider(
        {
            "tech_directions": ["invented_label"],
            "company_models": [],
            "event_type": "research",
            "confidence": 0.5,
        }
    )
    with pytest.raises(ValueError, match="unknown tech_directions"):
        HybridClassifier(provider).classify_with_metadata(_news_doc())


def test_hybrid_classifier_never_calls_model_for_structured_cve() -> None:
    provider = _FakeProvider({})
    doc = NormalizedDocument(
        raw_item_native_id="CVE-2026-1",
        endpoint_id="nvd-recent",
        title_original="CVE-2026-1",
        canonical_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1",
        cve_ids=["CVE-2026-1"],
    )
    outcome = HybridClassifier(provider).classify_with_metadata(
        doc, source_id="nvd", connector="rest"
    )
    assert provider.calls == 0
    assert outcome.classification.tech_directions == ["cve"]
    assert outcome.classification.method == "rule"


@respx.mock
def test_authoritative_rest_snapshot_emits_withdrawal() -> None:
    from ai_security_hot.connectors.rest import RestApiConnector

    policy = EndpointPolicy.model_validate(
        {
            "id": "test-cisa",
            "source_id": "cisa",
            "connector": "rest",
            "parser": "cisa-kev-v1",
            "url": "https://example.com/cisa.json",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "rest": {
                    "list_key": "vulnerabilities",
                    "id_field": "cveID",
                    "authoritative_snapshot": True,
                }
            },
        }
    )
    respx.get("https://example.com/cisa.json").mock(
        return_value=httpx.Response(
            200,
            json={"vulnerabilities": [{"cveID": "CVE-2026-0001", "vendorProject": "X"}]},
        )
    )
    result = RestApiConnector(FetchContext()).poll(
        policy,
        Checkpoint(active_native_ids={"CVE-2025-9999"}),
    )
    assert [(item.native_id, item.operation) for item in result.items] == [
        ("CVE-2026-0001", "upsert"),
        ("CVE-2025-9999", "withdraw"),
    ]


@respx.mock
def test_rest_pagination_limit_never_checkpoints_partial_data() -> None:
    from ai_security_hot.connectors.rest import RestApiConnector

    policy = EndpointPolicy.model_validate(
        {
            "id": "test-nvd",
            "source_id": "nvd",
            "connector": "rest",
            "parser": "nvd-v1",
            "url": "https://example.com/cves?resultsPerPage=1",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "rest": {
                    "list_key": "vulnerabilities",
                    "nested_key": "cve",
                    "id_field": "id",
                    "pagination": {"max_pages": 1},
                }
            },
        }
    )
    route = respx.get("https://example.com/cves?resultsPerPage=1").mock(
        return_value=httpx.Response(
            200,
            json={
                "startIndex": 0,
                "resultsPerPage": 1,
                "totalResults": 2,
                "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
            },
        )
    )
    with pytest.raises(RuntimeError, match="pagination incomplete"):
        RestApiConnector(FetchContext()).poll(policy, Checkpoint(cursor="unchanged"))
    assert route.call_count == 1


def test_source_registry_rejects_duplicate_endpoint_ids() -> None:
    from pydantic import ValidationError

    from ai_security_hot.config.sources import SourceRegistry

    payload = {
        "sources": [{"id": "s", "name": "S"}],
        "endpoints": [
            {"id": "same", "source_id": "s", "connector": "rss", "url": "https://example.com/1"},
            {"id": "same", "source_id": "s", "connector": "rss", "url": "https://example.com/2"},
        ],
    }
    with pytest.raises(ValidationError, match="duplicate endpoint ids"):
        SourceRegistry.model_validate(payload)


def test_source_registry_validates_endpoint_replacement_contract() -> None:
    from pydantic import ValidationError

    from ai_security_hot.config.sources import SourceRegistry

    base = {
        "sources": [{"id": "s", "name": "S"}],
        "endpoints": [
            {
                "id": "old",
                "source_id": "s",
                "connector": "rss",
                "url": "https://example.com/old",
                "enabled": False,
                "replaced_by": "new",
            },
            {
                "id": "new",
                "source_id": "s",
                "connector": "rss",
                "url": "https://example.com/new",
            },
        ],
    }
    registry = SourceRegistry.model_validate(base)
    assert registry.endpoint("old").replaced_by == "new"

    base["endpoints"][0]["enabled"] = True
    with pytest.raises(ValidationError, match="must be disabled"):
        SourceRegistry.model_validate(base)


@pytest.mark.parametrize(
    ("backlog", "expected_calls"),
    [(1001, []), (1000, ["dedupe", "cluster"])],
)
def test_scheduled_event_rebuild_waits_for_large_m1_backlog(
    monkeypatch, backlog: int, expected_calls: list[str]
) -> None:
    from ai_security_hot.jobs import scheduler

    calls: list[str] = []

    @contextmanager
    def fake_session_scope():
        yield object()

    monkeypatch.setattr(
        scheduler, "get_settings", lambda: SimpleNamespace(event_backlog_threshold=1000)
    )
    monkeypatch.setattr(scheduler, "session_scope", fake_session_scope)
    monkeypatch.setattr(scheduler.repo, "count_event_pipeline_backlog", lambda _session: backlog)
    monkeypatch.setattr(
        scheduler,
        "run_dedupe_stage",
        lambda: calls.append("dedupe") or {"status": "ok"},
    )
    monkeypatch.setattr(
        scheduler,
        "run_cluster_stage",
        lambda: calls.append("cluster") or {"status": "ok"},
    )

    scheduler.event_tick()

    assert calls == expected_calls
