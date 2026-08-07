"""Unit tests for the Hacker News API connector + parser."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ai_security_hot.connectors.base import Checkpoint, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem
from ai_security_hot.parsers.hackernews import HackerNewsParser, clean_hackernews_html


def _raw(native_id: str, item: dict) -> RawItem:
    published = (
        datetime.fromtimestamp(int(item["time"]), tz=UTC)
        if isinstance(item.get("time"), (int, float))
        else None
    )
    return RawItem(
        endpoint_id="hackernews-api",
        source_id="hackernews",
        native_id=native_id,
        request_url=f"https://hacker-news.firebaseio.com/v0/item/{native_id}.json",
        final_url=f"https://hacker-news.firebaseio.com/v0/item/{native_id}.json",
        http_status=200,
        published_at=published,
        fetched_at=datetime(2026, 8, 7, 6, 0, tzinfo=UTC),
        language="en",
        content_hash="x" * 64,
        connector_kind=ConnectorKind.HACKERNEWS,
        connector_version="hackernews-v1",
        raw_text=json.dumps(item, ensure_ascii=False),
        canonical_url=str(item.get("url") or ""),
    )


def test_clean_hackernews_html_decodes_entities_and_strips_tags() -> None:
    html = (
        '<a href="https://&#x2F;&#x2F;example.com&#x2F;x" rel="nofollow">'
        "https://example.com/x</a> &amp; more<br><p>line two</p>"
    )
    cleaned = clean_hackernews_html(html)
    assert "&#x2F;" not in cleaned
    assert "&amp;" not in cleaned
    assert "<a" not in cleaned and "<p>" not in cleaned
    assert "https://example.com/x & more" in cleaned
    assert "\n" in cleaned  # <br> becomes a newline
    assert cleaned == clean_hackernews_html(cleaned)  # idempotent


def test_parse_link_story_uses_structured_fields() -> None:
    item = {
        "id": 49201970,
        "type": "story",
        "by": "itvision",
        "time": 1786047791,
        "title": "AMD acquires Taalas to boost inference performance",
        "url": "https://www.theregister.com/amd-taalas",
        "score": 603,
        "descendants": 447,
    }
    doc = HackerNewsParser().parse(_raw("49201970", item))
    assert doc.title_original == "AMD acquires Taalas to boost inference performance"
    assert doc.canonical_url == "https://www.theregister.com/amd-taalas"
    assert doc.author == "itvision"
    assert doc.org == "Hacker News"
    assert doc.published_at is not None
    assert doc.body_text is None  # link post without submitter text → no fake summary


def test_parse_self_story_extracts_submitter_text() -> None:
    item = {
        "id": 49000001,
        "type": "story",
        "by": "pg",
        "time": 1786000000,
        "title": "Ask HN: Best approach for LLM guardrails?",
        "text": "<p>We are seeing <b>prompt injection</b> on user input.&nbsp; "
        "Any advice?</p><br><a href=\"https://example.com\">more</a>",
    }
    doc = HackerNewsParser().parse(_raw("49000001", item))
    body = doc.body_text
    assert body is not None
    assert "prompt injection" in body
    assert "<b>" not in body
    assert "&nbsp;" not in body
    assert doc.canonical_url.startswith("https://news.ycombinator.com/item?id=")


class _FakeCtx:
    """Stub FetchContext for connector tests — returns canned responses."""

    def __init__(self, responses: dict[str, str]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get(self, url: str, policy, **kwargs):
        self.calls.append(url)
        body = self._responses.get(url, "[]").encode()
        return type("R", (), {"body": body, "fetched_at": datetime(2026, 8, 7, 6, 0, tzinfo=UTC)})()


def test_connector_skips_known_items_and_limits_new_fetches() -> None:
    from ai_security_hot.config.sources import EndpointPolicy
    from ai_security_hot.connectors.hackernews import HackerNewsConnector

    base = "https://hacker-news.firebaseio.com/v0/"
    responses = {
        base + "topstories.json": json.dumps([1, 2, 3, 4]),
        base + "item/2.json": json.dumps(
            {"id": 2, "title": "New", "url": "https://b.example", "by": "u"}
        ),
        base + "item/3.json": json.dumps(
            {"id": 3, "title": "New3", "url": "https://c.example", "by": "v"}
        ),
        base + "item/4.json": json.dumps(
            {"id": 4, "title": "New4", "url": "https://d.example", "by": "w"}
        ),
    }
    ctx = _FakeCtx(responses)
    policy = EndpointPolicy(
        id="hackernews-api",
        source_id="hackernews",
        connector=ConnectorKind.HACKERNEWS,
        url=base,
    )
    connector = HackerNewsConnector(ctx)  # type: ignore[arg-type]
    # item 1 already known → skipped without fetching
    checkpoint = Checkpoint(known_content_hashes={"1": "known-hash"})
    result = connector.poll(policy, checkpoint)
    assert isinstance(result, PollResult)
    assert [r.native_id for r in result.items] == ["2", "3", "4"]
    assert not any(u.endswith("item/1.json") for u in ctx.calls)
