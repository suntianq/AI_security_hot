"""Hacker News official API connector (Firebase backend).

Polls the item-id list (``topstories.json``), then fetches each new item's
detail payload from ``item/{id}.json``. Incremental via the checkpoint's
known content hashes (skips stable items without re-fetching them). The HN
API gives structured metadata (title/url/score/descendants/time/author) plus
the story's own ``text`` when the submitter wrote one — the raw RSS summary
metadata is never stored as a body.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256

HN_ITEM_URL = "https://news.ycombinator.com/item?id="


class HackerNewsConnector(Connector):
    version = "hackernews-v1"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("hackernews", {})
        pool_size = int(opts.get("pool_size", 300))
        fetch_limit = int(opts.get("fetch_limit", 100))
        list_path = str(opts.get("list_path", "topstories.json"))
        base = policy.url.rstrip("/")

        res = self.ctx.get(f"{base}/{list_path}", policy)
        ids = json.loads(res.body)
        if not isinstance(ids, list):
            raise ValueError("HN story-id list is not a JSON array")

        items: list[RawItem] = []
        new_ids: list[str] = [str(i) for i in ids[:pool_size]]
        for native_id in new_ids:
            if native_id in checkpoint.known_content_hashes:
                continue  # stable item already persisted — skip without fetching
            if len(items) >= fetch_limit:
                break
            fetched = self._fetch_item(policy, base, native_id)
            if fetched is None:
                continue
            item, fetched_at = fetched
            raw = self._to_raw(policy, item, fetched_at, f"{base}/{list_path}")
            if checkpoint.known_content_hashes.get(native_id) != raw.content_hash:
                items.append(raw)

        # known_content_hashes is re-derived from source_records next poll;
        # persist_raw_items updates it for every emitted item.
        return PollResult(items, Checkpoint())

    def _fetch_item(
        self, policy: EndpointPolicy, base: str, native_id: str
    ) -> tuple[dict[str, Any], datetime] | None:
        url = f"{base}/item/{native_id}.json"
        try:
            item_res = self.ctx.get(url, policy)
        except Exception:
            return None
        try:
            payload = json.loads(item_res.body)
        except ValueError:
            return None
        if not isinstance(payload, dict) or not payload.get("id"):
            return None
        return payload, item_res.fetched_at

    def _to_raw(
        self,
        policy: EndpointPolicy,
        item: dict[str, Any],
        fetched_at: datetime,
        request_url: str,
    ) -> RawItem:
        native_id = str(item.get("id") or "")
        title = str(item.get("title") or "")
        url = item.get("url")
        text = item.get("text")
        author = item.get("by")
        epoch = item.get("time")
        raw_text = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        canonical = str(url) if url else f"{HN_ITEM_URL}{native_id}"
        published = (
            datetime.fromtimestamp(int(epoch), tz=UTC) if isinstance(epoch, (int, float)) else None
        )
        return RawItem(
            endpoint_id=policy.id,
            source_id=policy.source_id,
            native_id=native_id,
            request_url=request_url,
            final_url=request_url,
            http_status=200,
            published_at=published,
            fetched_at=fetched_at,
            language=policy.language,
            content_hash=content_sha256(
                native_id, title, str(url), str(text), str(author), str(epoch)
            ),
            raw_text=raw_text,
            canonical_url=canonical,
            connector_kind=ConnectorKind.HACKERNEWS,
            connector_version=self.version,
        )
