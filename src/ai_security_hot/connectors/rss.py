"""RSS/Atom connector — real fetch via feedparser (MVP 5.2)."""

from __future__ import annotations

from datetime import UTC, datetime
from time import mktime

import feedparser

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256


def _entry_published(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        val = entry.get(key)
        if val:
            return datetime.fromtimestamp(mktime(val), tz=UTC)
    return None


class RSSConnector(Connector):
    version = "rss-1"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        res = self.ctx.get(
            policy.url,
            policy,
            etag=checkpoint.etag,
            last_modified=checkpoint.last_modified,
        )
        if res.from_cache:
            return PollResult([], checkpoint, not_modified=True)

        feed = feedparser.parse(res.body)
        items: list[RawItem] = []
        for entry in feed.entries:
            native_id = entry.get("id") or entry.get("link") or ""
            if not native_id:
                continue
            link = entry.get("link", policy.url)
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            raw_text = f"{title}\n\n{summary}"
            items.append(
                RawItem(
                    endpoint_id=policy.id,
                    source_id=policy.source_id,
                    native_id=native_id,
                    request_url=policy.url,
                    final_url=res.final_url,
                    http_status=res.status_code,
                    published_at=_entry_published(entry),
                    fetched_at=res.fetched_at,
                    language=policy.language,
                    content_hash=content_sha256(native_id, title, summary),
                    raw_text=raw_text,
                    canonical_url=link,
                    connector_kind=ConnectorKind.RSS,
                    connector_version=self.version,
                )
            )

        new_ck = Checkpoint(
            etag=res.etag or checkpoint.etag,
            last_modified=res.last_modified or checkpoint.last_modified,
            cursor=checkpoint.cursor,
        )
        return PollResult(items, new_ck)
