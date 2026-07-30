"""arXiv connector — official arXiv API (https://export.arxiv.org/api/query).

The API returns Atom XML; feedparser reads it. Unlike the generic RSS
connector (which keeps only title+summary), this preserves the full
structured entry (authors, categories, pdf link, arxiv id) as JSON so the
arxiv-v1 parser can extract rich metadata. Fetch still goes through
FetchContext — proxy/egress/SSRF/rate-limit all apply (API-tier, not a
third-party client that bypasses our egress).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from time import mktime

import feedparser

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256


def _published(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        val = entry.get(key)
        if val:
            return datetime.fromtimestamp(mktime(val), tz=UTC)
    return None


def _abs_url(entry) -> str:
    # prefer the canonical abstract page link
    for link in entry.get("links", []):
        if link.get("rel") == "alternate":
            return link.get("href", "")
    return entry.get("link", "")


def _pdf_url(entry) -> str | None:
    for link in entry.get("links", []):
        if link.get("type") == "application/pdf":
            return link.get("href")
    return None


class ArxivConnector(Connector):
    version = "arxiv-2"

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
            native_id = entry.get("id", "")  # arXiv abs id, e.g. http://arxiv.org/abs/2607.25995v1
            if not native_id:
                continue
            summary = entry.get("summary", "")
            record = {
                "arxiv_id": native_id,
                "title": entry.get("title", "").replace("\n", " ").strip(),
                "summary": summary.strip(),
                "authors": [a.get("name", "") for a in entry.get("authors", [])],
                "categories": [t.get("term", "") for t in entry.get("tags", [])],
                "abs_url": _abs_url(entry),
                "pdf_url": _pdf_url(entry),
            }
            item_hash = content_sha256(native_id, record["title"], summary)
            if checkpoint.known_content_hashes.get(native_id) == item_hash:
                continue
            items.append(
                RawItem(
                    endpoint_id=policy.id,
                    source_id=policy.source_id,
                    native_id=native_id,
                    request_url=policy.url,
                    final_url=res.final_url,
                    http_status=res.status_code,
                    published_at=_published(entry),
                    fetched_at=res.fetched_at,
                    language=policy.language,
                    content_hash=item_hash,
                    raw_text=json.dumps(record, ensure_ascii=False),
                    canonical_url=record["abs_url"] or native_id,
                    connector_kind=ConnectorKind.ARXIV,
                    connector_version=self.version,
                )
            )

        new_ck = Checkpoint(
            etag=res.etag or checkpoint.etag,
            last_modified=res.last_modified or checkpoint.last_modified,
            cursor=checkpoint.cursor,
            last_published_at=max(
                [it.published_at for it in items if it.published_at]
                + (
                    [checkpoint.last_published_at]
                    if checkpoint.last_published_at
                    else []
                ),
                default=None,
            ),
        )
        return PollResult(items, new_ck)
