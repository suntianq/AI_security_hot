"""Sitemap connector — reads sitemap.xml, filters URLs by pattern, fetches each
article page concurrently and extracts full text via trafilatura.

This is a generic connector for SPA sites that have a sitemap but no static
article body on the listing page (e.g. Anthropic Newsroom / Research).  The
sitemap is the reliable discovery layer; trafilatura handles static article
pages.  Any site with a sitemap can reuse this without code changes.

**Incremental mode**: if the checkpoint carries ``last_success_at`` (set on
the second and subsequent polls), only URLs whose ``<lastmod>`` is newer than
that timestamp are fetched.  On the very first poll (no ``last_success_at``),
all matching URLs are fetched (capped by ``max_urls``).

**Concurrency**: article pages are fetched concurrently via ``asyncio.gather``
with a semaphore to respect the per-endpoint ``requests_per_minute`` limit.

Configuration via ``options.sitemap`` in ``sources.yaml``::

    options:
      sitemap:
        url_patterns:          # only keep URLs matching any of these
          - "/news/"
          - "/research/"
        strip_query: true      # remove query strings from URLs before dedup
        max_urls: 50           # cap on URLs to fetch per poll (newest first)
        concurrency: 5         # max concurrent article fetches
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from xml.etree import ElementTree

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256
from ai_security_hot.parsers.article import extract_article
from ai_security_hot.storage.blob import get_blob_store

log = logging.getLogger("intel.connector.sitemap")

_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def _to_utc(dt: datetime) -> datetime:
    """Normalize a datetime to offset-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


@dataclass
class _SitemapEntry:
    loc: str
    lastmod: datetime | None = None


def _parse_sitemap(xml_bytes: bytes) -> list[_SitemapEntry]:
    """Parse a sitemap XML (regular or sitemap-index is not followed in M0)."""
    # S314: defusedxml is not a dependency; sitemap XML comes from a trusted
    # endpoint (configured by the operator in sources.yaml), not arbitrary user
    # input.  The SSRF guard already limits which hosts we fetch from.
    root = ElementTree.fromstring(xml_bytes)  # noqa: S314
    entries: list[_SitemapEntry] = []
    for url_el in root.findall("sm:url", _NS):
        loc_el = url_el.find("sm:loc", _NS)
        if loc_el is None or not loc_el.text:
            continue
        lastmod_el = url_el.find("sm:lastmod", _NS)
        lastmod = None
        if lastmod_el is not None and lastmod_el.text:
            try:
                lastmod = datetime.fromisoformat(lastmod_el.text.rstrip("Z"))
            except (ValueError, OverflowError):
                lastmod = None
        entries.append(_SitemapEntry(loc=loc_el.text.strip(), lastmod=lastmod))
    return entries


def _filter_urls(
    entries: list[_SitemapEntry],
    patterns: list[str] | None,
    strip_query: bool,
    max_urls: int,
    since: datetime | None = None,
) -> list[_SitemapEntry]:
    """Keep only URLs matching any pattern, optionally newer than *since*,
    strip query, cap count."""
    if patterns:
        compiled = [re.compile(p) for p in patterns]
        entries = [e for e in entries if any(r.search(e.loc) for r in compiled)]
    if since:
        since_utc = since if since.tzinfo else since.replace(tzinfo=UTC)
        entries = [
            e for e in entries
            if e.lastmod is None
            or _to_utc(e.lastmod) > since_utc
        ]
    if strip_query:
        for e in entries:
            e.loc = e.loc.split("?", 1)[0]
    entries.sort(key=lambda e: e.lastmod or datetime.min.replace(tzinfo=UTC), reverse=True)
    return entries[:max_urls]


class SitemapConnector(Connector):
    version = "sitemap-1"

    async def apoll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("sitemap", {})
        url_patterns = opts.get("url_patterns")
        strip_query = opts.get("strip_query", True)
        max_urls = opts.get("max_urls", 50)
        concurrency = opts.get("concurrency", 5)

        # 1. Fetch the sitemap (single request, sync is fine)
        res = self.ctx.get(policy.url, policy)
        if res.status_code != 200:
            return PollResult([], checkpoint)

        # 2. Parse sitemap entries and filter — incremental: skip already-seen
        entries = _parse_sitemap(res.body)
        entries = _filter_urls(
            entries, url_patterns, strip_query, max_urls,
            since=checkpoint.last_success_at,
        )

        if not entries:
            return PollResult([], checkpoint)

        # 3. Deduplicate URLs
        seen: set[str] = set()
        unique: list[_SitemapEntry] = []
        for e in entries:
            if e.loc not in seen:
                seen.add(e.loc)
                unique.append(e)

        # 4. Fetch article pages concurrently
        sem = asyncio.Semaphore(concurrency)

        async def _fetch_one(entry: _SitemapEntry) -> RawItem | None:
            url = entry.loc
            async with sem:
                try:
                    art_res = await self.ctx.aget(url, policy)
                except Exception as e:
                    log.warning("sitemap article fetch failed for %s: %s", url, e)
                    return None
            if art_res.status_code != 200:
                return None

            html = art_res.body.decode("utf-8", errors="replace")
            art = extract_article(html)

            blob_ref = get_blob_store().put(art_res.body)

            raw_text = json.dumps(
                {
                    "url": url,
                    "title": art.title or "",
                    "body": art.body or "",
                    "published": art.published.isoformat() if art.published else None,
                    "lastmod": entry.lastmod.isoformat() if entry.lastmod else None,
                },
                ensure_ascii=False,
            )
            content_hash = content_sha256(url, art.body or "")

            return RawItem(
                endpoint_id=policy.id,
                source_id=policy.source_id,
                native_id=url,
                request_url=url,
                final_url=art_res.final_url,
                http_status=art_res.status_code,
                published_at=entry.lastmod,
                fetched_at=art_res.fetched_at,
                language=policy.language,
                content_hash=content_hash,
                blob_ref=blob_ref,
                raw_text=raw_text,
                canonical_url=url,
                connector_kind=ConnectorKind.SITEMAP,
                connector_version=self.version,
            )

        results = await asyncio.gather(*[_fetch_one(e) for e in unique])
        items: list[RawItem] = [r for r in results if r is not None]

        new_ck = Checkpoint(cursor=str(len(items)))
        return PollResult(items, new_ck)

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        """Synchronous fallback — runs the async apoll via asyncio.run."""
        return asyncio.run(self.apoll(policy, checkpoint))
