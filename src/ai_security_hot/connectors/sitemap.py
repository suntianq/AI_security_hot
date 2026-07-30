"""Hybrid listing + sitemap connector for article sites.

The fast path reads a server-rendered listing page and fetches only unknown
article URLs.  A slower sitemap reconciliation runs periodically with an
overlap window, catching listing omissions and revisions without comparing a
coarse ``lastmod`` directly to the precise fetch-completion timestamp.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

from lxml import html as lxml_html

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256
from ai_security_hot.parsers.article import extract_article
from ai_security_hot.storage.blob import get_blob_store

log = logging.getLogger("intel.connector.sitemap")

_NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


@dataclass
class _SitemapEntry:
    loc: str
    lastmod: datetime | None = None


def _parse_sitemap(xml_bytes: bytes) -> list[_SitemapEntry]:
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
    if patterns:
        compiled = [re.compile(pattern) for pattern in patterns]
        entries = [entry for entry in entries if any(p.search(entry.loc) for p in compiled)]
    if since:
        since_utc = _to_utc(since)
        entries = [
            entry
            for entry in entries
            if entry.lastmod is None or _to_utc(entry.lastmod) >= since_utc
        ]
    if strip_query:
        entries = [
            _SitemapEntry(loc=entry.loc.split("?", 1)[0], lastmod=entry.lastmod)
            for entry in entries
        ]
    entries.sort(
        key=lambda entry: _to_utc(entry.lastmod)
        if entry.lastmod
        else datetime.min.replace(tzinfo=UTC),
        reverse=True,
    )
    return entries[:max_urls]


def _parse_listing_links(
    html_text: str,
    listing_url: str,
    patterns: list[str] | None,
    max_urls: int,
) -> list[str]:
    if not html_text:
        return []
    doc = lxml_html.fromstring(html_text)
    base_host = urlparse(listing_url).hostname
    compiled = [re.compile(pattern) for pattern in patterns or []]
    links: list[str] = []
    seen: set[str] = set()
    for href in doc.xpath("//a[@href]/@href"):
        absolute = urljoin(listing_url, str(href)).split("?", 1)[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or parsed.hostname != base_host:
            continue
        if compiled and not any(pattern.search(parsed.path) for pattern in compiled):
            continue
        if absolute not in seen:
            seen.add(absolute)
            links.append(absolute)
        if len(links) >= max_urls:
            break
    return links


def _reconciled_at(cursor: str | None) -> datetime | None:
    if not cursor:
        return None
    try:
        value = json.loads(cursor).get("sitemap_reconciled_at")
        return datetime.fromisoformat(value) if value else None
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _checkpoint_cursor(reconciled_at: datetime | None) -> str | None:
    if reconciled_at is None:
        return None
    return json.dumps({"sitemap_reconciled_at": _to_utc(reconciled_at).isoformat()})


class SitemapConnector(Connector):
    version = "sitemap-2"

    async def apoll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("sitemap", {})
        patterns = opts.get("url_patterns")
        strip_query = opts.get("strip_query", True)
        max_urls = int(opts.get("max_urls", 50))
        concurrency = int(opts.get("concurrency", 5))
        listing_url = opts.get("listing_url")
        listing_max_urls = int(opts.get("listing_max_urls", 20))
        reconcile_hours = int(opts.get("reconcile_interval_hours", 0))
        overlap_hours = int(opts.get("overlap_hours", 48))

        now = datetime.now(UTC)
        candidates: dict[str, _SitemapEntry] = {}
        listing_failed = False

        # Fast path: one listing request, then only previously unseen URLs.
        if listing_url:
            try:
                listing_res = await self.ctx.aget(listing_url, policy)
                listing_html = listing_res.body.decode("utf-8", errors="replace")
                for url in _parse_listing_links(
                    listing_html, listing_url, patterns, listing_max_urls
                ):
                    if url not in checkpoint.known_native_ids:
                        candidates[url] = _SitemapEntry(loc=url)
            except Exception as exc:
                listing_failed = True
                log.warning("listing fetch failed for %s: %s", policy.id, exc)

        last_reconciled = _reconciled_at(checkpoint.cursor)
        reconcile_due = (
            not listing_url
            or listing_failed
            or last_reconciled is None
            or now - _to_utc(last_reconciled) >= timedelta(hours=reconcile_hours)
        )
        watermark = checkpoint.last_published_at
        reconciled = last_reconciled

        # Slow path: periodic overlapping sitemap reconciliation.
        if reconcile_due:
            bootstrapping_existing = watermark is None and bool(checkpoint.known_native_ids)
            sitemap_res = await self.ctx.aget(policy.url, policy)
            sitemap_entries = _parse_sitemap(sitemap_res.body)
            matching_entries = _filter_urls(
                sitemap_entries,
                patterns,
                strip_query,
                max_urls,
                since=(
                    _to_utc(watermark) - timedelta(hours=overlap_hours)
                    if watermark
                    else None
                ),
            )
            compiled = [re.compile(pattern) for pattern in patterns or []]
            dated = [
                entry.lastmod
                for entry in sitemap_entries
                if entry.lastmod
                and (not compiled or any(pattern.search(entry.loc) for pattern in compiled))
            ]
            if dated:
                newest = max(_to_utc(value) for value in dated)
                watermark = max(_to_utc(watermark), newest) if watermark else newest

            for entry in matching_entries:
                if bootstrapping_existing and entry.loc in checkpoint.known_native_ids:
                    continue
                current = candidates.get(entry.loc)
                if current is None or current.lastmod is None:
                    candidates[entry.loc] = entry
            reconciled = now

        entries = list(candidates.values())[:max_urls]
        if not entries:
            return PollResult(
                [],
                Checkpoint(
                    etag=checkpoint.etag,
                    last_modified=checkpoint.last_modified,
                    cursor=_checkpoint_cursor(reconciled),
                    last_published_at=watermark,
                ),
            )

        semaphore = asyncio.Semaphore(concurrency)

        async def _fetch_one(entry: _SitemapEntry) -> RawItem | None:
            async with semaphore:
                try:
                    article_res = await self.ctx.aget(entry.loc, policy)
                except Exception as exc:
                    log.warning("sitemap article fetch failed for %s: %s", entry.loc, exc)
                    return None

            html_text = article_res.body.decode("utf-8", errors="replace")
            article = await asyncio.to_thread(extract_article, html_text)
            blob_ref = await asyncio.to_thread(get_blob_store().put, article_res.body)
            source_published = article.published or entry.lastmod
            published = _to_utc(source_published) if source_published else None
            raw_text = json.dumps(
                {
                    "url": entry.loc,
                    "title": article.title or "",
                    "body": article.body or "",
                    "published": article.published.isoformat() if article.published else None,
                    "lastmod": entry.lastmod.isoformat() if entry.lastmod else None,
                },
                ensure_ascii=False,
            )
            # Keep the v1 hash formula for compatibility with existing rows;
            # body revisions still create a new immutable content version.
            item_hash = content_sha256(entry.loc, article.body or "")
            if checkpoint.known_content_hashes.get(entry.loc) == item_hash:
                return None

            return RawItem(
                endpoint_id=policy.id,
                source_id=policy.source_id,
                native_id=entry.loc,
                request_url=entry.loc,
                final_url=article_res.final_url,
                http_status=article_res.status_code,
                published_at=published,
                fetched_at=article_res.fetched_at,
                language=policy.language,
                content_hash=item_hash,
                blob_ref=blob_ref,
                raw_text=raw_text,
                canonical_url=entry.loc,
                connector_kind=ConnectorKind.SITEMAP,
                connector_version=self.version,
            )

        results = await asyncio.gather(*(_fetch_one(entry) for entry in entries))
        items = [item for item in results if item is not None]
        return PollResult(
            items,
            Checkpoint(
                etag=checkpoint.etag,
                last_modified=checkpoint.last_modified,
                cursor=_checkpoint_cursor(reconciled),
                last_published_at=watermark,
            ),
        )

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        async def _run() -> PollResult:
            try:
                return await self.apoll(policy, checkpoint)
            finally:
                await self.ctx.aclose()

        return asyncio.run(_run())
