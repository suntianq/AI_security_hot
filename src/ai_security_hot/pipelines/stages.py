"""Pipeline stage runners — the stage state machine (plan 修正 1).

Each stage claims its own work from the DB, so a slow stage never blocks a
fast one. M0 implements two real stages end-to-end:

  fetch      : poll endpoint → persist RawItems → advance checkpoint
  normalize  : parse RawItem (stage=FETCHED) → Document → stage=NORMALIZED
  fulltext   : for fulltext-enabled endpoints whose feed only gave a summary,
               second-fetch the article URL → update Document.body_text → DONE

M2 adds versioned dedupe and event clustering after classification. Enrichment
and delivery remain later milestones.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from ai_security_hot.config.sources import EndpointPolicy, load_registry
from ai_security_hot.connectors.fetch import FetchContext
from ai_security_hot.connectors.registry import get_connector, get_parser
from ai_security_hot.domain.enums import ConnectorKind, PipelineStage
from ai_security_hot.models.base import session_scope
from ai_security_hot.parsers.article import extract_article
from ai_security_hot.parsers.normalize import score_parse_quality
from ai_security_hot.storage import repositories as repo

log = logging.getLogger("intel.pipeline")

FULLTEXT_MIN_BODY = 400

# max concurrent endpoint fetches in a single tick
FETCH_CONCURRENCY = 5


def run_fetch_stage(limit: int = 5, lease_seconds: int = 300) -> dict:
    """Claim due endpoints and fetch each. Returns run stats.

    Multiple endpoints are fetched concurrently (up to FETCH_CONCURRENCY)
    using asyncio.  Connectors that implement ``apoll`` (e.g. SitemapConnector)
    are awaited concurrently; synchronous connectors are run in a thread pool.
    """
    registry = load_registry()
    ctx = FetchContext()
    stats = {"endpoints": 0, "items_new": 0}

    with session_scope() as session:
        due_ids = repo.claim_due_endpoints(session, limit=limit, lease_seconds=lease_seconds)

    if not due_ids:
        return stats

    async def _fetch_endpoint(endpoint_id: str) -> int:
        policy = registry.endpoint(endpoint_id)
        return await _afetch_one(ctx, policy)

    async def _run_all() -> list[int]:
        try:
            return await _gather_with_concurrency(
                FETCH_CONCURRENCY, [_fetch_endpoint(endpoint_id) for endpoint_id in due_ids]
            )
        finally:
            await ctx.aclose()

    results = asyncio.run(_run_all())

    for new_count in results:
        stats["items_new"] += new_count
        stats["endpoints"] += 1
    return stats


async def _gather_with_concurrency(concurrency: int, coros: list) -> list:
    """Run coros with a semaphore to limit concurrency."""
    sem = asyncio.Semaphore(concurrency)

    async def _wrap(c):
        async with sem:
            return await c

    return await asyncio.gather(*[_wrap(c) for c in coros])


async def _afetch_one(ctx: FetchContext, policy: EndpointPolicy) -> int:
    """Async wrapper around _fetch_one — dispatches to apoll or runs poll in a
    thread pool for synchronous connectors."""
    connector = get_connector(policy.connector, ctx)

    if hasattr(connector, "apoll"):
        # async connector (e.g. SitemapConnector)
        return await _afetch_one_async(ctx, policy, connector)
    else:
        # synchronous connector — run in a thread to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _fetch_one, ctx, policy)


async def _afetch_one_async(ctx: FetchContext, policy: EndpointPolicy, connector) -> int:
    """Fetch one endpoint using an async connector's apoll method."""
    started_at = datetime.now(UTC)
    error: str | None = None
    items_new = 0
    items_fetched = 0
    with session_scope() as session:
        checkpoint = repo.load_checkpoint(session, policy.id)
    try:
        result = await connector.apoll(policy, checkpoint)
        items_fetched = len(result.items)
        with session_scope() as session:
            items_new = repo.persist_raw_items(session, result.items)
        new_checkpoint = result.checkpoint
        success = True
    except Exception as e:
        log.warning("fetch failed for %s: %s", policy.id, e)
        error = f"{type(e).__name__}: {e}"
        new_checkpoint = checkpoint
        success = False

    with session_scope() as session:
        repo.advance_checkpoint(
            session,
            policy.id,
            new_checkpoint,
            success=success,
            error=error,
            interval_minutes=policy.schedule.interval_minutes,
            jitter_seconds=policy.schedule.jitter_seconds,
        )
        repo.record_fetch_run(
            session,
            policy.id,
            status="ok" if success else "error",
            items_fetched=items_fetched,
            items_new=items_new,
            error=error,
            started_at=started_at,
        )
    log.info("fetched %s: fetched=%d new=%d ok=%s", policy.id, items_fetched, items_new, success)
    return items_new


def _fetch_one(ctx: FetchContext, policy: EndpointPolicy) -> int:
    started_at = datetime.now(UTC)
    connector = get_connector(policy.connector, ctx)
    error: str | None = None
    items_new = 0
    items_fetched = 0
    with session_scope() as session:
        checkpoint = repo.load_checkpoint(session, policy.id)
    try:
        result = connector.poll(policy, checkpoint)
        items_fetched = len(result.items)
        # 先存 RawItem，再推 checkpoint (MVP §3)
        with session_scope() as session:
            items_new = repo.persist_raw_items(session, result.items)
        new_checkpoint = result.checkpoint
        success = True
    except Exception as e:
        log.warning("fetch failed for %s: %s", policy.id, e)
        error = f"{type(e).__name__}: {e}"
        new_checkpoint = checkpoint
        success = False

    with session_scope() as session:
        repo.advance_checkpoint(
            session,
            policy.id,
            new_checkpoint,
            success=success,
            error=error,
            interval_minutes=policy.schedule.interval_minutes,
            jitter_seconds=policy.schedule.jitter_seconds,
        )
        repo.record_fetch_run(
            session,
            policy.id,
            status="ok" if success else "error",
            items_fetched=items_fetched,
            items_new=items_new,
            error=error,
            started_at=started_at,
        )
    log.info("fetched %s: fetched=%d new=%d ok=%s", policy.id, items_fetched, items_new, success)
    return items_new


def run_normalize_stage(limit: int = 50, lease_seconds: int = 300) -> dict:
    """Parse FETCHED raw items into Documents (stage → NORMALIZED)."""
    registry = load_registry()
    stats = {"normalized": 0, "failed": 0}
    with session_scope() as session:
        rows = repo.claim_stage_items(
            session, PipelineStage.FETCHED, limit=limit, lease_seconds=lease_seconds
        )
        for raw in rows:
            try:
                policy = registry.endpoint(raw.endpoint_id)
                parser_name = policy.parser or _default_parser(policy.connector)
                parser = get_parser(parser_name)
                # rebuild a RawItem DTO for the parser
                from ai_security_hot.domain.models import RawItem as RawItemDTO

                dto = RawItemDTO(
                    endpoint_id=raw.endpoint_id,
                    source_id=raw.source_id,
                    native_id=raw.native_id,
                    request_url=raw.request_url,
                    final_url=raw.final_url,
                    http_status=raw.http_status,
                    published_at=raw.published_at,
                    fetched_at=raw.fetched_at,
                    language=raw.language,
                    content_hash=raw.content_hash,
                    blob_ref=raw.blob_ref,
                    raw_text=raw.raw_text,
                    canonical_url=raw.canonical_url,
                    connector_kind=ConnectorKind(policy.connector),
                    connector_version=raw.connector_version,
                )
                doc = parser.parse(dto)
                repo.persist_document(session, raw.id, doc, PipelineStage.NORMALIZED)
                stats["normalized"] += 1
            except Exception as e:
                log.warning("normalize failed for raw_item %s: %s", raw.id, e)
                raw.stage = PipelineStage.FAILED.value
                raw.stage_error = f"{type(e).__name__}: {e}"
                raw.stage_lease_until = None
                stats["failed"] += 1
        session.commit()
    return stats


def _default_parser(connector: ConnectorKind) -> str:
    return {
        ConnectorKind.RSS: "rss-default-v1",
        ConnectorKind.REST: "cisa-kev-v1",
        ConnectorKind.GITHUB: "github-releases-v1",
        ConnectorKind.WEB: "web-article-v1",
        ConnectorKind.ARXIV: "arxiv-v1",
        ConnectorKind.SITEMAP: "sitemap-article-v1",
    }[connector]


def run_fulltext_stage(limit: int = 20, lease_seconds: int = 300) -> dict:
    """Second-fetch full article text for fulltext-enabled endpoints whose feed
    only gave a summary (stage NORMALIZED → DONE). SPA sources stay off — they
    keep title + link only (Playwright not worth the cost)."""
    registry = load_registry()
    ft_policies = {e.id: e for e in registry.endpoints if e.fulltext}
    stats = {"enriched": 0, "skipped": 0, "failed": 0}
    if not ft_policies:
        return stats

    ctx = FetchContext()
    with session_scope() as session:
        pairs = repo.claim_fulltext_candidates(
            session, list(ft_policies), limit=limit, lease_seconds=lease_seconds
        )

    for raw, doc in pairs:
        policy = ft_policies[raw.endpoint_id]
        try:
            # already long enough? advance without a second fetch
            if doc.body_text and len(doc.body_text) >= FULLTEXT_MIN_BODY:
                with session_scope() as session:
                    repo.apply_fulltext(session, raw.id, doc.id, body_text=None, parse_quality=None)
                stats["skipped"] += 1
                continue

            res = ctx.get(doc.canonical_url, policy)
            html = res.body.decode("utf-8", errors="replace")
            art = extract_article(html)
            if art.body and len(art.body) > (len(doc.body_text or "")):
                quality = score_parse_quality(
                    title=doc.title_original,
                    published_at_present=doc.published_at_utc is not None,
                    body_text=art.body,
                    min_body_len=FULLTEXT_MIN_BODY,
                )
                with session_scope() as session:
                    repo.apply_fulltext(
                        session, raw.id, doc.id, body_text=art.body, parse_quality=quality
                    )
                stats["enriched"] += 1
            else:
                # SPA / no static body — keep summary + link, just advance
                with session_scope() as session:
                    repo.apply_fulltext(session, raw.id, doc.id, body_text=None, parse_quality=None)
                stats["skipped"] += 1
        except Exception as e:
            log.warning("fulltext failed for doc %s (%s): %s", doc.id, doc.canonical_url, e)
            with session_scope() as session:
                repo.apply_fulltext(session, raw.id, doc.id, body_text=None, parse_quality=None)
            stats["failed"] += 1
    return stats


def run_classify_stage(limit: int = 500) -> dict:
    """Classify documents that have no classification yet (M1.1, rule-based).

    Uses the endpoint registry to supply source_id/connector hints for the
    event_type rules. Classifier is swappable (RuleClassifier now; LLM/Hybrid
    in M1.3) — this runner does not change when the implementation does.
    """
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.domain.models import NormalizedDocument

    registry = load_registry()
    ep_map = {e.id: (e.source_id, e.connector.value) for e in registry.endpoints}
    classifier = RuleClassifier()
    stats = {"classified": 0}

    with session_scope() as session:
        docs = repo.claim_unclassified_documents(
            session,
            limit=limit,
            rule_version=classifier.tax.version,
        )
        for d in docs:
            ndoc = NormalizedDocument(
                raw_item_native_id=str(d.raw_item_id),
                endpoint_id=d.endpoint_id,
                title_original=d.title_original,
                body_text=d.body_text,
                canonical_url=d.canonical_url,
                cve_ids=(d.identifiers or {}).get("cve", []),
                ghsa_ids=(d.identifiers or {}).get("ghsa", []),
                cnvd_ids=(d.identifiers or {}).get("cnvd", []),
            )
            source_id, connector = ep_map.get(d.endpoint_id, (None, None))
            cls = classifier.classify(ndoc, source_id=source_id, connector=connector)
            repo.apply_classification(session, d.id, cls)
            stats["classified"] += 1
    return stats


def run_dedupe_stage(*, force: bool = False) -> dict:
    """Recompute deterministic duplicate components when the rule version is stale."""
    from ai_security_hot.events.intelligence import DEDUPE_VERSION, deduplicate_documents

    with session_scope() as session:
        if not repo.try_event_stage_lock(session, "dedupe"):
            return {"status": "locked", "version": DEDUPE_VERSION}
        due = repo.count_dedupe_due(session)
        if due == 0 and not force:
            return {
                "status": "current",
                "version": DEDUPE_VERSION,
                "due": 0,
                "updated": 0,
            }
        documents = repo.load_intel_documents(session)
        decisions = deduplicate_documents(documents)
        stats = repo.apply_dedup_decisions(session, decisions)
        return {
            "status": "ok",
            "version": DEDUPE_VERSION,
            "due": due,
            "scanned": len(documents),
            **stats,
        }


def run_cluster_stage(*, force: bool = False) -> dict:
    """Materialize explainable events and evidence links from deduped documents."""
    from ai_security_hot.events.intelligence import CLUSTER_VERSION, build_event_drafts

    with session_scope() as session:
        if not repo.try_event_stage_lock(session, "cluster"):
            return {"status": "locked", "version": CLUSTER_VERSION}
        due = repo.count_cluster_due(session)
        if due == 0 and not force:
            return {
                "status": "current",
                "version": CLUSTER_VERSION,
                "due": 0,
                "events_created": 0,
                "events_updated": 0,
            }
        decisions = repo.load_dedup_decisions(session)
        documents = [doc for doc in repo.load_intel_documents(session) if doc.id in decisions]
        drafts = build_event_drafts(documents, decisions)
        stats = repo.apply_event_drafts(session, drafts)
        return {
            "status": "ok",
            "version": CLUSTER_VERSION,
            "due": due,
            "documents": len(documents),
            "events": len(drafts),
            **stats,
        }
