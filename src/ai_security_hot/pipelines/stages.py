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


def run_fetch_stage(limit: int = 5, lease_seconds: int | None = None) -> dict:
    """Claim due endpoints and fetch each. Returns run stats.

    Multiple endpoints are fetched concurrently (up to FETCH_CONCURRENCY)
    using asyncio.  Connectors that implement ``apoll`` (e.g. SitemapConnector)
    are awaited concurrently; synchronous connectors are run in a thread pool.
    """
    from ai_security_hot.config.settings import get_settings

    registry = load_registry()
    ctx = FetchContext()
    stats = {"endpoints": 0, "items_new": 0}
    effective_lease_seconds = lease_seconds or get_settings().lease_seconds

    with session_scope() as session:
        due_claims = repo.claim_due_endpoints(
            session, limit=limit, lease_seconds=effective_lease_seconds
        )

    if not due_claims:
        return stats

    async def _fetch_endpoint(endpoint_id: str, lease_token: str) -> int:
        policy = registry.endpoint(endpoint_id)
        stop_heartbeat = asyncio.Event()
        heartbeat = asyncio.create_task(
            _heartbeat_endpoint_lease(
                endpoint_id,
                lease_token,
                effective_lease_seconds,
                stop_heartbeat,
            )
        )
        try:
            return await _afetch_one(ctx, policy, lease_token)
        finally:
            stop_heartbeat.set()
            await heartbeat

    async def _run_all() -> list[int]:
        try:
            return await _gather_with_concurrency(
                FETCH_CONCURRENCY,
                [
                    _fetch_endpoint(endpoint_id, lease_token)
                    for endpoint_id, lease_token in due_claims
                ],
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


def _extend_lease(endpoint_id: str, lease_token: str, lease_seconds: int) -> bool:
    with session_scope() as session:
        return repo.extend_endpoint_lease(
            session,
            endpoint_id,
            lease_token,
            lease_seconds=lease_seconds,
        )


async def _heartbeat_endpoint_lease(
    endpoint_id: str,
    lease_token: str,
    lease_seconds: int,
    stop: asyncio.Event,
) -> None:
    interval = max(10.0, lease_seconds / 3)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            owned = await asyncio.to_thread(_extend_lease, endpoint_id, lease_token, lease_seconds)
            if not owned:
                log.warning("endpoint lease heartbeat lost ownership: %s", endpoint_id)
                return


async def _afetch_one(ctx: FetchContext, policy: EndpointPolicy, lease_token: str) -> int:
    """Async wrapper around _fetch_one — dispatches to apoll or runs poll in a
    thread pool for synchronous connectors."""
    connector = get_connector(policy.connector, ctx)

    if hasattr(connector, "apoll"):
        # async connector (e.g. SitemapConnector)
        return await _afetch_one_async(ctx, policy, connector, lease_token)
    else:
        # synchronous connector — run in a thread to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _fetch_one, ctx, policy, lease_token)


async def _afetch_one_async(
    ctx: FetchContext, policy: EndpointPolicy, connector, lease_token: str
) -> int:
    """Fetch one endpoint using an async connector's apoll method."""
    started_at = datetime.now(UTC)
    error: str | None = None
    items_new = 0
    items_fetched = 0
    next_interval_minutes = policy.schedule.interval_minutes
    next_jitter_seconds = policy.schedule.jitter_seconds
    with session_scope() as session:
        options = policy.options or {}
        known_limit = int(options.get("checkpoint_known_limit", 5000))
        include_active_ids = policy.connector is ConnectorKind.AIHOT or bool(
            (options.get("rest") or {}).get("authoritative_snapshot")
        )
        checkpoint = repo.load_checkpoint(
            session,
            policy.id,
            known_limit=known_limit,
            include_active_ids=include_active_ids,
        )
    try:
        result = await connector.apoll(policy, checkpoint)
        items_fetched = len(result.items)
        with session_scope() as session:
            repo.ensure_endpoint_lease(session, policy.id, lease_token)
            items_new = repo.persist_raw_items(session, result.items)
        new_checkpoint = result.checkpoint
        next_interval_minutes = (
            result.next_poll_minutes
            if result.next_poll_minutes is not None
            else policy.schedule.interval_minutes
        )
        if result.next_poll_minutes is not None:
            # Connector-directed catch-up is a durable state-machine step, not
            # a normal fleet-wide poll. Run it at the requested cadence.
            next_jitter_seconds = 0
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
            lease_token=lease_token,
            success=success,
            error=error,
            interval_minutes=next_interval_minutes,
            jitter_seconds=next_jitter_seconds,
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


def _fetch_one(ctx: FetchContext, policy: EndpointPolicy, lease_token: str) -> int:
    started_at = datetime.now(UTC)
    connector = get_connector(policy.connector, ctx)
    error: str | None = None
    items_new = 0
    items_fetched = 0
    next_interval_minutes = policy.schedule.interval_minutes
    next_jitter_seconds = policy.schedule.jitter_seconds
    with session_scope() as session:
        options = policy.options or {}
        known_limit = int(options.get("checkpoint_known_limit", 5000))
        include_active_ids = policy.connector is ConnectorKind.AIHOT or bool(
            (options.get("rest") or {}).get("authoritative_snapshot")
        )
        checkpoint = repo.load_checkpoint(
            session,
            policy.id,
            known_limit=known_limit,
            include_active_ids=include_active_ids,
        )
    try:
        result = connector.poll(policy, checkpoint)
        items_fetched = len(result.items)
        # 先存 RawItem，再推 checkpoint (MVP §3)
        with session_scope() as session:
            repo.ensure_endpoint_lease(session, policy.id, lease_token)
            items_new = repo.persist_raw_items(session, result.items)
        new_checkpoint = result.checkpoint
        next_interval_minutes = (
            result.next_poll_minutes
            if result.next_poll_minutes is not None
            else policy.schedule.interval_minutes
        )
        if result.next_poll_minutes is not None:
            # Connector-directed catch-up is a durable state-machine step, not
            # a normal fleet-wide poll. Run it at the requested cadence.
            next_jitter_seconds = 0
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
            lease_token=lease_token,
            success=success,
            error=error,
            interval_minutes=next_interval_minutes,
            jitter_seconds=next_jitter_seconds,
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
                    operation=raw.operation,
                )
                doc = parser.parse(dto)
                next_stage = PipelineStage.NORMALIZED if policy.fulltext else PipelineStage.DONE
                with session.begin_nested():
                    repo.persist_document(session, raw.id, doc, next_stage)
                stats["normalized"] += 1
            except Exception as e:
                log.warning("normalize failed for raw_item %s: %s", raw.id, e)
                raw.stage = PipelineStage.FAILED.value
                raw.stage_error = f"{type(e).__name__}: {e}"
                raw.stage_lease_until = None
                stats["failed"] += 1
    return stats


def _default_parser(connector: ConnectorKind) -> str:
    return {
        ConnectorKind.RSS: "rss-default-v1",
        ConnectorKind.REST: "cisa-kev-v1",
        ConnectorKind.NVD: "nvd-v1",
        ConnectorKind.AIHOT: "aihot-v1",
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
    ctx.close()
    return stats


def run_classify_stage(limit: int | None = None) -> dict:
    """Run leased rule or cached hybrid classification independently of fetch."""
    from time import monotonic

    from ai_security_hot.classify.base import Classification
    from ai_security_hot.classify.llm import HybridClassifier
    from ai_security_hot.classify.rules import RuleClassifier
    from ai_security_hot.config.settings import get_settings
    from ai_security_hot.domain.models import NormalizedDocument
    from ai_security_hot.llm.registry import build_provider

    settings = get_settings()
    registry = load_registry()
    ep_map = {e.id: (e.source_id, e.connector.value) for e in registry.endpoints}
    rules = RuleClassifier()
    requested_mode = settings.classification_mode
    effective_mode = requested_mode
    hybrid: HybridClassifier | None = None
    config_fallback = False

    if requested_mode == "hybrid":
        try:
            provider = build_provider(settings)
        except ValueError as exc:
            log.warning("hybrid classification configuration invalid; using rules: %s", exc)
            effective_mode = "rule"
            config_fallback = True
        else:
            hybrid = HybridClassifier(
                provider,
                max_input_chars=settings.llm_max_input_chars,
                max_output_tokens=settings.llm_max_output_tokens,
            )

    default_batch_size = (
        settings.rule_classification_batch_size
        if effective_mode == "rule"
        else settings.classification_batch_size
    )
    batch_size = limit if limit is not None else default_batch_size
    model_version = hybrid.model_version if hybrid else None
    prompt_version = hybrid.prompt_version if hybrid else None
    with session_scope() as session:
        rows = repo.claim_unclassified_documents(
            session,
            limit=batch_size,
            mode=effective_mode,
            rule_version=rules.tax.version,
            model_version=model_version,
            prompt_version=prompt_version,
            lease_seconds=settings.classification_lease_seconds,
        )
        work = []
        for d in rows:
            doc = NormalizedDocument(
                raw_item_native_id=str(d.raw_item_id),
                endpoint_id=d.endpoint_id,
                title_original=d.title_original,
                title_zh=d.title_zh,
                body_text=d.body_text,
                canonical_url=d.canonical_url,
                published_at_utc=d.published_at_utc,
                language=d.language,
                cve_ids=(d.identifiers or {}).get("cve", []),
                ghsa_ids=(d.identifiers or {}).get("ghsa", []),
                cnvd_ids=(d.identifiers or {}).get("cnvd", []),
                cwe_ids=(d.identifiers or {}).get("cwe", []),
                entities=d.entities or {},
                parse_quality=d.parse_quality,
            )
            if not d.classify_lease_token:
                raise RuntimeError(f"classification lease token missing: {d.id}")
            work.append((d.id, d.classify_attempts, d.classify_lease_token, doc))

    stats = {
        "claimed": len(work),
        "classified": 0,
        "rules": 0,
        "model_calls": 0,
        "cache_hits": 0,
        "fallbacks": 0,
        "lease_lost": 0,
        "config_fallback": config_fallback,
    }
    if effective_mode == "rule":
        with session_scope() as session:
            owned = repo.extend_classification_leases(
                session,
                [document_id for document_id, _attempts, _token, _doc in work],
                work[0][2] if work else "",
                lease_seconds=settings.classification_lease_seconds,
            )
            for document_id, _attempts, lease_token, doc in work:
                if document_id not in owned:
                    stats["lease_lost"] += 1
                    continue
                source_id, connector = ep_map.get(doc.endpoint_id, (None, None))
                baseline = rules.classify(doc, source_id=source_id, connector=connector)
                try:
                    with session.begin_nested():
                        repo.apply_classification(
                            session, document_id, baseline, lease_token=lease_token
                        )
                except repo.ClassificationLeaseLost:
                    log.warning("classification lease lost in rule batch: %s", document_id)
                    stats["lease_lost"] += 1
                    continue
                stats["classified"] += 1
                stats["rules"] += 1
        return stats

    for index, (document_id, attempts, lease_token, doc) in enumerate(work):
        # Keep every not-yet-processed document alive while this batch performs
        # sequential, rate-limited model calls. A reclaimed row has a new token
        # and is skipped before any external cost or database write.
        remaining_ids = [row[0] for row in work[index:]]
        with session_scope() as session:
            owned = repo.extend_classification_leases(
                session,
                remaining_ids,
                lease_token,
                lease_seconds=settings.classification_lease_seconds,
            )
        if document_id not in owned:
            log.warning("classification lease lost before model call: %s", document_id)
            stats["lease_lost"] += 1
            continue

        source_id, connector = ep_map.get(doc.endpoint_id, (None, None))
        baseline = rules.classify(doc, source_id=source_id, connector=connector)
        if baseline.tech_directions == ["cve"]:
            try:
                with session_scope() as session:
                    repo.apply_classification(
                        session, document_id, baseline, lease_token=lease_token
                    )
            except repo.ClassificationLeaseLost:
                log.warning("classification lease lost for CVE document: %s", document_id)
                stats["lease_lost"] += 1
                continue
            stats["classified"] += 1
            stats["rules"] += 1
            continue

        assert hybrid is not None
        cache_key = {
            "task": "classification",
            "provider": hybrid.provider.name,
            "model": hybrid.model_version,
            "prompt_version": hybrid.prompt_version,
            "input_hash": hybrid.input_hash(doc),
        }
        with session_scope() as session:
            cached = repo.get_model_cache(session, **cache_key)
        if cached is not None:
            try:
                classification = Classification.model_validate(cached)
            except Exception as exc:
                log.warning("discarding invalid classification cache entry: %s", exc)
                with session_scope() as session:
                    repo.delete_model_cache(session, **cache_key)
            else:
                try:
                    with session_scope() as session:
                        repo.record_model_run(
                            session,
                            document_id=document_id,
                            task=cache_key["task"],
                            provider=cache_key["provider"],
                            model=cache_key["model"],
                            prompt_version=cache_key["prompt_version"],
                            input_hash=cache_key["input_hash"],
                            status="cache_hit",
                            latency_ms=0,
                        )
                        repo.apply_classification(
                            session,
                            document_id,
                            classification,
                            lease_token=lease_token,
                        )
                except repo.ClassificationLeaseLost:
                    log.warning("classification lease lost on cache hit: %s", document_id)
                    stats["lease_lost"] += 1
                    continue
                stats["classified"] += 1
                stats["cache_hits"] += 1
                continue

        started = monotonic()
        stats["model_calls"] += 1
        try:
            outcome = hybrid.classify_with_metadata(doc, source_id=source_id, connector=connector)
            latency_ms = round((monotonic() - started) * 1000)
            with session_scope() as session:
                repo.put_model_cache(
                    session,
                    output=outcome.classification.model_dump(mode="json"),
                    **cache_key,
                )
                repo.record_model_run(
                    session,
                    document_id=document_id,
                    task=cache_key["task"],
                    provider=cache_key["provider"],
                    model=cache_key["model"],
                    prompt_version=cache_key["prompt_version"],
                    input_hash=cache_key["input_hash"],
                    status="success",
                    latency_ms=latency_ms,
                    usage=outcome.usage,
                )
                repo.apply_classification(
                    session,
                    document_id,
                    outcome.classification,
                    lease_token=lease_token,
                )
            stats["classified"] += 1
        except repo.ClassificationLeaseLost:
            log.warning("classification lease lost after model call: %s", document_id)
            stats["lease_lost"] += 1
            continue
        except Exception as exc:
            latency_ms = round((monotonic() - started) * 1000)
            error = f"{type(exc).__name__}: {exc}"
            fallback = baseline.model_copy(
                update={
                    "method": "rule_fallback",
                    "model_version": hybrid.model_version,
                    "prompt_version": hybrid.prompt_version,
                    "input_hash": hybrid.input_hash(doc),
                }
            )
            retry_seconds = min(86400, 60 * (2 ** min(attempts, 10)))
            try:
                with session_scope() as session:
                    repo.record_model_run(
                        session,
                        document_id=document_id,
                        task=cache_key["task"],
                        provider=cache_key["provider"],
                        model=cache_key["model"],
                        prompt_version=cache_key["prompt_version"],
                        input_hash=cache_key["input_hash"],
                        status="fallback",
                        latency_ms=latency_ms,
                        error=error,
                    )
                    repo.apply_classification(
                        session,
                        document_id,
                        fallback,
                        lease_token=lease_token,
                        error=error,
                        retry_after_seconds=retry_seconds,
                    )
            except repo.ClassificationLeaseLost:
                log.warning("classification lease lost before fallback write: %s", document_id)
                stats["lease_lost"] += 1
                continue
            log.warning("classification fallback for document %s: %s", document_id, error)
            stats["classified"] += 1
            stats["fallbacks"] += 1
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
