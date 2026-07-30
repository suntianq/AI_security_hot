"""REST/JSON connector with rolling windows, pagination and revision detection.

Item extraction remains configuration-driven. Date-window APIs can overlap
requests safely because unchanged native-id/content-hash pairs are filtered
before persistence; paginated APIs are drained until ``totalResults``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import FetchResult, RawItem, content_sha256


def _set_query_params(url: str, values: Mapping[str, str | int]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({key: str(value) for key, value in values.items()})
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def _inject_date_params(
    url: str,
    date_params: dict,
    last_success_at: datetime | None = None,
) -> str:
    """Inject a rolling time window, with a safe overlap on incremental polls.

    ``overlap_minutes`` intentionally re-requests a small slice before the last
    successful fetch. Content-hash idempotency removes duplicates and protects
    against delayed/out-of-order publication.
    """
    fmt = date_params.get("format", "%Y-%m-%dT%H:%M:%S.000")
    now = datetime.now(UTC)

    extra: dict[str, str] = {}
    for side in ("start", "end"):
        cfg = date_params.get(side)
        if not cfg:
            continue
        param_name = cfg.get("param")
        if not param_name:
            continue
        if side == "start" and last_success_at:
            overlap = int(date_params.get("overlap_minutes", 0))
            ts = last_success_at - timedelta(minutes=overlap)
        else:
            offset = cfg.get("offset_days", 0)
            ts = now - timedelta(days=offset)
        extra[param_name] = ts.strftime(fmt)

    return _set_query_params(url, extra) if extra else url


def _as_int(value: object, default: int) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


class RestApiConnector(Connector):
    version = "rest-2"

    default_list_key = "vulnerabilities"
    default_id_field = "cveID"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("rest", {})
        list_key = opts.get("list_key", self.default_list_key)
        id_field = opts.get("id_field", self.default_id_field)
        nested_key = opts.get("nested_key")
        date_params = opts.get("date_params")
        pagination = opts.get("pagination")

        base_url = (
            _inject_date_params(policy.url, date_params, checkpoint.last_success_at)
            if date_params
            else policy.url
        )
        page_url = base_url
        pages: list[tuple[FetchResult, dict | list, str]] = []
        max_pages = _as_int((pagination or {}).get("max_pages"), 100)

        while len(pages) < max_pages:
            res = self.ctx.get(
                page_url,
                policy,
                etag=checkpoint.etag if not date_params and not pages else None,
                last_modified=(
                    checkpoint.last_modified if not date_params and not pages else None
                ),
            )
            if res.from_cache and not pages:
                return PollResult([], checkpoint, not_modified=True)

            payload = json.loads(res.body)
            pages.append((res, payload, page_url))
            if not pagination or not isinstance(payload, dict):
                break

            records = payload.get(list_key, [])
            start_key = pagination.get("start_key", "startIndex")
            total_key = pagination.get("total_key", "totalResults")
            page_size_key = pagination.get("page_size_key", "resultsPerPage")
            start_param = pagination.get("start_param", start_key)
            start = _as_int(payload.get(start_key), 0)
            page_size = _as_int(payload.get(page_size_key), len(records))
            total = _as_int(payload.get(total_key), len(records))
            consumed = max(page_size, len(records))
            next_start = start + consumed
            if not records or consumed <= 0 or next_start >= total:
                break
            page_url = _set_query_params(base_url, {start_param: next_start})

        items: list[RawItem] = []
        for res, payload, request_url in pages:
            records = payload.get(list_key, []) if isinstance(payload, dict) else payload
            for outer in records:
                rec = outer.get(nested_key, outer) if nested_key else outer
                native_id = str(rec.get(id_field) or rec.get("id") or "")
                if not native_id:
                    continue
                raw_text = json.dumps(rec, ensure_ascii=False, sort_keys=True)
                item_hash = content_sha256(native_id, raw_text)
                if checkpoint.known_content_hashes.get(native_id) == item_hash:
                    continue
                items.append(
                    RawItem(
                        endpoint_id=policy.id,
                        source_id=policy.source_id,
                        native_id=native_id,
                        request_url=request_url,
                        final_url=res.final_url,
                        http_status=res.status_code,
                        published_at=None,
                        fetched_at=res.fetched_at,
                        language=policy.language,
                        content_hash=item_hash,
                        raw_text=raw_text,
                        canonical_url=f"{policy.url}#{native_id}",
                        connector_kind=ConnectorKind.REST,
                        connector_version=self.version,
                    )
                )

        first_res = pages[0][0]
        new_ck = Checkpoint(
            etag=(first_res.etag or checkpoint.etag) if not date_params else None,
            last_modified=(
                (first_res.last_modified or checkpoint.last_modified)
                if not date_params
                else None
            ),
            cursor=checkpoint.cursor,
            last_published_at=checkpoint.last_published_at,
        )
        return PollResult(items, new_ck)
