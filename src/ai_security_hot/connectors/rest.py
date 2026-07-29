"""REST/JSON connector — MVP 5.2. Generic JSON feed; item extraction is
delegated to the parser, so here we produce one RawItem per top-level record
using a configurable list key (default: CISA KEV 'vulnerabilities').

Supports ``date_params`` in ``options.rest`` to inject rolling time-window
query parameters into the URL at fetch time — e.g. NVD's ``pubStartDate`` /
``pubEndDate``.  Any time-window API can reuse this without code changes.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlparse, urlunparse

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256


def _inject_date_params(
    url: str,
    date_params: dict,
    last_success_at: datetime | None = None,
) -> str:
    """Inject rolling time-window query params into *url* at fetch time.

    ``date_params`` schema (inside ``options.rest``)::

        date_params:
          start:
            param: pubStartDate      # query-key for the start of the window
            offset_days: 30          # fallback: start = now - offset_days
          end:
            param: pubEndDate        # query-key for the end of the window
            offset_days: 0           # end = now - offset_days  (0 = now)
          format: "%Y-%m-%dT%H:%M:%S.000"   # strftime format

    **Incremental mode**: if ``last_success_at`` is provided (from the
    checkpoint), it is used as the start time instead of ``now - offset_days``.
    This means on subsequent polls only items published since the last
    successful fetch are requested.  On the very first poll (no
    ``last_success_at``), the ``offset_days`` fallback is used.
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
            ts = last_success_at
        else:
            offset = cfg.get("offset_days", 0)
            ts = now - timedelta(days=offset)
        extra[param_name] = ts.strftime(fmt)

    if not extra:
        return url

    parsed = urlparse(url)
    existing = dict(p.split("=", 1) for p in parsed.query.split("&") if p and "=" in p)
    existing.update(extra)
    new_query = urlencode(existing, doseq=True)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    )


class RestApiConnector(Connector):
    version = "rest-1"

    # defaults target CISA KEV; override per endpoint via policy.options.rest
    default_list_key = "vulnerabilities"
    default_id_field = "cveID"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("rest", {})
        list_key = opts.get("list_key", self.default_list_key)
        id_field = opts.get("id_field", self.default_id_field)
        nested_key = opts.get("nested_key")  # e.g. NVD: each record is under ".cve"
        date_params = opts.get("date_params")  # rolling time-window params

        fetch_url = (
            _inject_date_params(policy.url, date_params, checkpoint.last_success_at)
            if date_params
            else policy.url
        )

        res = self.ctx.get(
            fetch_url,
            policy,
            etag=checkpoint.etag if not date_params else None,
            last_modified=checkpoint.last_modified if not date_params else None,
        )
        if res.from_cache:
            return PollResult([], checkpoint, not_modified=True)

        payload = json.loads(res.body)
        records = payload.get(list_key, []) if isinstance(payload, dict) else payload
        items: list[RawItem] = []
        for outer in records:
            rec = outer.get(nested_key, outer) if nested_key else outer
            native_id = str(rec.get(id_field) or rec.get("id") or "")
            if not native_id:
                continue
            raw_text = json.dumps(rec, ensure_ascii=False, sort_keys=True)
            items.append(
                RawItem(
                    endpoint_id=policy.id,
                    source_id=policy.source_id,
                    native_id=native_id,
                    request_url=fetch_url,
                    final_url=res.final_url,
                    http_status=res.status_code,
                    published_at=None,
                    fetched_at=res.fetched_at,
                    language=policy.language,
                    content_hash=content_sha256(native_id, raw_text),
                    raw_text=raw_text,
                    canonical_url=f"{policy.url}#{native_id}",
                    connector_kind=ConnectorKind.REST,
                    connector_version=self.version,
                )
            )

        new_ck = Checkpoint(
            etag=(res.etag or checkpoint.etag) if not date_params else None,
            last_modified=(
                (res.last_modified or checkpoint.last_modified) if not date_params else None
            ),
            cursor=checkpoint.cursor,
        )
        return PollResult(items, new_ck)
