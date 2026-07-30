"""AI HOT selected-set mirror using snapshot + durable changes cursor."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from dateutil.parser import isoparse

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256


def _query(url: str, **values: str | int) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query.update({k: str(v) for k, v in values.items()})
    return urlunparse(parsed._replace(query=urlencode(query)))


def _published(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    dt = isoparse(value)
    return dt.astimezone(UTC) if dt.tzinfo else dt.replace(tzinfo=UTC)


class AIHotConnector(Connector):
    """Maintain an exact local selected-set mirror, including removals."""

    version = "aihot-selected-v1"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        if not checkpoint.cursor:
            return self._snapshot(policy, checkpoint)
        try:
            return self._changes(policy, checkpoint)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 409:
                raise
            # 409 snapshot_required is the API's sole unsafe-resume signal.
            return self._snapshot(policy, checkpoint)

    def _snapshot(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("aihot", {})
        fields = str(opts.get("fields", "default"))
        limit = int(opts.get("snapshot_limit", 500))
        max_pages = int(opts.get("max_pages", 100))
        page: str | None = None
        cursor: str | None = None
        selected_ids: set[str] = set()
        items: list[RawItem] = []

        for _ in range(max_pages):
            params: dict[str, str | int] = {"fields": fields, "limit": limit}
            if page:
                params["page"] = page
            url = _query(policy.url, **params)
            res = self.ctx.get(url, policy)
            payload = json.loads(res.body)
            page_cursor = str(payload["cursor"])
            if cursor is None:
                cursor = page_cursor
            elif page_cursor != cursor:
                raise ValueError("AI HOT snapshot cursor changed between pages")
            for item in payload.get("items", []):
                native_id = str(item.get("id") or "")
                if not native_id:
                    continue
                selected_ids.add(native_id)
                raw = self._upsert(policy, item, res.fetched_at, url)
                if checkpoint.known_content_hashes.get(native_id) != raw.content_hash:
                    items.append(raw)
            if not payload.get("hasMore"):
                break
            page = payload.get("nextPage")
            if not page:
                raise ValueError("AI HOT snapshot hasMore=true without nextPage")
        else:
            raise ValueError(f"AI HOT snapshot exceeded max_pages={max_pages}")

        for native_id in sorted(checkpoint.active_native_ids - selected_ids):
            items.append(self._remove(policy, native_id, datetime.now(UTC), policy.url))
        if cursor is None:
            raise ValueError("AI HOT snapshot did not return a cursor")
        return PollResult(items, Checkpoint(cursor=cursor))

    def _changes(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("aihot", {})
        limit = int(opts.get("changes_limit", 100))
        max_pages = int(opts.get("max_pages", 100))
        changes_url = str(opts.get("changes_url") or "")
        if not changes_url:
            raise ValueError("AI HOT changes_url is required")
        cursor = checkpoint.cursor
        initial_cursor = cursor
        items: list[RawItem] = []
        last_etag: str | None = None

        for page_number in range(max_pages):
            if not cursor:
                raise ValueError("AI HOT changes requires a cursor")
            url = _query(changes_url, cursor=cursor, limit=limit)
            res = self.ctx.get(
                url,
                policy,
                etag=checkpoint.etag if page_number == 0 else None,
            )
            if res.from_cache:
                return PollResult([], checkpoint, not_modified=True)
            payload = json.loads(res.body)
            for change in payload.get("changes", []):
                op = change.get("op")
                if op == "upsert":
                    item = change.get("item") or {}
                    native_id = str(item.get("id") or "")
                    raw = self._upsert(policy, item, res.fetched_at, url)
                    if (
                        native_id
                        and checkpoint.known_content_hashes.get(native_id) != raw.content_hash
                    ):
                        items.append(raw)
                elif op == "remove":
                    native_id = str(change.get("id") or "")
                    if native_id and native_id in checkpoint.active_native_ids:
                        changed_at = _published(change.get("changedAt")) or res.fetched_at
                        items.append(self._remove(policy, native_id, changed_at, url))
            cursor = str(payload["cursor"])
            last_etag = res.etag
            if not payload.get("hasMore"):
                break
        else:
            raise ValueError(f"AI HOT changes exceeded max_pages={max_pages}")

        etag = last_etag if cursor == initial_cursor else None
        return PollResult(items, Checkpoint(cursor=cursor, etag=etag))

    def _upsert(
        self, policy: EndpointPolicy, item: dict, fetched_at: datetime, request_url: str
    ) -> RawItem:
        native_id = str(item.get("id") or "")
        raw_text = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        links = item.get("links") or {}
        canonical = links.get("original") or links.get("aihot") or f"{policy.url}#{native_id}"
        return RawItem(
            endpoint_id=policy.id,
            source_id=policy.source_id,
            native_id=native_id,
            request_url=request_url,
            final_url=request_url,
            http_status=200,
            published_at=_published(item.get("publishedAt")),
            fetched_at=fetched_at,
            language=policy.language,
            content_hash=content_sha256("upsert", native_id, raw_text),
            raw_text=raw_text,
            canonical_url=str(canonical),
            connector_kind=ConnectorKind.AIHOT,
            connector_version=self.version,
        )

    def _remove(
        self, policy: EndpointPolicy, native_id: str, changed_at: datetime, request_url: str
    ) -> RawItem:
        raw_text = json.dumps(
            {"op": "remove", "id": native_id, "changedAt": changed_at.isoformat()},
            sort_keys=True,
            separators=(",", ":"),
        )
        return RawItem(
            endpoint_id=policy.id,
            source_id=policy.source_id,
            native_id=native_id,
            request_url=request_url,
            final_url=request_url,
            http_status=200,
            fetched_at=changed_at,
            language=policy.language,
            content_hash=content_sha256("withdraw", native_id, raw_text),
            raw_text=raw_text,
            canonical_url=f"{policy.url}#{native_id}",
            connector_kind=ConnectorKind.AIHOT,
            connector_version=self.version,
            operation="withdraw",
        )
