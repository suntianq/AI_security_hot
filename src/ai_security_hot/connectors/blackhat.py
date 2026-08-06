"""Black Hat Briefings connector (playwright-backed, shared-volume bridge).

Black Hat's schedule pages sit behind a Cloudflare JS challenge that a plain
HTTP client cannot pass, so the fetch itself runs in a separate Playwright
container (scripts/blackhat_fetch.py) which writes the raw ``sessions.json``
to a shared volume. This connector reads that file, keeps only Briefings
sessions, and emits one RawItem per session with content-hash idempotency so
unchanged sessions are not re-emitted on later polls.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256

# Program string for the Briefings schedule (Arsenal has its own sessions.json).
_BRIEFINGS_PROGRAM = "Briefings"


def _parse_iso(iso_value: str | None) -> datetime | None:
    if not iso_value:
        return None
    try:
        return datetime.fromisoformat(iso_value.replace("Z", "+00:00"))
    except ValueError:
        return None


class BlackHatConnector(Connector):
    version = "blackhat-1"

    def __init__(self, ctx=None, data_file: str | None = None) -> None:
        # BlackHat does not go through FetchContext (Cloudflare); ctx is kept
        # for interface compatibility but unused.
        super().__init__(ctx)  # type: ignore[arg-type]
        self.data_file = data_file

    def _resolve_data_file(self, policy: EndpointPolicy) -> Path:
        """The shared-volume JSON written by scripts/blackhat_fetch.py.

        Endpoint options may point at a specific file, e.g.
        options: {blackhat: {data_file: /shared/blackhat-us26.json}}.
        Defaults to <blackhat_data_file setting> or a local path.
        """
        opts = (policy.options or {}).get("blackhat", {})
        configured = opts.get("data_file") or self.data_file
        if configured:
            return Path(configured)
        env_default = "/shared/blackhat/sessions.json"
        return Path(env_default)

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        data_path = self._resolve_data_file(policy)
        if not data_path.exists():
            # The Playwright fetch has not run yet (or is scheduled); report a
            # clean no-op so the endpoint stays healthy instead of failing.
            return PollResult([], checkpoint, not_modified=True)

        payload = json.loads(data_path.read_text(encoding="utf-8"))
        sessions = payload.get("sessions") or {}
        if not isinstance(sessions, dict):
            return PollResult([], checkpoint, not_modified=True)

        fetched_at = datetime.now(UTC)
        items: list[RawItem] = []
        for session_id, rec in sessions.items():
            if not isinstance(rec, dict):
                continue
            program = str(rec.get("program") or "")
            if _BRIEFINGS_PROGRAM not in program:
                continue  # Arsenal / Training / Summit entries excluded
            native_id = str(session_id)
            raw_text = json.dumps(rec, ensure_ascii=False, sort_keys=True)
            item_hash = content_sha256(native_id, raw_text)
            if checkpoint.known_content_hashes.get(native_id) == item_hash:
                continue
            published_at = _parse_iso(rec.get("iso_start_date"))
            items.append(
                RawItem(
                    endpoint_id=policy.id,
                    source_id=policy.source_id,
                    native_id=native_id,
                    request_url=policy.url,
                    final_url=policy.url,
                    http_status=200,
                    published_at=published_at,
                    fetched_at=fetched_at,
                    language="en",
                    content_hash=item_hash,
                    raw_text=raw_text,
                    canonical_url=f"{policy.url.rstrip('/')}/#session-{native_id}",
                    connector_kind=ConnectorKind.PLAYWRIGHT,
                    connector_version=self.version,
                )
            )

        new_ck = Checkpoint(
            etag=checkpoint.etag,
            last_modified=checkpoint.last_modified,
            cursor=checkpoint.cursor,
            last_published_at=checkpoint.last_published_at,
            known_content_hashes={
                **checkpoint.known_content_hashes,
                **{str(item.native_id): item.content_hash for item in items},
            },
            active_native_ids=checkpoint.active_native_ids,
        )
        return PollResult(items, new_ck)
