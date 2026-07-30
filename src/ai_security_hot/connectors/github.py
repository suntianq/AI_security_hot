"""GitHub connector — releases via REST API (MVP 5.2 / source-registry §8).

Uses the GitHub JSON API. Honors an optional token from env (GITHUB_TOKEN)
for higher rate limits — added as an Authorization header via FetchContext.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256


class GitHubConnector(Connector):
    version = "github-2"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        res = self.ctx.get(
            policy.url,
            policy,
            etag=checkpoint.etag,
            last_modified=checkpoint.last_modified,
            extra_headers=self._headers(),
        )
        if res.from_cache:
            return PollResult([], checkpoint, not_modified=True)

        releases = json.loads(res.body)
        items: list[RawItem] = []
        for rel in releases:
            native_id = str(rel.get("id") or rel.get("tag_name") or "")
            if not native_id:
                continue
            published = rel.get("published_at") or rel.get("created_at")
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00")) if published else None
            title = rel.get("name") or rel.get("tag_name") or ""
            body = rel.get("body") or ""
            item_hash = content_sha256(native_id, title, body)
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
                    published_at=pub_dt,
                    fetched_at=res.fetched_at,
                    language=policy.language,
                    content_hash=item_hash,
                    raw_text=f"{title}\n\n{body}",
                    canonical_url=rel.get("html_url", policy.url),
                    connector_kind=ConnectorKind.GITHUB,
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
