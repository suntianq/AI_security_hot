"""Web list connector — static HTML adapter (MVP 5.2).

Fetches the page HTML and stores the full snapshot in the BlobStore (plan
修正 5), keeping the DB row small. The web parser (trafilatura) extracts the
article body downstream. HTML is treated as untrusted input — no JS is
executed (MVP 15.1/15.2).
"""

from __future__ import annotations

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.domain.models import RawItem, content_sha256
from ai_security_hot.storage.blob import get_blob_store


class WebListConnector(Connector):
    version = "web-1"

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        res = self.ctx.get(
            policy.url,
            policy,
            etag=checkpoint.etag,
            last_modified=checkpoint.last_modified,
        )
        if res.from_cache:
            return PollResult([], checkpoint, not_modified=True)

        content_hash = content_sha256(res.body)
        # dedup against last snapshot via content hash on the checkpoint cursor
        if checkpoint.cursor == content_hash:
            return PollResult([], checkpoint, not_modified=True)

        blob_ref = get_blob_store().put(res.body)
        item = RawItem(
            endpoint_id=policy.id,
            source_id=policy.source_id,
            native_id=res.final_url,  # page URL is the native id for a web snapshot
            request_url=policy.url,
            final_url=res.final_url,
            http_status=res.status_code,
            published_at=None,
            fetched_at=res.fetched_at,
            language=policy.language,
            content_hash=content_hash,
            blob_ref=blob_ref,
            raw_text=None,  # body lives in the blob, not the DB row
            canonical_url=res.final_url,
            connector_kind=ConnectorKind.WEB,
            connector_version=self.version,
        )
        new_ck = Checkpoint(
            etag=res.etag or checkpoint.etag,
            last_modified=res.last_modified or checkpoint.last_modified,
            cursor=content_hash,
        )
        return PollResult([item], new_ck)
