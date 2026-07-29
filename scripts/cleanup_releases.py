"""One-off cleanup: delete raw_items + documents for the 4 removed GitHub
release endpoints (langchain/dify/ollama/vllm-releases), then disable those
endpoints in the DB.

Usage::

    uv run python scripts/cleanup_releases.py

Safe to run multiple times — idempotent.
"""

from __future__ import annotations

from ai_security_hot.models.base import session_scope
from ai_security_hot.models.tables import Document, RawItem, SourceEndpoint

DEAD_ENDPOINTS = [
    "langchain-releases",
    "dify-releases",
    "ollama-releases",
    "vllm-releases",
]


def main() -> None:
    with session_scope() as session:
        # count before
        for ep_id in DEAD_ENDPOINTS:
            raw_count = session.query(RawItem).filter(
                RawItem.endpoint_id == ep_id
            ).count()
            doc_count = (
                session.query(Document)
                .join(RawItem, RawItem.id == Document.raw_item_id)
                .filter(RawItem.endpoint_id == ep_id)
                .count()
            )
            print(f"  {ep_id}: {raw_count} raw_items, {doc_count} documents")

        # delete documents (via raw_item join)
        for ep_id in DEAD_ENDPOINTS:
            raw_ids = [
                r.id
                for r in session.query(RawItem)
                .filter(RawItem.endpoint_id == ep_id)
                .all()
            ]
            if raw_ids:
                deleted_docs = (
                    session.query(Document)
                    .filter(Document.raw_item_id.in_(raw_ids))
                    .delete(synchronize_session=False)
                )
                print(f"  deleted {deleted_docs} documents for {ep_id}")
                deleted_raws = (
                    session.query(RawItem)
                    .filter(RawItem.endpoint_id == ep_id)
                    .delete(synchronize_session=False)
                )
                print(f"  deleted {deleted_raws} raw_items for {ep_id}")

        # disable the endpoint rows so they won't be claimed even if they linger
        for ep_id in DEAD_ENDPOINTS:
            row = session.get(SourceEndpoint, ep_id)
            if row is not None:
                row.enabled = False
                print(f"  disabled endpoint {ep_id}")

        session.commit()
    print("done")


if __name__ == "__main__":
    main()
