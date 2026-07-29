"""BlobStore — abstraction over large raw snapshots (plan 修正 5).

M0 implementation writes to a local volume; DB stores only content_hash +
blob_ref. Swapping to S3/MinIO later means a new implementation, no schema
change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ai_security_hot.config.settings import get_settings
from ai_security_hot.domain.models import content_sha256


class BlobStore(ABC):
    @abstractmethod
    def put(self, data: bytes) -> str:
        """Store bytes, return a content-addressed reference."""

    @abstractmethod
    def get(self, ref: str) -> bytes: ...

    @abstractmethod
    def exists(self, ref: str) -> bool: ...


class LocalBlobStore(BlobStore):
    """Content-addressed store on a local directory (sharded by hash prefix)."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root or get_settings().blob_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, ref: str) -> Path:
        # ref == sha256 hex; shard into aa/bb/<hash> to avoid huge dirs
        return self.root / ref[:2] / ref[2:4] / ref

    def put(self, data: bytes) -> str:
        ref = content_sha256(data)
        path = self._path(ref)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return ref

    def get(self, ref: str) -> bytes:
        return self._path(ref).read_bytes()

    def exists(self, ref: str) -> bool:
        return self._path(ref).exists()


def get_blob_store() -> BlobStore:
    return LocalBlobStore()
