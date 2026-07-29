"""Connector and Parser base interfaces (MVP 5.2).

Transport (Connector) and mapping (Parser) are separated: a Connector fetches
via FetchContext and yields RawItems; a Parser maps a RawItem into a
NormalizedDocument with a parse_quality score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.fetch import FetchContext
from ai_security_hot.domain.models import NormalizedDocument, RawItem


class Checkpoint:
    """Mutable checkpoint carried across polls (MVP 6.1).

    ``last_success_at`` is loaded from the endpoint's DB row and passed to
    connectors so they can skip already-fetched items (incremental mode).
    """

    def __init__(
        self,
        etag: str | None = None,
        last_modified: str | None = None,
        cursor: str | None = None,
        last_success_at: datetime | None = None,
    ) -> None:
        self.etag = etag
        self.last_modified = last_modified
        self.cursor = cursor
        self.last_success_at = last_success_at


class PollResult:
    def __init__(self, items: list[RawItem], checkpoint: Checkpoint, not_modified: bool = False):
        self.items = items
        self.checkpoint = checkpoint
        self.not_modified = not_modified


class Connector(ABC):
    version: str = "0"

    def __init__(self, ctx: FetchContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        """Fetch since checkpoint, return raw items + advanced checkpoint."""


class Parser(ABC):
    version: str = "0"

    @abstractmethod
    def parse(self, raw: RawItem) -> NormalizedDocument:
        """Map a raw item into a normalized document with parse_quality."""
