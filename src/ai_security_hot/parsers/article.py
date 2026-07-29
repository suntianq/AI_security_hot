"""Shared trafilatura article extraction — used by the web-article parser and
the fulltext second-fetch stage so both extract identically."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

import trafilatura
from dateutil import parser as dateparser


@dataclass
class ArticleExtract:
    title: str | None = None
    body: str | None = None
    published: datetime | None = None


def extract_article(html: str) -> ArticleExtract:
    """Extract title/body/date from an HTML page. Empty result if none found
    (e.g. JS-rendered SPA pages have no static article body)."""
    if not html:
        return ArticleExtract()

    extracted = trafilatura.extract(
        html,
        output_format="json",
        with_metadata=True,
        favor_precision=True,
    )
    if not extracted:
        return ArticleExtract()

    meta = json.loads(extracted)
    published = None
    date_str = meta.get("date")
    if date_str:
        try:
            published = dateparser.parse(date_str)
        except (ValueError, OverflowError):
            published = None
    return ArticleExtract(title=meta.get("title"), body=meta.get("text"), published=published)
