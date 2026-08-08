"""Headless-browser full-text fetch for sources that block plain HTTP clients.

Some sites (e.g. openai.com) return 403 to any non-browser client, so the
static fulltext fetch cannot get the article body. This module drives a real
Chromium via Playwright to render the page and extracts the article text.

It runs in the dedicated browser container (the main worker image has no
browser): the fulltext stage leaves ``browser_fetch`` endpoints' documents in
the NORMALIZED stage and ``intel browser-fetch`` claims and enriches them.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable

from ai_security_hot.parsers.article import extract_article

log = logging.getLogger("intel.browser")

_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)


class BrowserBodyFetcher:
    """Fetch full article bodies for a batch of URLs using headless Chromium.

    Reusable across any source whose page requires real browser rendering or
    passes a JS/bot challenge that a plain HTTP client cannot satisfy.
    """

    def __init__(self, *, wait_seconds: float = 6.0, timeout_ms: int = 60000) -> None:
        self.wait_seconds = wait_seconds
        self.timeout_ms = timeout_ms

    def fetch(self, urls: Iterable[str]) -> dict[str, str]:
        """Return ``{url: extracted_body}`` for pages Playwright could render.

        A single bad page never aborts the batch; failures are simply omitted.
        """
        from playwright.sync_api import sync_playwright

        results: dict[str, str] = {}
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                for url in urls:
                    if not url:
                        continue
                    try:
                        body = self._fetch_one(browser, url)
                        if body:
                            results[url] = body
                    except Exception as exc:
                        log.warning("browser fetch failed for %s: %s", url, exc)
            finally:
                browser.close()
        return results

    def _fetch_one(self, browser, url: str) -> str:
        page = browser.new_page(user_agent=_BROWSER_UA)
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            time.sleep(self.wait_seconds)  # let the WAF/JS settle
            html = page.content()
            art = extract_article(html)
            return art.body or ""
        finally:
            page.close()
