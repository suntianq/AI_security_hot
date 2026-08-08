"""Unit tests for the browser-based full-text fetch pattern."""

from __future__ import annotations

import sys
import types


class _FakePage:
    def goto(self, url: str, **kwargs) -> None:
        pass

    def content(self) -> str:
        return (
            "<html><head><title>Test</title></head><body>"
            "<article><h1>Title</h1><p>First paragraph of the article body.</p>"
            "<p>Second paragraph.</p></article></body></html>"
        )

    def close(self) -> None:
        pass


class _FakeBrowser:
    def new_page(self, **kwargs) -> _FakePage:
        return _FakePage()

    def close(self) -> None:
        pass


class _FakeChromium:
    def launch(self, **kwargs) -> _FakeBrowser:
        return _FakeBrowser()


class _FakePlaywright:
    def __init__(self) -> None:
        self.chromium = _FakeChromium()

    def __enter__(self) -> _FakePlaywright:
        return self

    def __exit__(self, *args) -> bool:
        return False


def _install_fake_playwright(monkeypatch) -> None:
    playwright = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    setattr(sync_api, "sync_playwright", lambda: _FakePlaywright())
    monkeypatch.setitem(sys.modules, "playwright", playwright)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)


def test_browser_fetcher_extracts_body(monkeypatch) -> None:
    _install_fake_playwright(monkeypatch)
    from ai_security_hot.connectors.browser import BrowserBodyFetcher

    fetcher = BrowserBodyFetcher(wait_seconds=0)
    result = fetcher.fetch(["https://example.com/a", "https://example.com/b"])
    assert "First paragraph of the article body" in result["https://example.com/a"]
    assert "Second paragraph" in result["https://example.com/a"]
    assert len(result) == 2


def test_registry_browser_fetch_flag() -> None:
    from ai_security_hot.config.sources import load_registry

    registry = load_registry()
    oai = registry.endpoint("openai-news-rss")
    assert oai.fulltext is True
    assert oai.browser_fetch is True
    # blackhat is gone — the flag only applies to explicitly marked endpoints
    assert not any(e.browser_fetch for e in registry.endpoints if e.id != "openai-news-rss")
