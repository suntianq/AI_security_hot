"""Offline smoke test — connector + parser logic with mocked HTTP (no DB, no net).

Uses respx to serve a canned RSS body so CI verifies the fetch→parse path
deterministically. The live DB path is covered by tests/integration.
"""

from __future__ import annotations

import httpx
import respx

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.connectors.fetch import FetchContext
from ai_security_hot.connectors.rss import RSSConnector
from ai_security_hot.parsers.rss_default import RssDefaultParser

_RSS = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Test Feed</title>
  <item>
    <title>Critical bug in Langflow CVE-2025-99999</title>
    <link>https://example.com/post/1?utm_source=x</link>
    <guid>https://example.com/post/1</guid>
    <description>A serious issue affecting version 1.2.0</description>
    <pubDate>Mon, 21 Jul 2025 10:00:00 GMT</pubDate>
  </item>
</channel></rss>"""


def _policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-rss",
            "source_id": "test",
            "connector": "rss",
            "parser": "rss-default-v1",
            "url": "https://example.com/rss.xml",
            "egress": {"route": "direct"},
        }
    )


@respx.mock
def test_rss_fetch_and_parse() -> None:
    respx.get("https://example.com/rss.xml").mock(
        return_value=httpx.Response(200, text=_RSS, headers={"ETag": "abc123"})
    )

    policy = _policy()
    connector = RSSConnector(FetchContext())
    result = connector.poll(policy, Checkpoint())

    assert len(result.items) == 1
    assert result.checkpoint.etag == "abc123"

    raw = result.items[0]
    assert raw.native_id == "https://example.com/post/1"

    doc = RssDefaultParser().parse(raw)
    assert "Langflow" in doc.title_original
    assert doc.cve_ids == ["CVE-2025-99999"]
    assert "utm_source" not in doc.canonical_url  # canonicalized
    assert doc.parse_quality >= 0.6


@respx.mock
def test_rss_304_not_modified() -> None:
    respx.get("https://example.com/rss.xml").mock(return_value=httpx.Response(304))
    connector = RSSConnector(FetchContext())
    result = connector.poll(_policy(), Checkpoint(etag="abc123"))
    assert result.not_modified is True
    assert result.items == []


_NVD = """{"vulnerabilities":[
  {"cve":{"id":"CVE-2024-12345","published":"2024-05-01T10:00:00.000",
    "descriptions":[{"lang":"en","value":"A serious flaw in ExampleLib allows RCE."}],
    "weaknesses":[{"description":[{"value":"CWE-77"}]}]}}
]}"""


def _rest_policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-nvd",
            "source_id": "nvd",
            "connector": "rest",
            "parser": "nvd-v1",
            "url": "https://example.com/nvd.json",
            "egress": {"route": "direct"},
            "options": {
                "rest": {"list_key": "vulnerabilities", "nested_key": "cve", "id_field": "id"}
            },
        }
    )


@respx.mock
def test_nvd_nested_rest_parse() -> None:
    from ai_security_hot.connectors.rest import RestApiConnector
    from ai_security_hot.parsers.nvd import NvdParser

    respx.get("https://example.com/nvd.json").mock(return_value=httpx.Response(200, text=_NVD))

    policy = _rest_policy()
    result = RestApiConnector(FetchContext()).poll(policy, Checkpoint())
    assert len(result.items) == 1
    assert result.items[0].native_id == "CVE-2024-12345"  # nested id extracted

    doc = NvdParser().parse(result.items[0])
    assert doc.cve_ids == ["CVE-2024-12345"]
    assert doc.cwe_ids == ["CWE-77"]
    assert "nvd.nist.gov" in doc.canonical_url
    assert doc.parse_quality == 1.0


_ARTICLE_HTML = """<!DOCTYPE html><html><head><title>Full Article Title</title>
<meta property="article:published_time" content="2025-07-01"/></head>
<body><article><h1>Full Article Title</h1>
<p>%s</p></article></body></html>""" % ("This is the complete article body. " * 40)


def test_extract_article_static_page() -> None:
    from ai_security_hot.parsers.article import extract_article

    art = extract_article(_ARTICLE_HTML)
    assert art.title == "Full Article Title"
    assert art.body is not None and len(art.body) > 400  # full body extracted


def test_extract_article_empty_on_spa() -> None:
    from ai_security_hot.parsers.article import extract_article

    # a JS-shell page with no static article body → nothing extracted
    spa = "<html><body><div id='root'></div><script>app()</script></body></html>"
    art = extract_article(spa)
    assert art.body is None or len(art.body) < 50


# arXiv official API returns Atom; connector preserves structured fields
_ARXIV_ATOM = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <id>http://arxiv.org/abs/2501.00001v1</id>
    <title>Prompt Injection Attacks on LLM Agents</title>
    <summary>%s</summary>
    <published>2025-01-02T10:00:00Z</published>
    <author><name>Alice Zhang</name></author>
    <author><name>Bob Lee</name></author>
    <link rel="alternate" href="http://arxiv.org/abs/2501.00001v1"/>
    <link title="pdf" type="application/pdf" href="http://arxiv.org/pdf/2501.00001v1"/>
    <category term="cs.CR"/>
    <category term="cs.AI"/>
  </entry>
</feed>""" % ("We study prompt injection against agentic LLM systems. " * 5)


def _arxiv_policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-arxiv",
            "source_id": "arxiv",
            "connector": "arxiv",
            "parser": "arxiv-v1",
            "url": "https://export.arxiv.org/api/query?search_query=cat:cs.CR",
            "egress": {"route": "direct"},
        }
    )


@respx.mock
def test_arxiv_connector_and_parser() -> None:
    from ai_security_hot.connectors.arxiv import ArxivConnector
    from ai_security_hot.parsers.arxiv import ArxivParser

    respx.get(url__startswith="https://export.arxiv.org/api/query").mock(
        return_value=httpx.Response(200, text=_ARXIV_ATOM)
    )
    result = ArxivConnector(FetchContext()).poll(_arxiv_policy(), Checkpoint())
    assert len(result.items) == 1
    assert result.items[0].native_id == "http://arxiv.org/abs/2501.00001v1"

    doc = ArxivParser().parse(result.items[0])
    assert "Prompt Injection" in doc.title_original
    assert doc.entities["authors"] == ["Alice Zhang", "Bob Lee"]
    assert doc.entities["categories"] == ["cs.CR", "cs.AI"]
    assert doc.entities["pdf_url"] == ["http://arxiv.org/pdf/2501.00001v1"]
    assert doc.body_text is not None and len(doc.body_text) > 100  # full abstract
    assert doc.parse_quality == 1.0


# Sitemap connector + parser
_SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/news/claude-4-release</loc>
    <lastmod>2026-07-15</lastmod>
  </url>
  <url>
    <loc>https://example.com/research/alignment-study</loc>
    <lastmod>2026-07-10</lastmod>
  </url>
  <url>
    <loc>https://example.com/careers/engineering</loc>
    <lastmod>2026-07-01</lastmod>
  </url>
</urlset>"""

_ARTICLE_HTML_1 = """<!DOCTYPE html><html><head>
<title>Claude 4 Release</title>
<meta property="article:published_time" content="2026-07-15"/></head>
<body><article><h1>Claude 4 Release</h1>
<p>%s</p></article></body></html>""" % ("Anthropic announces Claude 4 with improved safety. " * 20)

_ARTICLE_HTML_2 = """<!DOCTYPE html><html><head>
<title>Alignment Study</title>
<meta property="article:published_time" content="2026-07-10"/></head>
<body><article><h1>Alignment Study</h1>
<p>%s</p></article></body></html>""" % ("We present a new alignment technique for LLMs. " * 20)


def _sitemap_policy() -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "test-sitemap",
            "source_id": "anthropic",
            "connector": "sitemap",
            "parser": "sitemap-article-v1",
            "url": "https://example.com/sitemap.xml",
            "egress": {"route": "direct"},
            "fetch": {"requests_per_minute": 60},
            "options": {
                "sitemap": {
                    "url_patterns": ["/news/", "/research/"],
                    "strip_query": True,
                    "max_urls": 50,
                }
            },
        }
    )


@respx.mock
def test_sitemap_connector_and_parser() -> None:
    from ai_security_hot.connectors.sitemap import SitemapConnector
    from ai_security_hot.parsers.sitemap_article import SitemapArticleParser

    # mock the sitemap
    respx.get("https://example.com/sitemap.xml").mock(
        return_value=httpx.Response(200, text=_SITEMAP_XML)
    )
    # mock article pages
    respx.get("https://example.com/news/claude-4-release").mock(
        return_value=httpx.Response(200, text=_ARTICLE_HTML_1)
    )
    respx.get("https://example.com/research/alignment-study").mock(
        return_value=httpx.Response(200, text=_ARTICLE_HTML_2)
    )

    result = SitemapConnector(FetchContext()).poll(_sitemap_policy(), Checkpoint())
    # only /news/ and /research/ URLs, not /careers/
    assert len(result.items) == 2

    urls = {item.native_id for item in result.items}
    assert "https://example.com/news/claude-4-release" in urls
    assert "https://example.com/research/alignment-study" in urls
    assert "https://example.com/careers/engineering" not in urls

    # parse first article
    raw = result.items[0]
    doc = SitemapArticleParser().parse(raw)
    assert doc.title_original
    assert doc.body_text is not None and len(doc.body_text) > 80
    assert "example.com" in doc.canonical_url
    assert doc.parse_quality >= 0.6


@respx.mock
def test_rss_filters_unchanged_but_emits_revision() -> None:
    policy = _policy()
    respx.get("https://example.com/rss.xml").mock(
        return_value=httpx.Response(200, text=_RSS)
    )
    first = RSSConnector(FetchContext()).poll(policy, Checkpoint())
    assert len(first.items) == 1
    raw = first.items[0]

    unchanged = RSSConnector(FetchContext()).poll(
        policy, Checkpoint(known_content_hashes={raw.native_id: raw.content_hash})
    )
    assert unchanged.items == []

    revised_feed = _RSS.replace("A serious issue", "An updated serious issue")
    respx.get("https://example.com/rss.xml").mock(
        return_value=httpx.Response(200, text=revised_feed)
    )
    revised = RSSConnector(FetchContext()).poll(
        policy, Checkpoint(known_content_hashes={raw.native_id: raw.content_hash})
    )
    assert len(revised.items) == 1
    assert revised.items[0].native_id == raw.native_id
    assert revised.items[0].content_hash != raw.content_hash


@respx.mock
def test_rest_connector_drains_nvd_pagination() -> None:
    from ai_security_hot.connectors.rest import RestApiConnector

    policy = EndpointPolicy.model_validate(
        {
            "id": "test-nvd-pages",
            "source_id": "nvd",
            "connector": "rest",
            "parser": "nvd-v1",
            "url": "https://example.com/nvd-pages?resultsPerPage=1",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "rest": {
                    "list_key": "vulnerabilities",
                    "nested_key": "cve",
                    "id_field": "id",
                    "pagination": {
                        "start_param": "startIndex",
                        "start_key": "startIndex",
                        "page_size_key": "resultsPerPage",
                        "total_key": "totalResults",
                    },
                }
            },
        }
    )
    page_1 = {
        "startIndex": 0,
        "resultsPerPage": 1,
        "totalResults": 2,
        "vulnerabilities": [{"cve": {"id": "CVE-2026-0001"}}],
    }
    page_2 = {
        "startIndex": 1,
        "resultsPerPage": 1,
        "totalResults": 2,
        "vulnerabilities": [{"cve": {"id": "CVE-2026-0002"}}],
    }
    respx.get("https://example.com/nvd-pages?resultsPerPage=1").mock(
        return_value=httpx.Response(200, json=page_1)
    )
    respx.get(
        "https://example.com/nvd-pages?resultsPerPage=1&startIndex=1"
    ).mock(return_value=httpx.Response(200, json=page_2))

    result = RestApiConnector(FetchContext()).poll(policy, Checkpoint())
    assert [item.native_id for item in result.items] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]


@respx.mock
def test_sitemap_connector_uses_listing_fast_path_without_sitemap() -> None:
    import json
    from datetime import UTC, datetime

    from ai_security_hot.connectors.sitemap import SitemapConnector

    policy = EndpointPolicy.model_validate(
        {
            "id": "test-anthropic-fast",
            "source_id": "anthropic",
            "connector": "sitemap",
            "parser": "sitemap-article-v1",
            "url": "https://example.com/sitemap.xml",
            "fetch": {"requests_per_minute": 0},
            "options": {
                "sitemap": {
                    "listing_url": "https://example.com/news",
                    "listing_max_urls": 20,
                    "reconcile_interval_hours": 24,
                    "overlap_hours": 72,
                    "url_patterns": ["/news/", "/research/"],
                }
            },
        }
    )
    listing = (
        '<html><body><a href="/news/new-release">New</a>'
        '<a href="/careers/job">Ignore</a></body></html>'
    )
    respx.get("https://example.com/news").mock(
        return_value=httpx.Response(200, text=listing)
    )
    respx.get("https://example.com/news/new-release").mock(
        return_value=httpx.Response(200, text=_ARTICLE_HTML_1)
    )
    now = datetime.now(UTC)
    checkpoint = Checkpoint(
        cursor=json.dumps({"sitemap_reconciled_at": now.isoformat()}),
        last_published_at=now,
    )

    result = SitemapConnector(FetchContext()).poll(policy, checkpoint)
    assert len(result.items) == 1
    assert result.items[0].native_id == "https://example.com/news/new-release"
