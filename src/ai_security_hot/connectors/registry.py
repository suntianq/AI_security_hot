"""Connector and Parser registries — map YAML names to implementations."""

from __future__ import annotations

from ai_security_hot.connectors.arxiv import ArxivConnector
from ai_security_hot.connectors.base import Connector, Parser
from ai_security_hot.connectors.fetch import FetchContext
from ai_security_hot.connectors.github import GitHubConnector
from ai_security_hot.connectors.rest import RestApiConnector
from ai_security_hot.connectors.rss import RSSConnector
from ai_security_hot.connectors.sitemap import SitemapConnector
from ai_security_hot.connectors.web import WebListConnector
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.parsers.arxiv import ArxivParser
from ai_security_hot.parsers.cisa_kev import CisaKevParser
from ai_security_hot.parsers.github_releases import GitHubReleasesParser
from ai_security_hot.parsers.nvd import NvdParser
from ai_security_hot.parsers.rss_default import RssDefaultParser
from ai_security_hot.parsers.sitemap_article import SitemapArticleParser
from ai_security_hot.parsers.web_article import WebArticleParser

_CONNECTORS = {
    ConnectorKind.RSS: RSSConnector,
    ConnectorKind.REST: RestApiConnector,
    ConnectorKind.GITHUB: GitHubConnector,
    ConnectorKind.WEB: WebListConnector,
    ConnectorKind.ARXIV: ArxivConnector,
    ConnectorKind.SITEMAP: SitemapConnector,
}

_PARSERS: dict[str, type[Parser]] = {
    "rss-default-v1": RssDefaultParser,
    "cisa-kev-v1": CisaKevParser,
    "nvd-v1": NvdParser,
    "github-releases-v1": GitHubReleasesParser,
    "web-article-v1": WebArticleParser,
    "arxiv-v1": ArxivParser,
    "sitemap-article-v1": SitemapArticleParser,
}


def get_connector(kind: ConnectorKind, ctx: FetchContext) -> Connector:
    return _CONNECTORS[kind](ctx)


def get_parser(name: str) -> Parser:
    return _PARSERS[name]()
