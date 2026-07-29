"""FetchContext — the single controlled HTTP egress layer (plan 修正 2/3).

Every connector calls ``ctx.get(...)`` or ``await ctx.aget(...)`` instead of
using httpx directly, so SSRF, proxy selection, rate limiting, retry, timeout,
size cap and ETag/Last-Modified handling are implemented once. Adding a new
connector kind never re-implements this.

The synchronous ``get()`` is kept for backwards-compatible connectors; the
async ``aget()`` is used by async connectors (e.g. SitemapConnector) for
concurrent HTTP requests.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from ai_security_hot.config.settings import get_settings
from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.ssrf import validate_resolved, validate_url
from ai_security_hot.domain.enums import EgressRoute
from ai_security_hot.domain.models import FetchResult

_RETRYABLE = (httpx.TransportError, httpx.HTTPStatusError)


class ResponseTooLarge(Exception):
    pass


@dataclass
class _RateLimiter:
    """Simple per-endpoint token bucket keyed by requests_per_minute."""

    _last_call: dict[str, float] = field(default_factory=dict)

    def wait(self, endpoint_id: str, rpm: float) -> None:
        if rpm <= 0:
            return
        min_interval = 60.0 / rpm
        last = self._last_call.get(endpoint_id, 0.0)
        elapsed = time.monotonic() - last
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_call[endpoint_id] = time.monotonic()

    async def await_(self, endpoint_id: str, rpm: float) -> None:
        if rpm <= 0:
            return
        min_interval = 60.0 / rpm
        last = self._last_call.get(endpoint_id, 0.0)
        elapsed = time.monotonic() - last
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        self._last_call[endpoint_id] = time.monotonic()


class FetchContext:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._rate = _RateLimiter()

    def _proxy_for(self, route: EgressRoute) -> str | None:
        """Resolve the proxy URL for a route. Falls back to direct if the pool
        is not configured (so a dev box with no proxy still works)."""
        if route is EgressRoute.PROXY_POOL_CN:
            return self.settings.proxy_pool_cn
        if route is EgressRoute.PROXY_POOL_GLOBAL:
            return self.settings.proxy_pool_global
        return None

    @staticmethod
    def _build_headers(
        *,
        user_agent: str,
        etag: str | None,
        last_modified: str | None,
        extra_headers: dict[str, str] | None,
    ) -> dict[str, str]:
        headers = {"User-Agent": user_agent}
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def get(
        self,
        url: str,
        policy: EndpointPolicy,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> FetchResult:
        """Perform one synchronous controlled GET. Returns FetchResult; 304 => from_cache."""
        validate_url(url)
        proxy = self._proxy_for(policy.egress.route)
        self._rate.wait(policy.id, policy.fetch.requests_per_minute)
        headers = self._build_headers(
            user_agent=self.settings.fetch_user_agent,
            etag=etag,
            last_modified=last_modified,
            extra_headers=extra_headers,
        )

        @retry(
            retry=retry_if_exception_type(_RETRYABLE),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            reraise=True,
        )
        def _do() -> FetchResult:
            with httpx.Client(
                timeout=policy.fetch.timeout_seconds,
                follow_redirects=True,
                max_redirects=policy.fetch.max_redirects,
                proxy=proxy,
                headers=headers,
            ) as client:
                req = client.build_request("GET", url)
                if not proxy:
                    validate_resolved(req.url.host)

                with client.stream("GET", url) as resp:
                    if resp.status_code == 304:
                        return FetchResult(
                            url=url,
                            final_url=str(resp.url),
                            status_code=304,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            body=b"",
                            fetched_at=datetime.now(UTC),
                            egress_route=policy.egress.route,
                            from_cache=True,
                        )
                    cap = policy.fetch.max_response_bytes
                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > cap:
                            raise ResponseTooLarge(f"{url} exceeded {cap} bytes")
                        chunks.append(chunk)
                    resp.raise_for_status()
                    return FetchResult(
                        url=url,
                        final_url=str(resp.url),
                        status_code=resp.status_code,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        body=b"".join(chunks),
                        fetched_at=datetime.now(UTC),
                        egress_route=policy.egress.route,
                    )

        return _do()

    async def aget(
        self,
        url: str,
        policy: EndpointPolicy,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> FetchResult:
        """Async version of ``get()`` — same SSRF/rate-limit/retry/size-cap logic,
        but uses ``httpx.AsyncClient`` for concurrent I/O."""
        validate_url(url)
        proxy = self._proxy_for(policy.egress.route)
        await self._rate.await_(policy.id, policy.fetch.requests_per_minute)
        headers = self._build_headers(
            user_agent=self.settings.fetch_user_agent,
            etag=etag,
            last_modified=last_modified,
            extra_headers=extra_headers,
        )

        @retry(
            retry=retry_if_exception_type(_RETRYABLE),
            stop=stop_after_attempt(3),
            wait=wait_exponential(multiplier=1, min=1, max=10),
            reraise=True,
        )
        async def _do() -> FetchResult:
            async with httpx.AsyncClient(
                timeout=policy.fetch.timeout_seconds,
                follow_redirects=True,
                max_redirects=policy.fetch.max_redirects,
                proxy=proxy,
                headers=headers,
            ) as client:
                if not proxy:
                    validate_resolved(httpx.URL(url).host)
                resp = await client.get(url)
                if resp.status_code == 304:
                    return FetchResult(
                        url=url,
                        final_url=str(resp.url),
                        status_code=304,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        body=b"",
                        fetched_at=datetime.now(UTC),
                        egress_route=policy.egress.route,
                        from_cache=True,
                    )
                if len(resp.content) > policy.fetch.max_response_bytes:
                    raise ResponseTooLarge(
                        f"{url} exceeded {policy.fetch.max_response_bytes} bytes"
                    )
                resp.raise_for_status()
                return FetchResult(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=resp.content,
                    fetched_at=datetime.now(UTC),
                    egress_route=policy.egress.route,
                )

        return await _do()
