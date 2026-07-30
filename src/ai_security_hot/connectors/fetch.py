"""The single controlled HTTP egress layer.

Sync and async callers share SSRF validation, proxy selection, strict request
start-rate limiting, retries, timeouts and streaming response-size caps. Async
requests reuse pooled clients for the lifetime of one pipeline pass.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt

from ai_security_hot.config.settings import get_settings
from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.ssrf import validate_resolved, validate_url
from ai_security_hot.domain.enums import EgressRoute
from ai_security_hot.domain.models import FetchResult


def _is_retryable(exc: BaseException) -> bool:
    """Retry transient failures only; deterministic 4xx (notably 409) return once."""
    if isinstance(exc, httpx.TransportError):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        return status in {408, 425, 429} or status >= 500
    return False


def _retry_wait(retry_state) -> float:
    """Honor Retry-After, otherwise use bounded exponential backoff."""
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    if isinstance(exc, httpx.HTTPStatusError):
        value = exc.response.headers.get("Retry-After")
        if value and value.isdigit():
            return float(min(60, max(1, int(value))))
        if value:
            try:
                retry_at = parsedate_to_datetime(value)
                retry_at = (
                    retry_at.astimezone(UTC)
                    if retry_at.tzinfo
                    else retry_at.replace(tzinfo=UTC)
                )
                delay = (retry_at - datetime.now(UTC)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                pass
            else:
                if delay > 0:
                    return float(min(60, max(1, delay)))
    return float(min(10, 2 ** max(0, retry_state.attempt_number - 1)))


class ResponseTooLarge(Exception):
    pass


@dataclass
class _RateLimiter:
    """Reserve request start times per endpoint, safely across threads/tasks."""

    _next_call: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def _reserve(self, endpoint_id: str, rpm: float) -> float:
        if rpm <= 0:
            return 0.0
        interval = 60.0 / rpm
        now = time.monotonic()
        with self._lock:
            target = max(now, self._next_call.get(endpoint_id, now))
            self._next_call[endpoint_id] = target + interval
        return max(0.0, target - now)

    def wait(self, endpoint_id: str, rpm: float) -> None:
        delay = self._reserve(endpoint_id, rpm)
        if delay:
            time.sleep(delay)

    async def await_(self, endpoint_id: str, rpm: float) -> None:
        delay = self._reserve(endpoint_id, rpm)
        if delay:
            await asyncio.sleep(delay)


class FetchContext:
    def __init__(self) -> None:
        self.settings = get_settings()
        self._rate = _RateLimiter()
        self._client_lock = threading.Lock()
        self._sync_clients: dict[tuple[str | None, int], httpx.Client] = {}
        self._async_clients: dict[tuple[str | None, int], httpx.AsyncClient] = {}

    def _proxy_for(self, route: EgressRoute) -> str | None:
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

    def _sync_client(self, policy: EndpointPolicy, proxy: str | None) -> httpx.Client:
        key = (proxy, policy.fetch.max_redirects)
        with self._client_lock:
            client = self._sync_clients.get(key)
            if client is None:
                client = httpx.Client(
                    follow_redirects=True,
                    max_redirects=policy.fetch.max_redirects,
                    proxy=proxy,
                    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
                )
                self._sync_clients[key] = client
            return client

    def _async_client(self, policy: EndpointPolicy, proxy: str | None) -> httpx.AsyncClient:
        key = (proxy, policy.fetch.max_redirects)
        client = self._async_clients.get(key)
        if client is None:
            client = httpx.AsyncClient(
                follow_redirects=True,
                max_redirects=policy.fetch.max_redirects,
                proxy=proxy,
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
            self._async_clients[key] = client
        return client

    def close(self) -> None:
        with self._client_lock:
            clients = list(self._sync_clients.values())
            self._sync_clients.clear()
        for client in clients:
            client.close()

    async def aclose(self) -> None:
        self.close()
        clients = list(self._async_clients.values())
        self._async_clients.clear()
        if clients:
            await asyncio.gather(*(client.aclose() for client in clients))

    def get(
        self,
        url: str,
        policy: EndpointPolicy,
        *,
        etag: str | None = None,
        last_modified: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> FetchResult:
        """Perform one synchronous controlled GET. A 304 is marked from_cache."""
        validate_url(url)
        proxy = self._proxy_for(policy.egress.route)
        headers = self._build_headers(
            user_agent=self.settings.fetch_user_agent,
            etag=etag,
            last_modified=last_modified,
            extra_headers=extra_headers,
        )

        @retry(
            retry=retry_if_exception(_is_retryable),
            stop=stop_after_attempt(3),
            wait=_retry_wait,
            reraise=True,
        )
        def _do() -> FetchResult:
            self._rate.wait(policy.id, policy.fetch.requests_per_minute)
            client = self._sync_client(policy, proxy)
            req = client.build_request("GET", url, headers=headers)
            if not proxy:
                validate_resolved(req.url.host)

            with client.stream(
                "GET", url, headers=headers, timeout=policy.fetch.timeout_seconds
            ) as resp:
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
                resp.raise_for_status()
                cap = policy.fetch.max_response_bytes
                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_bytes():
                    total += len(chunk)
                    if total > cap:
                        raise ResponseTooLarge(f"{url} exceeded {cap} bytes")
                    chunks.append(chunk)
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
        """Async controlled GET using a reusable connection-pooled client."""
        validate_url(url)
        proxy = self._proxy_for(policy.egress.route)
        headers = self._build_headers(
            user_agent=self.settings.fetch_user_agent,
            etag=etag,
            last_modified=last_modified,
            extra_headers=extra_headers,
        )

        @retry(
            retry=retry_if_exception(_is_retryable),
            stop=stop_after_attempt(3),
            wait=_retry_wait,
            reraise=True,
        )
        async def _do() -> FetchResult:
            await self._rate.await_(policy.id, policy.fetch.requests_per_minute)
            client = self._async_client(policy, proxy)
            if not proxy:
                validate_resolved(httpx.URL(url).host)
            async with client.stream(
                "GET",
                url,
                headers=headers,
                timeout=policy.fetch.timeout_seconds,
            ) as resp:
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
                resp.raise_for_status()
                cap = policy.fetch.max_response_bytes
                chunks: list[bytes] = []
                total = 0
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > cap:
                        raise ResponseTooLarge(f"{url} exceeded {cap} bytes")
                    chunks.append(chunk)
                return FetchResult(
                    url=url,
                    final_url=str(resp.url),
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    body=b"".join(chunks),
                    fetched_at=datetime.now(UTC),
                    egress_route=policy.egress.route,
                )

        return await _do()
