"""NVD modified-time connector with durable, bounded catch-up windows."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dateutil.parser import isoparse

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint, Connector, PollResult
from ai_security_hot.connectors.rest import RestApiConnector, _set_query_params
from ai_security_hot.domain.enums import ConnectorKind

_CURSOR_PREFIX = "nvd-window-v1:"
_STEADY_CURSOR = "nvd-steady-v1"


def _cve_year(native_id: str) -> int | None:
    """Parse the year from a CVE id like 'CVE-2026-12345'. None if unparseable."""
    parts = native_id.split("-")
    if len(parts) >= 2 and parts[0].upper() == "CVE" and parts[1].isdigit():
        return int(parts[1])
    return None


def _format_nvd_time(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _replace_query_param(url: str, name: str, value: str | int) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[name] = str(value)
    return urlunparse(parsed._replace(query=urlencode(query)))


class NvdConnector(Connector):
    """Drain NVD changes in durable windows instead of one unbounded poll.

    The same cursor handles initial 120-day bootstrap and catch-up after a long
    outage. A preflight count shrinks unusually dense windows before downloading
    pages, bounding memory, retry scope, and transaction size.
    """

    version = "nvd-modified-v1"

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    def poll(self, policy: EndpointPolicy, checkpoint: Checkpoint) -> PollResult:
        opts = (policy.options or {}).get("nvd", {})
        bootstrap_days = int(opts.get("bootstrap_days", 120))
        segment_days = float(opts.get("segment_days", 7))
        overlap_minutes = int(opts.get("overlap_minutes", 15))
        target_results = int(opts.get("target_results", 20000))
        minimum_window_minutes = int(opts.get("minimum_window_minutes", 60))
        catchup_interval = int(opts.get("catchup_interval_minutes", 1))
        # Drop CVEs whose id-year is before this (e.g. 2026): NVD's lastMod
        # window still surfaces old CVEs revised recently, so filter by id-year.
        min_cve_year = opts.get("min_cve_year")
        min_cve_year = int(min_cve_year) if min_cve_year is not None else None
        now = self._now()

        if checkpoint.cursor and checkpoint.cursor.startswith(_CURSOR_PREFIX):
            window_start = isoparse(checkpoint.cursor.removeprefix(_CURSOR_PREFIX))
            window_start = (
                window_start.astimezone(UTC)
                if window_start.tzinfo
                else window_start.replace(tzinfo=UTC)
            )
        elif checkpoint.last_success_at is None:
            window_start = now - timedelta(days=bootstrap_days)
        else:
            window_start = checkpoint.last_success_at - timedelta(minutes=overlap_minutes)

        candidate_end = min(window_start + timedelta(days=segment_days), now)
        window_end, total = self._bounded_window(
            policy,
            window_start,
            candidate_end,
            target_results=target_results,
            minimum_window=timedelta(minutes=minimum_window_minutes),
        )
        has_more = window_end < now
        next_cursor = (
            f"{_CURSOR_PREFIX}{window_end.isoformat()}" if has_more else _STEADY_CURSOR
        )
        next_poll = catchup_interval if has_more else None

        if total == 0:
            return PollResult(
                [],
                Checkpoint(cursor=next_cursor),
                next_poll_minutes=next_poll,
            )

        window_url = self._window_url(policy.url, window_start, window_end)
        rest_options = dict(policy.options or {})
        rest_config = dict(rest_options.get("rest") or {})
        rest_config.pop("date_params", None)
        rest_options["rest"] = rest_config
        window_policy = policy.model_copy(
            update={"url": window_url, "options": rest_options}
        )
        inner_checkpoint = Checkpoint(
            known_content_hashes=checkpoint.known_content_hashes,
            active_native_ids=checkpoint.active_native_ids,
        )
        result = RestApiConnector(self.ctx).poll(window_policy, inner_checkpoint)
        items = result.items
        if min_cve_year is not None:
            items = [
                it for it in items
                if (_cve_year(it.native_id) or 0) >= min_cve_year
            ]
        for item in items:
            item.connector_kind = ConnectorKind.NVD
            item.connector_version = self.version
            item.canonical_url = f"https://nvd.nist.gov/vuln/detail/{item.native_id}"
        return PollResult(
            items,
            Checkpoint(cursor=next_cursor),
            next_poll_minutes=next_poll,
        )

    def _bounded_window(
        self,
        policy: EndpointPolicy,
        start: datetime,
        end: datetime,
        *,
        target_results: int,
        minimum_window: timedelta,
    ) -> tuple[datetime, int]:
        total = self._count(policy, start, end)
        while total > target_results and end - start > minimum_window:
            span = max(minimum_window, (end - start) / 2)
            end = min(start + span, end)
            total = self._count(policy, start, end)
        return end, total

    def _count(self, policy: EndpointPolicy, start: datetime, end: datetime) -> int:
        url = self._window_url(policy.url, start, end)
        url = _replace_query_param(url, "resultsPerPage", 1)
        response = self.ctx.get(url, policy)
        payload = json.loads(response.body)
        total = payload.get("totalResults")
        if not isinstance(total, int) or total < 0:
            raise ValueError("NVD preflight did not return a valid totalResults")
        return total

    @staticmethod
    def _window_url(url: str, start: datetime, end: datetime) -> str:
        return _set_query_params(
            url,
            {
                "lastModStartDate": _format_nvd_time(start),
                "lastModEndDate": _format_nvd_time(end),
            },
        )
