"""Fetch Black Hat sessions.json through Cloudflare using Playwright.

Black Hat schedule pages sit behind a Cloudflare JS challenge; a plain HTTP
client gets a 403. This script drives a headless Chromium (via Playwright)
through the challenge, then fetches the same-directory ``sessions.json`` and
writes it to a shared volume that the main worker's BlackHatConnector reads.

Usage (runs inside the playwright container):

    uv run python scripts/blackhat_fetch.py \
        --url https://blackhat.com/us-26/briefings/schedule/ \
        --out /shared/blackhat/sessions.json

Exit code 0 on success; non-zero on failure (including challenge timeout).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path


def _fetch_sessions(url: str, timeout_seconds: int = 90) -> dict:
    """Open the schedule page in headless Chromium, wait out Cloudflare, fetch JSON."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
            ),
            locale="en-US",
        )
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)

        # Cloudflare challenge: poll until the page title no longer mentions it.
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                title = page.title()
            except Exception:
                title = ""
            if "Attention Required" not in title and "Just a moment" not in title:
                break
            page.wait_for_timeout(1500)

        # Resolve the same-directory sessions.json relative to the page URL.
        base = url.rstrip("/")
        if "/schedule/" in url and not url.rstrip("/").endswith("/schedule"):
            base = url.rstrip("/")
        json_url = f"{base}/sessions.json"
        result = page.evaluate(
            """async (u) => {
                const r = await fetch(u);
                if (!r.ok) return { ok: false, status: r.status };
                return { ok: true, data: await r.json() };
            }""",
            json_url,
        )
        browser.close()

    if not result.get("ok"):
        raise RuntimeError(f"failed to fetch {json_url}: HTTP {result.get('status')}")
    data = result["data"]
    if not isinstance(data, dict) or "sessions" not in data:
        raise RuntimeError(f"{json_url} did not contain a sessions object")
    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch Black Hat sessions.json via Playwright")
    parser.add_argument(
        "--url",
        required=True,
        help="schedule page URL, e.g. https://blackhat.com/us-26/briefings/schedule/",
    )
    parser.add_argument(
        "--out",
        default="/shared/blackhat/sessions.json",
        help="output path (shared volume)",
    )
    parser.add_argument("--timeout", type=int, default=90, help="challenge timeout in seconds")
    args = parser.parse_args()

    try:
        data = _fetch_sessions(args.url, timeout_seconds=args.timeout)
    except Exception as exc:  # surface any fetch failure as non-zero exit
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    session_count = len(data.get("sessions") or {})
    print(f"wrote {out} — {session_count} sessions")


if __name__ == "__main__":
    main()
