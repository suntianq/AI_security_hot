from __future__ import annotations

import json

from ai_security_hot.reporting import json_for_html_script


def test_json_for_html_script_blocks_script_termination() -> None:
    original = {"title": "</script><img src=x onerror=alert(1)>", "separator": "\u2028"}
    payload = json_for_html_script(original)

    assert "</script>" not in payload
    assert "<img" not in payload
    assert r"\u003c/script\u003e" in payload
    assert r"\u2028" in payload
    assert json.loads(payload) == original
