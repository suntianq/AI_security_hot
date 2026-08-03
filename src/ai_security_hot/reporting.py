"""Helpers for generating self-contained offline reports safely."""

from __future__ import annotations

import json
from typing import Any


def json_for_html_script(value: Any) -> str:
    """Serialize JSON without allowing data to terminate a script element."""
    return json.dumps(value, ensure_ascii=False).translate(
        {
            ord("<"): r"\u003c",
            ord(">"): r"\u003e",
            ord("&"): r"\u0026",
            ord("\u2028"): r"\u2028",
            ord("\u2029"): r"\u2029",
        }
    )
