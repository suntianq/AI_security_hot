"""Schema + loader for ``config/cve_follow.yaml``.

Determines which CVEs get surfaced: a CVE is kept when its CVSS base score is
at least ``cvss_min`` AND one of its affected products / vendors / title /
description hits a ``follow`` keyword. An empty ``follow`` list disables the
filter (all CVEs shown) — a safe default if the file is missing or unedited.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, field_validator

from ai_security_hot.config.settings import get_settings


class CveFollowConfig(BaseModel):
    cvss_min: float = Field(default=7.0, ge=0.0, le=10.0)
    follow: list[str] = Field(default_factory=list)

    @field_validator("follow")
    @classmethod
    def _normalize_keywords(cls, v: list[object]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for raw in v:
            kw = str(raw).strip().lower()
            if kw and kw not in seen:
                seen.add(kw)
                out.append(kw)
        return out


def load_cve_follow_config(path: str | Path) -> CveFollowConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except OSError:
        return CveFollowConfig()
    if not isinstance(raw, dict):
        return CveFollowConfig()
    try:
        return CveFollowConfig.model_validate(raw)
    except ValueError:
        return CveFollowConfig()


@lru_cache(maxsize=1)
def get_cve_follow_config() -> CveFollowConfig:
    return load_cve_follow_config(get_settings().cve_follow_config_file)


def is_followed_cve(entities: dict, title: str, body: str) -> bool:
    """True when a CVE document should be surfaced under the follow policy.

    No follow list configured → keep everything (backward compatible).
    Otherwise require BOTH a CVSS score at/above ``cvss_min`` AND a follow
    keyword hit on products/vendors/title/description.
    """
    config = get_cve_follow_config()
    if not config.follow:
        return True
    cvss_raw = (entities or {}).get("cvss")
    try:
        cvss = float(cvss_raw[0]) if cvss_raw else 0.0
    except (TypeError, ValueError, IndexError):
        cvss = 0.0
    if cvss < config.cvss_min:
        return False
    products = (entities or {}).get("products", [])
    vendors = (entities or {}).get("vendors", [])
    haystack = " ".join(
        [title, body, *(str(p) for p in products), *(str(v) for v in vendors)]
    ).lower()
    return any(kw in haystack for kw in config.follow)
