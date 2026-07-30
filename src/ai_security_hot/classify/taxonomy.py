"""Load and validate taxonomy.yaml into typed config."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class EventTypeRules(BaseModel):
    default: str = "opinion"
    by_source: dict[str, str] = Field(default_factory=dict)
    by_connector: dict[str, str] = Field(default_factory=dict)
    by_keyword: dict[str, list[str]] = Field(default_factory=dict)


class TechDirection(BaseModel):
    keywords: list[str] = Field(default_factory=list)


class Taxonomy(BaseModel):
    version: str = "taxonomy-v2"
    company_models: dict[str, list[str]] = Field(default_factory=dict)
    tech_directions: dict[str, TechDirection] = Field(default_factory=dict)
    event_type: EventTypeRules = Field(default_factory=EventTypeRules)


@lru_cache
def load_taxonomy(path: str | None = None) -> Taxonomy:
    p = Path(path) if path else Path("sources/taxonomy.yaml")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    return Taxonomy.model_validate(data)
