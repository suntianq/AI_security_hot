"""Classifier interface + Classification value object (M1 plan §二).

Same pattern as Connector/Parser: define the interface once; RuleClassifier
(M1.1), LLMClassifier / HybridClassifier (M1.3) are swappable implementations.
The pipeline depends only on this interface — swapping in the LLM later needs
no schema/pipeline change because the provenance fields are already here.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, Field

from ai_security_hot.domain.models import NormalizedDocument


class Classification(BaseModel):
    """Result of classifying one document. Multi-label for both layers."""

    # Layer 2: 技术方向 — subset of
    # {ai_for_security, security_for_ai, agent, system_security}
    tech_directions: list[str] = Field(default_factory=list)
    # Layer 1: 公司与模型 — subset of the 15 configured ids
    company_models: list[str] = Field(default_factory=list)
    # content form — single value
    event_type: str | None = None
    confidence: float = 0.0

    # --- provenance (stored now so upgrading to LLM needs zero migration) ---
    method: str = "rule"  # "rule" | "llm" | "hybrid"
    model_version: str | None = None
    prompt_version: str | None = None
    rule_version: str | None = None
    input_hash: str | None = None


class Classifier(Protocol):
    """A classifier maps a normalized document to a Classification."""

    def classify(self, doc: NormalizedDocument) -> Classification: ...
