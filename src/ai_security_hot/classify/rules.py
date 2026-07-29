"""RuleClassifier — deterministic, zero-cost, offline (M1.1).

Company/model: alias table. event_type: source/connector + keyword rules.
tech_direction: keyword baseline (LLM becomes the main driver in M1.3, this
stays as the fallback when the LLM is unavailable — M1 plan §一).
"""

from __future__ import annotations

import re

from ai_security_hot.classify.base import Classification, Classifier
from ai_security_hot.classify.taxonomy import Taxonomy, load_taxonomy
from ai_security_hot.domain.models import NormalizedDocument, content_sha256


def _compile_aliases(aliases: list[str]) -> list[re.Pattern[str]]:
    # word-boundary, case-insensitive; CJK terms need no boundary
    pats = []
    for a in aliases:
        if re.search(r"[一-鿿]", a):
            pats.append(re.compile(re.escape(a), re.IGNORECASE))
        else:
            pats.append(re.compile(rf"(?<![\w-]){re.escape(a)}(?![\w-])", re.IGNORECASE))
    return pats


class RuleClassifier(Classifier):
    def __init__(self, taxonomy: Taxonomy | None = None) -> None:
        self.tax = taxonomy or load_taxonomy()
        self._company = {
            cid: _compile_aliases(al) for cid, al in self.tax.company_models.items()
        }
        self._tech = {
            tid: _compile_aliases(td.keywords) for tid, td in self.tax.tech_directions.items()
        }
        self._etype_kw = {
            et: _compile_aliases(kws) for et, kws in self.tax.event_type.by_keyword.items()
        }

    def classify(
        self,
        doc: NormalizedDocument,
        *,
        source_id: str | None = None,
        connector: str | None = None,
    ) -> Classification:
        text = f"{doc.title_original}\n{doc.body_text or ''}"

        companies = [
            cid for cid, pats in self._company.items() if any(p.search(text) for p in pats)
        ]
        techs = [tid for tid, pats in self._tech.items() if any(p.search(text) for p in pats)]
        event_type = self._event_type(text, doc, source_id, connector)

        # confidence: rules are high-precision on what they DO match
        hits = len(companies) + len(techs) + (1 if event_type else 0)
        confidence = min(1.0, 0.4 + 0.15 * hits)

        return Classification(
            tech_directions=techs,
            company_models=companies,
            event_type=event_type,
            confidence=round(confidence, 3),
            method="rule",
            rule_version=self.tax.version,
            input_hash=content_sha256(text),
        )

    def _event_type(
        self,
        text: str,
        doc: NormalizedDocument,
        source_id: str | None,
        connector: str | None,
    ) -> str:
        et = self.tax.event_type
        # strong signals first: source id, then connector
        if source_id:
            for key, val in et.by_source.items():
                if source_id.startswith(key):
                    return val
        if connector and connector in et.by_connector:
            return et.by_connector[connector]
        # hard signal: any CVE/GHSA already extracted => vulnerability
        if doc.cve_ids or doc.ghsa_ids or doc.cnvd_ids:
            return "vulnerability"
        # keyword rules
        for etype, pats in self._etype_kw.items():
            if any(p.search(text) for p in pats):
                return etype
        return et.default
