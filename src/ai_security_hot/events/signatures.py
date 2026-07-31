"""M2.1 deterministic document signatures and conservative candidates.

This module is pure and versioned.  PostgreSQL stores its output so a normal
incremental run only loads documents that share an exact key, strong identity
or bounded LSH bucket with changed evidence.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from ai_security_hot.events.intelligence import (
    IntelDocument,
    content_fingerprint,
    normalize_title,
    normalize_url_key,
    strong_event_keys,
    title_similarity,
)

SIGNATURE_VERSION = "signature-v3"
SIMHASH_BITS = 64
MINHASH_SIZE = 16

_WORD_RE = re.compile(r"[a-z0-9][a-z0-9+.#_-]{2,}")
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")


@dataclass(frozen=True, slots=True)
class DocumentIdentity:
    kind: str
    value: str
    fingerprint: str
    event_key: bool


@dataclass(frozen=True, slots=True)
class DocumentSignatureDraft:
    url_hash: str | None
    title_hash: str | None
    content_hash: str | None
    simhash: str | None
    minhash: tuple[int, ...]
    block_tokens: tuple[str, ...]
    identities: tuple[DocumentIdentity, ...]


@dataclass(frozen=True, slots=True)
class CandidateAssessment:
    decision: str  # merge | review | separate
    reason: str
    score: float
    title_score: float
    simhash_distance: int | None
    minhash_similarity: float | None
    conflict: str | None = None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _tokens(value: str) -> tuple[str, ...]:
    normalized = normalize_title(value)
    tokens = {word for word in _WORD_RE.findall(normalized) if len(word) >= 4}
    for segment in _CJK_RE.findall(normalized):
        tokens.update(segment[index : index + 2] for index in range(len(segment) - 1))
    return tuple(sorted(tokens))


def blocking_tokens(title: str, body: str | None = None) -> tuple[str, ...]:
    """Return bounded persistent candidate keys, excluding short catalogue titles."""
    title_tokens = _tokens(title)
    if len(normalize_title(title).replace(" ", "")) < 24:
        return ()
    summary_tokens = _tokens((body or "")[:600])
    # A document cannot create unbounded index fan-out. Title tokens have
    # priority because they are both cheaper and more precise than body words.
    return tuple(dict.fromkeys((*title_tokens[:24], *summary_tokens[:8])))


def simhash64(value: str) -> str | None:
    tokens = _tokens(value)
    if not tokens:
        return None
    weights = [0] * SIMHASH_BITS
    for token in tokens:
        digest = int.from_bytes(hashlib.sha256(token.encode()).digest()[:8], "big")
        for bit in range(SIMHASH_BITS):
            weights[bit] += 1 if digest & (1 << bit) else -1
    result = sum(1 << bit for bit, weight in enumerate(weights) if weight >= 0)
    return f"{result:016x}"


def simhash_distance(left: str | None, right: str | None) -> int | None:
    if not left or not right:
        return None
    return (int(left, 16) ^ int(right, 16)).bit_count()


def simhash_bands(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    number = int(value, 16)
    return tuple(f"sim:{band}:{(number >> (band * 16)) & 0xFFFF:04x}" for band in range(4))


def minhash_signature(value: str) -> tuple[int, ...]:
    tokens = _tokens(value)
    if not tokens:
        return ()
    return tuple(
        min(
            int.from_bytes(hashlib.sha256(f"{seed}:{token}".encode()).digest()[:8], "big")
            for token in tokens
        )
        for seed in range(MINHASH_SIZE)
    )


def minhash_similarity(left: tuple[int, ...], right: tuple[int, ...]) -> float | None:
    if len(left) != MINHASH_SIZE or len(right) != MINHASH_SIZE:
        return None
    return sum(a == b for a, b in zip(left, right, strict=True)) / MINHASH_SIZE


def minhash_bands(value: tuple[int, ...]) -> tuple[str, ...]:
    if len(value) != MINHASH_SIZE:
        return ()
    bands: list[str] = []
    for band in range(4):
        chunk = value[band * 4 : (band + 1) * 4]
        digest = _sha256(":".join(str(item) for item in chunk))[:16]
        bands.append(f"min:{band}:{digest}")
    return tuple(bands)


def _identity(kind: str, value: Any, *, event_key: bool = False) -> DocumentIdentity | None:
    normalized = re.sub(r"\s+", " ", str(value or "").strip()).casefold()
    if not normalized:
        return None
    fingerprint = f"{kind}:{normalized}"
    if len(fingerprint) > 256:
        fingerprint = f"{kind}:sha256:{_sha256(fingerprint)}"
    return DocumentIdentity(kind, normalized, fingerprint, event_key)


def _entity_rows(entities: dict[str, Any], key: str) -> list[dict[str, Any]]:
    raw = entities.get(key, [])
    if isinstance(raw, dict):
        return [raw]
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def extract_document_identities(document: IntelDocument) -> tuple[DocumentIdentity, ...]:
    identities: list[DocumentIdentity] = []
    for key in strong_event_keys(document):
        identity = _identity(key.kind, key.fingerprint.split(":", 1)[1], event_key=True)
        if identity:
            identities.append(identity)
    for company_model in document.company_models:
        identity = _identity("company_model", company_model)
        if identity:
            identities.append(identity)
    entities = document.entities or {}
    for row in _entity_rows(entities, "model_versions"):
        identity = _identity("model_version", f"{row.get('model')}@{row.get('version')}")
        if identity:
            identities.append(identity)
    for row in _entity_rows(entities, "packages"):
        identity = _identity("package_version", f"{row.get('name')}@{row.get('version')}")
        if identity:
            identities.append(identity)
    repositories = entities.get("repositories", [])
    if isinstance(repositories, str):
        repositories = [repositories]
    if not isinstance(repositories, list):
        repositories = []
    for repository in repositories:
        identity = _identity("repository", repository)
        if identity:
            identities.append(identity)
    for row in _entity_rows(entities, "affected_ai_components"):
        identity = _identity(
            "vulnerability_component",
            f"{row.get('vulnerability')}@{row.get('component')}",
        )
        if identity:
            identities.append(identity)
    for row in _entity_rows(entities, "campaigns"):
        identity = _identity("actor", row.get("actor"))
        if identity:
            identities.append(identity)
    return tuple(
        sorted(
            {(item.kind, item.fingerprint): item for item in identities}.values(),
            key=lambda item: (item.kind, item.fingerprint),
        )
    )


def _document_url_key(document: IntelDocument) -> str:
    """Keep a fragment only when the publisher uses it as strong record identity."""
    url_key = normalize_url_key(document.canonical_url)
    try:
        fragment = urlsplit(document.canonical_url).fragment
    except ValueError:
        return url_key
    normalized_fragment = re.sub(r"[^a-z0-9]+", "", fragment.casefold())
    if not normalized_fragment:
        return url_key
    strong_values = {
        re.sub(r"[^a-z0-9]+", "", key.fingerprint.split(":", 1)[1].casefold())
        for key in strong_event_keys(document)
    }
    if normalized_fragment in strong_values:
        return f"{url_key}#{fragment.casefold()}"
    return url_key


def build_document_signature(document: IntelDocument) -> DocumentSignatureDraft:
    url_key = _document_url_key(document) if document.canonical_url.strip() else ""
    title_key = normalize_title(document.title)
    similarity_text = f"{document.title}\n{(document.body or '')[:600]}"
    simhash = simhash64(similarity_text)
    minhash = minhash_signature(similarity_text)
    blocks = blocking_tokens(document.title, document.body)
    lsh_blocks = (*simhash_bands(simhash), *minhash_bands(minhash))
    return DocumentSignatureDraft(
        url_hash=_sha256(url_key) if url_key else None,
        title_hash=_sha256(title_key) if len(title_key.replace(" ", "")) >= 20 else None,
        content_hash=content_fingerprint(document.body),
        simhash=simhash,
        minhash=minhash,
        block_tokens=tuple(dict.fromkeys((*blocks, *lsh_blocks))),
        identities=extract_document_identities(document),
    )


def _event_keys_by_kind(document: IntelDocument) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for key in strong_event_keys(document):
        result.setdefault(key.kind, set()).add(key.fingerprint)
    return result


def strong_identity_conflict(left: IntelDocument, right: IntelDocument) -> str | None:
    left_keys = _event_keys_by_kind(left)
    right_keys = _event_keys_by_kind(right)
    for kind in sorted(left_keys.keys() & right_keys.keys()):
        if left_keys[kind].isdisjoint(right_keys[kind]):
            return f"conflict:{kind}"
    left_vulns = {value for kind in ("cve", "ghsa", "cnvd") for value in left_keys.get(kind, set())}
    right_vulns = {
        value for kind in ("cve", "ghsa", "cnvd") for value in right_keys.get(kind, set())
    }
    if left_vulns and right_vulns and left_vulns.isdisjoint(right_vulns):
        return "conflict:vulnerability"
    return None


def assess_candidate(
    left: IntelDocument,
    right: IntelDocument,
    *,
    left_signature: DocumentSignatureDraft | None = None,
    right_signature: DocumentSignatureDraft | None = None,
) -> CandidateAssessment:
    conflict = strong_identity_conflict(left, right)
    title_score = title_similarity(left.title, right.title)
    left_sig = left_signature or build_document_signature(left)
    right_sig = right_signature or build_document_signature(right)
    distance = simhash_distance(left_sig.simhash, right_sig.simhash)
    minhash_score = minhash_similarity(left_sig.minhash, right_sig.minhash)
    if conflict:
        return CandidateAssessment(
            "separate", conflict, 0.0, title_score, distance, minhash_score, conflict
        )
    observed_left = left.published_at or left.fetched_at
    observed_right = right.published_at or right.fetched_at
    if (
        observed_left
        and observed_right
        and abs(observed_left - observed_right) > timedelta(days=30)
    ):
        return CandidateAssessment(
            "separate", "outside_time_window", 0.0, title_score, distance, minhash_score
        )
    if left_sig.url_hash and left_sig.url_hash == right_sig.url_hash:
        return CandidateAssessment("merge", "exact_url", 1.0, title_score, distance, minhash_score)
    if left_sig.title_hash and left_sig.title_hash == right_sig.title_hash:
        return CandidateAssessment(
            "merge", "exact_title", 1.0, title_score, distance, minhash_score
        )
    if left_sig.content_hash and left_sig.content_hash == right_sig.content_hash:
        return CandidateAssessment(
            "merge", "exact_content", 1.0, title_score, distance, minhash_score
        )
    if title_score >= 94:
        return CandidateAssessment(
            "merge", "near_title", round(title_score / 100, 4), title_score, distance, minhash_score
        )
    semantic_score = max(
        title_score / 100,
        1 - (distance / SIMHASH_BITS) if distance is not None else 0.0,
        minhash_score or 0.0,
    )
    if title_score >= 82 or (distance is not None and distance <= 8) or (minhash_score or 0) >= 0.5:
        return CandidateAssessment(
            "review",
            "semantic_candidate",
            round(semantic_score, 4),
            title_score,
            distance,
            minhash_score,
        )
    return CandidateAssessment(
        "separate",
        "below_threshold",
        round(semantic_score, 4),
        title_score,
        distance,
        minhash_score,
    )
