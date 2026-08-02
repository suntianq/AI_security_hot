"""Versioned, deterministic deduplication and event construction.

This module is deliberately pure: it makes no database or network calls. The
pipeline can therefore replay a rule version and explain every relationship.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from rapidfuzz import fuzz

from ai_security_hot.domain.enums import STRUCTURED_VULN_ENDPOINTS

DEDUPE_VERSION = "dedupe-v2"
CLUSTER_VERSION = "cluster-v2"
FUZZY_TITLE_THRESHOLD = 94.0

_ARXIV_RE = re.compile(r"arxiv\.org/(?:abs|pdf)/([0-9]{4}\.[0-9]{4,5})(?:v[0-9]+)?", re.I)
_GITHUB_RELEASE_RE = re.compile(r"github\.com/([^/]+)/([^/]+?)/releases/tag/([^/?#]+)", re.I)
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]+")
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9+.#_-]{2,}")
_SPACE_RE = re.compile(r"\s+")
_IDENTIFIER_PATTERNS = {
    "cve": re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}"),
    "ghsa": re.compile(r"GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}"),
    "cnvd": re.compile(r"CNVD-[0-9]{4}-[0-9]+"),
}


@dataclass(frozen=True, slots=True)
class IntelDocument:
    id: int
    endpoint_id: str
    source_id: str
    trust_tier: str
    title: str
    body: str | None
    canonical_url: str
    published_at: datetime | None
    fetched_at: datetime | None
    identifiers: dict[str, Any]
    tech_directions: list[str]
    event_type: str | None
    parse_quality: float
    # Dedupe only needs a normalized content fingerprint and body length.  The
    # repository can therefore stream large bodies, compute these two values,
    # and discard the text instead of retaining the entire corpus in memory.
    content_digest: str | None = None
    content_length: int | None = None
    entities: dict[str, Any] = field(default_factory=dict)
    company_models: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DedupDecision:
    document_id: int
    near_dup_of: int | None
    duplicate_kind: str | None
    duplicate_score: float | None


@dataclass(frozen=True, slots=True)
class EventKey:
    fingerprint: str
    kind: str


@dataclass(frozen=True, slots=True)
class EventMembership:
    document_id: int
    evidence_level: str
    relation_reason: str


@dataclass(frozen=True, slots=True)
class EventDraft:
    fingerprint: str
    event_type: str | None
    topic: str | None
    category: str | None  # "vuln_db" (NVD/KEV) or "general"
    title: str
    summary: str | None
    status: str
    score: int
    evidence_level: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    memberships: tuple[EventMembership, ...]


class _UnionFind:
    def __init__(self, ids: list[int]) -> None:
        self.parent = {document_id: document_id for document_id in ids}

    def find(self, document_id: int) -> int:
        parent = self.parent[document_id]
        if parent != document_id:
            self.parent[document_id] = self.find(parent)
        return self.parent[document_id]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[max(left_root, right_root)] = min(left_root, right_root)


def normalize_title(value: str) -> str:
    """Normalize case, width, punctuation and whitespace without translating."""
    normalized = unicodedata.normalize("NFKC", value).casefold()
    chars = [char if char.isalnum() else " " for char in normalized]
    return _SPACE_RE.sub(" ", "".join(chars)).strip()


def normalize_url_key(value: str) -> str:
    """Return a conservative equality key; do not merge HTTP and HTTPS."""
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return value.strip()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def title_similarity(left: str, right: str) -> float:
    left_key = normalize_title(left)
    right_key = normalize_title(right)
    if not left_key or not right_key:
        return 0.0
    ratio = fuzz.ratio(left_key, right_key)
    token_sort = fuzz.token_sort_ratio(left_key, right_key)
    return round(max(ratio, token_sort), 2)


def _compact_title(value: str) -> str:
    return normalize_title(value).replace(" ", "")


def _content_key(body: str | None) -> str | None:
    if not body:
        return None
    normalized = _SPACE_RE.sub(" ", unicodedata.normalize("NFKC", body)).strip()
    if len(normalized) < 200:
        return None
    return hashlib.sha256(normalized.encode()).hexdigest()


def content_fingerprint(body: str | None) -> str | None:
    """Return the exact-content key used by dedupe loaders and pure rules."""
    return _content_key(body)


def _document_content_key(doc: IntelDocument) -> str | None:
    if doc.content_digest is not None:
        return doc.content_digest
    return _content_key(doc.body)


def _document_body_length(doc: IntelDocument) -> int:
    if doc.content_length is not None:
        return doc.content_length
    return len(doc.body or "")


def _identifier_values(doc: IntelDocument, kind: str) -> set[str]:
    raw = doc.identifiers.get(kind, [])
    if not isinstance(raw, list):
        return set()
    pattern = _IDENTIFIER_PATTERNS[kind]
    values = {str(value).upper() for value in raw if value}
    return {value for value in values if pattern.fullmatch(value)}


def _identifier_set(doc: IntelDocument) -> set[str]:
    return {value for kind in ("cve", "ghsa", "cnvd") for value in _identifier_values(doc, kind)}


def _identifiers_conflict(left: IntelDocument, right: IntelDocument) -> bool:
    """Hard-block incompatible strong identities before any fuzzy rule.

    CVE/GHSA/CNVD retain their original cross-kind conflict behaviour. New
    M2.1 identities are compared within their own kind, so two different
    GitHub releases or explicitly structured incidents cannot be merged by a
    similar headline.
    """
    left_ids = _identifier_set(left)
    right_ids = _identifier_set(right)
    if left_ids and right_ids and left_ids.isdisjoint(right_ids):
        return True
    exclusive_kinds = {
        "arxiv",
        "github_release",
        "model_release",
        "package_release",
        "incident",
        "campaign",
    }
    left_by_kind: dict[str, set[str]] = defaultdict(set)
    right_by_kind: dict[str, set[str]] = defaultdict(set)
    for key in strong_event_keys(left):
        if key.kind in exclusive_kinds:
            left_by_kind[key.kind].add(key.fingerprint)
    for key in strong_event_keys(right):
        if key.kind in exclusive_kinds:
            right_by_kind[key.kind].add(key.fingerprint)
    return any(
        left_by_kind[kind]
        and right_by_kind[kind]
        and left_by_kind[kind].isdisjoint(right_by_kind[kind])
        for kind in left_by_kind.keys() & right_by_kind.keys()
    )


def _dates_compatible(
    left: IntelDocument, right: IntelDocument, *, days: int, require_both: bool = False
) -> bool:
    if left.published_at is None or right.published_at is None:
        return not require_both
    return abs(left.published_at - right.published_at) <= timedelta(days=days)


def _blocking_keys(title: str) -> set[str]:
    normalized = normalize_title(title)
    keys = {f"w:{word}" for word in _WORD_RE.findall(normalized) if len(word) >= 4}
    for segment in _CJK_RE.findall(normalized):
        keys.update(f"c:{segment[index : index + 2]}" for index in range(len(segment) - 1))
    return keys


def _master_rank(doc: IntelDocument) -> tuple[int, float, int, int, int]:
    trust_rank = {"A": 0, "B": 1, "C": 2}.get(doc.trust_tier, 3)
    return (
        trust_rank,
        -doc.parse_quality,
        -_document_body_length(doc),
        -len(doc.title),
        doc.id,
    )


def _same_isolation_scope(left: IntelDocument, right: IntelDocument) -> bool:
    """True when both documents belong to the same vuln/general isolation scope.

    Structured vulnerability feeds (NVD/KEV) must never merge with a news
    article, even when a headline repeats the same CVE id. Enforced at every
    union point so cross-scope near-duplicates stay in separate components.
    """
    return (
        left.endpoint_id in STRUCTURED_VULN_ENDPOINTS
    ) == (right.endpoint_id in STRUCTURED_VULN_ENDPOINTS)


def deduplicate_documents(
    documents: list[IntelDocument],
    *,
    fuzzy_threshold: float = FUZZY_TITLE_THRESHOLD,
    approved_pairs: set[tuple[int, int]] | None = None,
) -> dict[int, DedupDecision]:
    """Build non-destructive duplicate components and select one master each."""
    if not documents:
        return {}

    docs = {doc.id: doc for doc in documents}
    union_find = _UnionFind(list(docs))

    url_groups: dict[str, list[int]] = defaultdict(list)
    title_groups: dict[str, list[int]] = defaultdict(list)
    content_groups: dict[str, list[int]] = defaultdict(list)
    for doc in documents:
        if doc.canonical_url.strip():
            url_groups[normalize_url_key(doc.canonical_url)].append(doc.id)
        compact = _compact_title(doc.title)
        if len(compact) >= 20:
            title_groups[compact].append(doc.id)
        content_key = _document_content_key(doc)
        if content_key:
            content_groups[content_key].append(doc.id)

    for group in url_groups.values():
        if len(group) < 2:
            continue
        identified: dict[str, list[int]] = defaultdict(list)
        unidentified: list[int] = []
        for document_id in group:
            identifiers = _identifier_set(docs[document_id])
            if identifiers:
                for identifier in identifiers:
                    identified[identifier].append(document_id)
            else:
                unidentified.append(document_id)
        # A shared catalogue URL (for example CISA KEV) is not item identity.
        # Only documents sharing a strong identifier may merge in such groups.
        for same_identifier in identified.values():
            for document_id in same_identifier[1:]:
                if _same_isolation_scope(docs[same_identifier[0]], docs[document_id]):
                    union_find.union(same_identifier[0], document_id)
        for document_id in unidentified[1:]:
            if _same_isolation_scope(docs[unidentified[0]], docs[document_id]):
                union_find.union(unidentified[0], document_id)
        if len(identified) <= 1 and identified and unidentified:
            identified_master = next(iter(identified.values()))[0]
            if _same_isolation_scope(docs[identified_master], docs[unidentified[0]]):
                union_find.union(identified_master, unidentified[0])

    for group in title_groups.values():
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                left = docs[left_id]
                right = docs[right_id]
                if (
                    _same_isolation_scope(left, right)
                    and not _identifiers_conflict(left, right)
                    and _dates_compatible(left, right, days=30)
                ):
                    union_find.union(left_id, right_id)

    for group in content_groups.values():
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                left = docs[left_id]
                right = docs[right_id]
                if (
                    _same_isolation_scope(left, right)
                    and not _identifiers_conflict(left, right)
                    and _dates_compatible(left, right, days=30)
                    and title_similarity(left.title, right.title) >= 80
                ):
                    union_find.union(left_id, right_id)

    block_index: dict[str, list[int]] = defaultdict(list)
    for doc in documents:
        # Short titles cannot pass the later fuzzy-candidate length gate.  Do
        # not index hundreds of thousands of catalogue titles such as CVE IDs
        # only to reject every generated pair afterwards.
        if len(_compact_title(doc.title)) < 24:
            continue
        for key in _blocking_keys(doc.title):
            block_index[key].append(doc.id)

    candidate_pairs: set[tuple[int, int]] = set()
    for group in block_index.values():
        if len(group) > 100:
            continue
        for index, left_id in enumerate(group):
            for right_id in group[index + 1 :]:
                candidate_pairs.add((min(left_id, right_id), max(left_id, right_id)))

    for left_id, right_id in candidate_pairs:
        left = docs[left_id]
        right = docs[right_id]
        if _identifiers_conflict(left, right):
            continue
        if not _dates_compatible(left, right, days=14, require_both=True):
            continue
        left_len = len(_compact_title(left.title))
        right_len = len(_compact_title(right.title))
        if (
            min(left_len, right_len) < 24
            or min(left_len, right_len) / max(left_len, right_len) < 0.72
        ):
            continue
        ratio = fuzz.ratio(normalize_title(left.title), normalize_title(right.title))
        score = title_similarity(left.title, right.title)
        if (
            _same_isolation_scope(left, right)
            and score >= fuzzy_threshold
            and ratio >= 88
        ):
            union_find.union(left_id, right_id)

    approved_documents: set[int] = set()
    for left_id, right_id in sorted(approved_pairs or set()):
        if left_id not in docs or right_id not in docs:
            continue
        # Human review can approve a conservative semantic candidate, but it
        # cannot override incompatible strong identities or the vuln/general
        # isolation boundary.
        if _identifiers_conflict(docs[left_id], docs[right_id]):
            continue
        if not _same_isolation_scope(docs[left_id], docs[right_id]):
            continue
        union_find.union(left_id, right_id)
        approved_documents.update((left_id, right_id))

    component_masters: dict[int, IntelDocument] = {}
    for doc in documents:
        root = union_find.find(doc.id)
        master = component_masters.get(root)
        if master is None or _master_rank(doc) < _master_rank(master):
            component_masters[root] = doc

    decisions: dict[int, DedupDecision] = {}
    for doc in documents:
        master = component_masters[union_find.find(doc.id)]
        if doc.id == master.id:
            decisions[doc.id] = DedupDecision(doc.id, None, None, None)
            continue
        if normalize_url_key(doc.canonical_url) == normalize_url_key(master.canonical_url):
            kind, score = "exact_url", 1.0
        elif _compact_title(doc.title) == _compact_title(master.title):
            kind, score = "exact_title", 1.0
        elif _document_content_key(doc) and _document_content_key(doc) == _document_content_key(
            master
        ):
            kind, score = "exact_content", 1.0
        elif doc.id in approved_documents:
            kind = "review_approved"
            score = title_similarity(doc.title, master.title) / 100
        else:
            kind = "near_title"
            score = title_similarity(doc.title, master.title) / 100
        decisions[doc.id] = DedupDecision(doc.id, master.id, kind, round(score, 4))
    return decisions


def _identity_part(value: Any) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold().strip()
    return re.sub(r"[^a-z0-9._+-]+", "-", normalized).strip("-")


def _bounded_event_key(kind: str, *parts: Any) -> EventKey | None:
    values = [_identity_part(part) for part in parts]
    if not values or any(not value for value in values):
        return None
    fingerprint = f"{kind}:{'@'.join(values)}"
    if len(fingerprint) > 160:
        digest = hashlib.sha256(fingerprint.encode()).hexdigest()
        fingerprint = f"{kind}:sha256:{digest}"
    return EventKey(fingerprint, kind)


def _structured_pairs(
    entities: dict[str, Any], key: str, left_name: str, right_name: str
) -> list[tuple[str, str]]:
    raw = entities.get(key, [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    pairs: list[tuple[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        left = str(item.get(left_name) or "").strip()
        right = str(item.get(right_name) or "").strip()
        if left and right:
            pairs.append((left, right))
    return pairs


def strong_event_keys(doc: IntelDocument) -> tuple[EventKey, ...]:
    """Extract conservative stable event keys; entity-only links stay separate.

    Model/package identities are event keys only for release-classified
    documents. Merely mentioning GPT-4 or a package version must not collapse
    unrelated research, vulnerabilities and incidents into one event.
    """
    keys: list[EventKey] = []
    # Structured vuln feeds (NVD/KEV) get a namespaced key so their events are
    # a separate vuln-db category and never merge with a news article that
    # merely references the same CVE id.
    vuln_namespace = (
        "cve-nvd" if doc.endpoint_id in STRUCTURED_VULN_ENDPOINTS else "cve"
    )
    for kind in ("cve", "ghsa", "cnvd"):
        for value in sorted(_identifier_values(doc, kind)):
            if kind == "cve" and doc.endpoint_id in STRUCTURED_VULN_ENDPOINTS:
                keys.append(EventKey(f"cve-nvd:{value}", vuln_namespace))
            else:
                keys.append(EventKey(f"{kind}:{value}", kind))
    match = _ARXIV_RE.search(doc.canonical_url)
    if match:
        keys.append(EventKey(f"arxiv:{match.group(1)}", "arxiv"))
    release = _GITHUB_RELEASE_RE.search(doc.canonical_url)
    if release:
        key = _bounded_event_key(
            "github_release", release.group(1), release.group(2), release.group(3)
        )
        if key:
            keys.append(key)
    entities = doc.entities or {}
    if doc.event_type == "release":
        for model, version in _structured_pairs(entities, "model_versions", "model", "version"):
            key = _bounded_event_key("model_release", model, version)
            if key:
                keys.append(key)
        for package, version in _structured_pairs(entities, "packages", "name", "version"):
            key = _bounded_event_key("package_release", package, version)
            if key:
                keys.append(key)
    for company, incident in _structured_pairs(entities, "incidents", "company", "incident"):
        product = ""
        raw_incidents = entities.get("incidents", [])
        rows = [raw_incidents] if isinstance(raw_incidents, dict) else raw_incidents
        if isinstance(rows, list):
            product = next(
                (
                    str(row.get("product") or "")
                    for row in rows
                    if isinstance(row, dict)
                    and str(row.get("company") or "") == company
                    and str(row.get("incident") or "") == incident
                ),
                "",
            )
        key = _bounded_event_key("incident", company, product or "unknown-product", incident)
        if key:
            keys.append(key)
    for actor, campaign in _structured_pairs(entities, "campaigns", "actor", "campaign"):
        key = _bounded_event_key("campaign", actor, campaign)
        if key:
            keys.append(key)
    return tuple(dict.fromkeys(keys))


def _primary_topic(documents: list[IntelDocument], kind: str) -> str | None:
    if kind in {"cve", "ghsa", "cnvd", "cve-nvd"}:
        return "cve"
    priority = ("security_for_ai", "ai_for_security", "agent", "llm", "system_security")
    counts = Counter(topic for doc in documents for topic in doc.tech_directions if topic != "cve")
    if not counts:
        return None
    return min(
        counts,
        key=lambda topic: (-counts[topic], priority.index(topic) if topic in priority else 99),
    )


def _event_type(documents: list[IntelDocument], kind: str) -> str | None:
    if kind in {"cve", "ghsa", "cnvd", "cve-nvd"}:
        return "vulnerability"
    if kind == "arxiv":
        return "research"
    if kind in {"github_release", "model_release", "package_release"}:
        return "release"
    if kind in {"incident", "campaign"}:
        return "incident"
    counts = Counter(doc.event_type for doc in documents if doc.event_type)
    return counts.most_common(1)[0][0] if counts else None


def _summary(doc: IntelDocument) -> str | None:
    value = _SPACE_RE.sub(" ", doc.body or "").strip()
    if not value or value == doc.title.strip():
        return None
    return value[:600].rstrip()


def _event_score(documents: list[IntelDocument], *, kind: str, source_count: int) -> int:
    best_tier = min(
        (doc.trust_tier for doc in documents),
        key=lambda tier: {"A": 0, "B": 1, "C": 2}.get(tier, 3),
    )
    trust_score = {"A": 40, "B": 28, "C": 15}.get(best_tier, 10)
    identity_score = (
        25
        if kind in {"cve", "ghsa", "cnvd", "cve-nvd", "github_release", "incident", "campaign"}
        else 20
        if kind in {"model_release", "package_release"}
        else 15
        if kind == "arxiv"
        else 5
    )
    diversity_score = min(20, max(0, source_count - 1) * 7)
    quality_score = round(max((doc.parse_quality for doc in documents), default=0.0) * 15)
    return min(100, trust_score + identity_score + diversity_score + quality_score)


def build_event_draft(
    key: EventKey,
    members: list[IntelDocument],
    reasons: dict[int, str],
) -> EventDraft:
    """Build one deterministic event from its complete ordered evidence group."""
    primary = min(members, key=_master_rank)
    evidence_level = min(
        (doc.trust_tier for doc in members),
        key=lambda tier: {"A": 0, "B": 1, "C": 2}.get(tier, 3),
    )
    observed = [doc.published_at or doc.fetched_at for doc in members]
    observed = [value for value in observed if value is not None]
    source_count = len({doc.source_id for doc in members})
    memberships = tuple(
        EventMembership(doc.id, doc.trust_tier, reasons[doc.id])
        for doc in sorted(members, key=lambda item: item.id)
    )
    return EventDraft(
        fingerprint=key.fingerprint,
        event_type=_event_type(members, key.kind),
        topic=_primary_topic(members, key.kind),
        category="vuln_db" if key.kind == "cve-nvd" else "general",
        title=primary.title.strip()[:240],
        summary=_summary(primary),
        status="detected",
        score=_event_score(members, kind=key.kind, source_count=source_count),
        evidence_level=evidence_level,
        first_seen_at=min(observed) if observed else None,
        last_seen_at=max(observed) if observed else None,
        memberships=memberships,
    )


def build_event_drafts(
    documents: list[IntelDocument],
    decisions: dict[int, DedupDecision],
) -> dict[str, EventDraft]:
    """Turn duplicate components into strong-key or fallback events."""
    if not documents:
        return {}
    docs_by_id = {doc.id: doc for doc in documents}
    component_docs: dict[int, list[IntelDocument]] = defaultdict(list)
    for doc in documents:
        decision = decisions.get(doc.id)
        master_id = decision.near_dup_of if decision and decision.near_dup_of else doc.id
        component_docs[master_id].append(doc)

    event_members: dict[EventKey, dict[int, str]] = defaultdict(dict)
    for master_id, component in component_docs.items():
        keys_by_document = {doc.id: set(strong_event_keys(doc)) for doc in component}
        keys = {key for doc_keys in keys_by_document.values() for key in doc_keys}
        if len(keys) > 20:
            # Defensive degradation: a duplicate component must never create an
            # unbounded strong-key × document Cartesian product.
            for doc in component:
                own_keys = keys_by_document[doc.id]
                if not own_keys:
                    own_keys = {EventKey(f"document:{doc.id}", "document")}
                for key in own_keys:
                    event_members[key][doc.id] = (
                        f"identifier:{key.kind}" if key.kind != "document" else "component"
                    )
            continue
        if not keys:
            keys = {EventKey(f"document:{master_id}", "document")}
        for key in keys:
            for doc in component:
                if key in keys_by_document[doc.id]:
                    reason = f"identifier:{key.kind}"
                else:
                    decision = decisions.get(doc.id)
                    reason = (
                        decision.duplicate_kind
                        if decision and decision.duplicate_kind
                        else "component"
                    )
                event_members[key][doc.id] = reason

    drafts: dict[str, EventDraft] = {}
    for key, reasons in event_members.items():
        members = [docs_by_id[document_id] for document_id in reasons]
        drafts[key.fingerprint] = build_event_draft(key, members, reasons)
    return drafts
