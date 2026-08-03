"""Persistent, locally rebuilt identities for semantic same-event components."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import uuid4

from sqlalchemy import and_, case, not_, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ai_security_hot.models.semantic_tables import (
    AtomicEvent,
    RelationVerdict,
    SemanticComponentWorkItem,
    SemanticRelationComponent,
    SemanticRelationMembership,
)
from ai_security_hot.models.tables import Document
from ai_security_hot.semantic.versions import RELATION_COMPONENT_VERSION, RELATION_VERSION
from ai_security_hot.storage.repositories import current_document_conditions

log = logging.getLogger("intel.relation_components")


@dataclass(frozen=True)
class ComponentLease:
    id: int
    seed_atomic_id: int
    generation: int
    attempts: int
    lease_token: str


@dataclass(frozen=True)
class RelationComponent:
    id: int
    component_key: str
    revision: int
    atomic_ids: list[int]

    @property
    def fingerprint(self) -> str:
        return f"semantic-component:{self.component_key}"


def enqueue_component_work(
    session: Session,
    atomic_ids: set[int] | list[int],
    *,
    reason: str,
) -> int:
    """Increment each seed generation without stealing an active worker lease."""
    now = datetime.now(UTC)
    affected = 0
    for atomic_id in sorted(set(int(value) for value in atomic_ids)):
        stmt = pg_insert(SemanticComponentWorkItem).values(
            seed_atomic_id=atomic_id,
            algorithm_version=RELATION_COMPONENT_VERSION,
            status="pending",
            requested_generation=1,
            completed_generation=0,
            attempts=0,
            reason=reason[:64],
            updated_at=now,
        )
        running = and_(
            SemanticComponentWorkItem.status == "running",
            SemanticComponentWorkItem.lease_until > now,
        )
        session.execute(
            stmt.on_conflict_do_update(
                constraint="uq_semantic_component_work_seed",
                set_={
                    "requested_generation": (SemanticComponentWorkItem.requested_generation + 1),
                    "status": case((running, "running"), else_="pending"),
                    "attempts": case(
                        (running, SemanticComponentWorkItem.attempts),
                        else_=0,
                    ),
                    "reason": reason[:64],
                    "lease_token": case(
                        (running, SemanticComponentWorkItem.lease_token),
                        else_=None,
                    ),
                    "lease_until": case(
                        (running, SemanticComponentWorkItem.lease_until),
                        else_=None,
                    ),
                    "next_retry_at": case(
                        (running, SemanticComponentWorkItem.next_retry_at),
                        else_=None,
                    ),
                    "error": None,
                    "updated_at": now,
                },
            )
        )
        affected += 1
    session.flush()
    return affected


def ensure_component_work(
    session: Session,
    atomic_ids: set[int] | list[int],
    *,
    reason: str,
) -> int:
    """Ensure discovery work exists without repeatedly bumping an open generation."""
    now = datetime.now(UTC)
    affected = 0
    for atomic_id in sorted(set(int(value) for value in atomic_ids)):
        stmt = pg_insert(SemanticComponentWorkItem).values(
            seed_atomic_id=atomic_id,
            algorithm_version=RELATION_COMPONENT_VERSION,
            status="pending",
            requested_generation=1,
            completed_generation=0,
            attempts=0,
            reason=reason[:64],
            updated_at=now,
        )
        result = session.execute(
            stmt.on_conflict_do_update(
                constraint="uq_semantic_component_work_seed",
                set_={
                    "requested_generation": (SemanticComponentWorkItem.requested_generation + 1),
                    "status": "pending",
                    "attempts": 0,
                    "reason": reason[:64],
                    "lease_token": None,
                    "lease_until": None,
                    "next_retry_at": None,
                    "error": None,
                    "updated_at": now,
                },
                where=(
                    SemanticComponentWorkItem.completed_generation
                    >= SemanticComponentWorkItem.requested_generation
                ),
            ).returning(SemanticComponentWorkItem.id)
        ).scalar_one_or_none()
        affected += int(result is not None)
    session.flush()
    return affected


def enqueue_missing_component_work(session: Session, *, limit: int = 500) -> int:
    """Find current same-event edges with at least one unmaterialized endpoint."""
    from sqlalchemy.orm import aliased

    left_atomic = aliased(AtomicEvent)
    right_atomic = aliased(AtomicEvent)
    left_document = aliased(Document)
    right_document = aliased(Document)
    left_membership = aliased(SemanticRelationMembership)
    right_membership = aliased(SemanticRelationMembership)
    rows = session.execute(
        select(
            RelationVerdict.left_atomic_id,
            RelationVerdict.right_atomic_id,
        )
        .join(left_atomic, left_atomic.id == RelationVerdict.left_atomic_id)
        .join(right_atomic, right_atomic.id == RelationVerdict.right_atomic_id)
        .join(left_document, left_document.id == left_atomic.document_id)
        .join(right_document, right_document.id == right_atomic.document_id)
        .where(
            RelationVerdict.decision == "same_event",
            RelationVerdict.algorithm_version == RELATION_VERSION,
            left_document.source_status == "active",
            left_document.record_status.not_in(["rejected", "withdrawn"]),
            right_document.source_status == "active",
            right_document.record_status.not_in(["rejected", "withdrawn"]),
            or_(
                ~select(left_membership.id)
                .where(
                    left_membership.atomic_event_id == RelationVerdict.left_atomic_id,
                    left_membership.algorithm_version == RELATION_COMPONENT_VERSION,
                    left_membership.active.is_(True),
                )
                .exists(),
                ~select(right_membership.id)
                .where(
                    right_membership.atomic_event_id == RelationVerdict.right_atomic_id,
                    right_membership.algorithm_version == RELATION_COMPONENT_VERSION,
                    right_membership.active.is_(True),
                )
                .exists(),
            ),
        )
        .order_by(RelationVerdict.id)
        .limit(limit)
    ).all()
    candidates = {int(value) for row in rows for value in (row.left_atomic_id, row.right_atomic_id)}
    return ensure_component_work(
        session,
        candidates,
        reason="missing_materialization",
    )


def enqueue_stale_component_work(session: Session, *, limit: int = 500) -> int:
    """Invalidate active memberships whose source Document is no longer current."""
    rows = session.execute(
        select(SemanticRelationMembership.atomic_event_id)
        .join(AtomicEvent, AtomicEvent.id == SemanticRelationMembership.atomic_event_id)
        .join(Document, Document.id == AtomicEvent.document_id)
        .where(
            SemanticRelationMembership.algorithm_version == RELATION_COMPONENT_VERSION,
            SemanticRelationMembership.active.is_(True),
            not_(and_(*current_document_conditions())),
        )
        .order_by(SemanticRelationMembership.id)
        .limit(limit)
    ).scalars()
    return ensure_component_work(
        session,
        {int(value) for value in rows},
        reason="document_not_current",
    )


def claim_component_work(
    session: Session,
    *,
    limit: int = 100,
    lease_seconds: int = 300,
) -> list[ComponentLease]:
    now = datetime.now(UTC)
    session.execute(
        update(SemanticComponentWorkItem)
        .where(
            SemanticComponentWorkItem.status == "running",
            SemanticComponentWorkItem.lease_until < now,
            SemanticComponentWorkItem.attempts >= SemanticComponentWorkItem.max_attempts,
        )
        .values(
            status="failed",
            lease_token=None,
            lease_until=None,
            next_retry_at=None,
            error="lease expired after maximum attempts",
            updated_at=now,
        )
    )
    eligible = or_(
        SemanticComponentWorkItem.status.in_(["pending", "retry"]),
        and_(
            SemanticComponentWorkItem.status == "running",
            SemanticComponentWorkItem.lease_until < now,
        ),
    )
    rows = list(
        session.execute(
            select(SemanticComponentWorkItem)
            .where(
                eligible,
                SemanticComponentWorkItem.completed_generation
                < SemanticComponentWorkItem.requested_generation,
                SemanticComponentWorkItem.attempts < SemanticComponentWorkItem.max_attempts,
                or_(
                    SemanticComponentWorkItem.next_retry_at.is_(None),
                    SemanticComponentWorkItem.next_retry_at <= now,
                ),
            )
            .order_by(SemanticComponentWorkItem.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    leases = []
    for row in rows:
        token = token_urlsafe(24)
        row.status = "running"
        row.lease_token = token
        row.lease_until = now + timedelta(seconds=lease_seconds)
        row.attempts += 1
        row.updated_at = now
        leases.append(
            ComponentLease(
                id=int(row.id),
                seed_atomic_id=int(row.seed_atomic_id),
                generation=int(row.requested_generation),
                attempts=int(row.attempts),
                lease_token=token,
            )
        )
    session.flush()
    return leases


def _current_atomic_ids(session: Session, atomic_ids: set[int]) -> set[int]:
    if not atomic_ids:
        return set()
    return {
        int(value)
        for value in session.execute(
            select(AtomicEvent.id)
            .join(Document, Document.id == AtomicEvent.document_id)
            .where(AtomicEvent.id.in_(atomic_ids), *current_document_conditions())
        ).scalars()
    }


def _component_closure(
    session: Session,
    seed_atomic_ids: set[int],
    *,
    max_atomic_events: int,
    max_edges: int,
) -> tuple[set[int], set[tuple[int, int]], dict[int, set[int]]]:
    """Close over old memberships and current same-event edges without global scans."""
    touched = set(seed_atomic_ids)
    frontier = set(seed_atomic_ids)
    processed: set[int] = set()
    old_component_ids: set[int] = set()
    old_members: dict[int, set[int]] = {}
    edges: set[tuple[int, int]] = set()

    while frontier:
        batch = frontier - processed
        if not batch:
            break
        processed.update(batch)

        component_ids = {
            int(value)
            for value in session.execute(
                select(SemanticRelationMembership.component_id).where(
                    SemanticRelationMembership.atomic_event_id.in_(batch),
                    SemanticRelationMembership.algorithm_version == RELATION_COMPONENT_VERSION,
                    SemanticRelationMembership.active.is_(True),
                )
            ).scalars()
        } - old_component_ids
        if component_ids:
            rows = session.execute(
                select(
                    SemanticRelationMembership.component_id,
                    SemanticRelationMembership.atomic_event_id,
                ).where(
                    SemanticRelationMembership.component_id.in_(component_ids),
                    SemanticRelationMembership.active.is_(True),
                )
            ).all()
            for component_id, atomic_id in rows:
                old_members.setdefault(int(component_id), set()).add(int(atomic_id))
                touched.add(int(atomic_id))
            old_component_ids.update(component_ids)

        current_batch = _current_atomic_ids(session, batch)
        if current_batch:
            remaining_edge_budget = max_edges - len(edges)
            if remaining_edge_budget <= 0:
                raise RuntimeError(f"relation component exceeds edge bound: {max_edges}")
            rows = session.execute(
                select(
                    RelationVerdict.left_atomic_id,
                    RelationVerdict.right_atomic_id,
                )
                .where(
                    RelationVerdict.decision == "same_event",
                    RelationVerdict.algorithm_version == RELATION_VERSION,
                    or_(
                        RelationVerdict.left_atomic_id.in_(current_batch),
                        RelationVerdict.right_atomic_id.in_(current_batch),
                    ),
                )
                .order_by(RelationVerdict.id)
                .limit(remaining_edge_budget + 1)
            ).all()
            if len(rows) > remaining_edge_budget:
                raise RuntimeError(f"relation component exceeds edge bound: {max_edges}")
            edge_atomic_ids = {
                int(value) for row in rows for value in (row.left_atomic_id, row.right_atomic_id)
            }
            current_edge_atoms = _current_atomic_ids(session, edge_atomic_ids)
            for row in rows:
                left, right = sorted((int(row.left_atomic_id), int(row.right_atomic_id)))
                if left in current_edge_atoms and right in current_edge_atoms:
                    edges.add((left, right))
                    touched.update((left, right))

        if len(touched) > max_atomic_events:
            raise RuntimeError(
                f"relation component exceeds atomic bound: {len(touched)} > {max_atomic_events}"
            )
        frontier = touched - processed

    return _current_atomic_ids(session, touched), edges, old_members


def _connected_groups(
    current_atomic_ids: set[int],
    edges: set[tuple[int, int]],
) -> list[set[int]]:
    parent: dict[int, int] = {}

    def find(value: int) -> int:
        parent.setdefault(value, value)
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for left, right in edges:
        if left in current_atomic_ids and right in current_atomic_ids:
            union(left, right)
    groups: dict[int, set[int]] = {}
    for atomic_id in parent:
        groups.setdefault(find(atomic_id), set()).add(atomic_id)
    return sorted(
        (group for group in groups.values() if len(group) >= 2),
        key=lambda group: min(group),
    )


def _assign_existing_components(
    groups: list[set[int]],
    old_members: dict[int, set[int]],
) -> dict[int, int]:
    candidates = []
    for group_index, group in enumerate(groups):
        for component_id, members in old_members.items():
            overlap = len(group & members)
            if overlap:
                candidates.append((-overlap, component_id, min(group), group_index))
    assigned_groups: set[int] = set()
    assigned_components: set[int] = set()
    assignments: dict[int, int] = {}
    for _negative_overlap, component_id, _minimum, group_index in sorted(candidates):
        if group_index in assigned_groups or component_id in assigned_components:
            continue
        assignments[group_index] = component_id
        assigned_groups.add(group_index)
        assigned_components.add(component_id)
    return assignments


def rebuild_component_closure(
    session: Session,
    seed_atomic_ids: set[int],
    *,
    max_atomic_events: int = 20000,
    max_edges: int | None = None,
) -> dict:
    """Locally rebuild affected components while preserving one stable ID per overlap."""
    if not seed_atomic_ids:
        return {"groups": 0, "changed": 0, "superseded": 0}
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"semantic-components:{RELATION_COMPONENT_VERSION}"},
    )
    current_ids, edges, old_members = _component_closure(
        session,
        seed_atomic_ids,
        max_atomic_events=max_atomic_events,
        max_edges=max_edges or max_atomic_events * 20,
    )
    groups = _connected_groups(current_ids, edges)
    assignments = _assign_existing_components(groups, old_members)
    old_component_ids = set(old_members)
    components = {
        int(row.id): row
        for row in session.execute(
            select(SemanticRelationComponent)
            .where(SemanticRelationComponent.id.in_(old_component_ids))
            .with_for_update()
        ).scalars()
    }
    now = datetime.now(UTC)
    assigned_component_ids = set(assignments.values())
    changed_component_ids = {
        component_id
        for group_index, component_id in assignments.items()
        if old_members.get(component_id, set()) != groups[group_index]
    }
    components_to_deactivate = (old_component_ids - assigned_component_ids) | changed_component_ids
    if components_to_deactivate:
        session.execute(
            update(SemanticRelationMembership)
            .where(
                SemanticRelationMembership.component_id.in_(components_to_deactivate),
                SemanticRelationMembership.active.is_(True),
            )
            .values(active=False, removed_at=now)
        )
    changed = 0
    active_component_ids: set[int] = set()

    for group_index, group in enumerate(groups):
        component_id = assignments.get(group_index)
        if component_id is None:
            component = SemanticRelationComponent(
                component_key=uuid4().hex,
                algorithm_version=RELATION_COMPONENT_VERSION,
                revision=1,
                status="active",
                member_count=len(group),
                updated_at=now,
            )
            session.add(component)
            session.flush()
            component_id = int(component.id)
            components[component_id] = component
            old_members[component_id] = set()
        else:
            component = components[component_id]
        active_component_ids.add(component_id)
        previous_members = old_members.get(component_id, set())
        if (
            previous_members == group
            and component.status == "active"
            and component.member_count == len(group)
        ):
            continue
        if previous_members:
            component.revision += 1
        component.status = "active"
        component.member_count = len(group)
        component.updated_at = now
        for atomic_id in sorted(group):
            session.add(
                SemanticRelationMembership(
                    component_id=component_id,
                    atomic_event_id=atomic_id,
                    algorithm_version=RELATION_COMPONENT_VERSION,
                    active=True,
                    added_at=now,
                )
            )
        changed += 1

    superseded = 0
    for component_id in old_component_ids - active_component_ids:
        component = components[component_id]
        if component.status != "superseded" or component.member_count != 0:
            component.status = "superseded"
            component.member_count = 0
            component.revision += 1
            component.updated_at = now
            superseded += 1
    session.flush()
    return {
        "groups": len(groups),
        "changed": changed,
        "superseded": superseded,
        "atoms": len(current_ids),
        "edges": len(edges),
    }


def complete_component_work(
    session: Session,
    lease: ComponentLease,
    *,
    max_atomic_events: int = 20000,
) -> dict:
    row = session.execute(
        select(SemanticComponentWorkItem)
        .where(
            SemanticComponentWorkItem.id == lease.id,
            SemanticComponentWorkItem.status == "running",
            SemanticComponentWorkItem.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        raise RuntimeError(f"semantic component lease lost: {lease.id}")
    result = rebuild_component_closure(
        session,
        {lease.seed_atomic_id},
        max_atomic_events=max_atomic_events,
    )
    row.completed_generation = max(row.completed_generation, lease.generation)
    row.status = "pending" if row.requested_generation > lease.generation else "succeeded"
    row.attempts = 0
    row.lease_token = None
    row.lease_until = None
    row.next_retry_at = None
    row.error = None
    row.updated_at = datetime.now(UTC)
    session.flush()
    return result


def fail_component_work(
    session: Session,
    lease: ComponentLease,
    error: Exception,
    *,
    retry_base_seconds: int = 30,
) -> bool:
    row = session.execute(
        select(SemanticComponentWorkItem)
        .where(
            SemanticComponentWorkItem.id == lease.id,
            SemanticComponentWorkItem.status == "running",
            SemanticComponentWorkItem.lease_token == lease.lease_token,
        )
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        return False
    now = datetime.now(UTC)
    terminal = row.attempts >= row.max_attempts
    row.status = "failed" if terminal else "retry"
    row.next_retry_at = (
        None
        if terminal
        else now + timedelta(seconds=min(3600, retry_base_seconds * 2 ** int(row.attempts)))
    )
    row.error = f"{type(error).__name__}: {error}"[:2000]
    row.lease_token = None
    row.lease_until = None
    row.updated_at = now
    session.flush()
    return True


def load_active_components(
    session: Session,
    *,
    limit: int = 1000,
) -> list[RelationComponent]:
    """Load complete, current materialized components without scanning verdict edges."""
    components = list(
        session.execute(
            select(SemanticRelationComponent)
            .where(
                SemanticRelationComponent.algorithm_version == RELATION_COMPONENT_VERSION,
                SemanticRelationComponent.status == "active",
                SemanticRelationComponent.member_count >= 2,
            )
            .order_by(SemanticRelationComponent.id)
            .limit(limit)
        ).scalars()
    )
    if not components:
        return []
    component_ids = [int(component.id) for component in components]
    rows = session.execute(
        select(
            SemanticRelationMembership.component_id,
            SemanticRelationMembership.atomic_event_id,
        )
        .join(AtomicEvent, AtomicEvent.id == SemanticRelationMembership.atomic_event_id)
        .join(Document, Document.id == AtomicEvent.document_id)
        .where(
            SemanticRelationMembership.component_id.in_(component_ids),
            SemanticRelationMembership.active.is_(True),
            *current_document_conditions(),
        )
        .order_by(SemanticRelationMembership.atomic_event_id)
    ).all()
    members: dict[int, list[int]] = {}
    for component_id, atomic_id in rows:
        members.setdefault(int(component_id), []).append(int(atomic_id))
    return [
        RelationComponent(
            id=int(component.id),
            component_key=component.component_key,
            revision=int(component.revision),
            atomic_ids=members[int(component.id)],
        )
        for component in components
        if len(members.get(int(component.id), [])) == int(component.member_count)
    ]


def run_component_stage(
    *,
    discovery_limit: int = 500,
    work_limit: int = 100,
    lease_seconds: int = 300,
    max_atomic_events: int = 20000,
) -> dict:
    """Discover invalidations, commit leases, then rebuild each seed transactionally."""
    from ai_security_hot.models.base import session_scope

    with session_scope() as session:
        missing = enqueue_missing_component_work(session, limit=discovery_limit)
        stale = enqueue_stale_component_work(session, limit=discovery_limit)
    with session_scope() as session:
        leases = claim_component_work(
            session,
            limit=work_limit,
            lease_seconds=lease_seconds,
        )
    changed = superseded = failed = 0
    for lease in leases:
        try:
            with session_scope() as session:
                result = complete_component_work(
                    session,
                    lease,
                    max_atomic_events=max_atomic_events,
                )
                changed += int(result["changed"])
                superseded += int(result["superseded"])
        except Exception as exc:
            failed += 1
            with session_scope() as session:
                fail_component_work(session, lease, exc)
            log.exception("semantic component rebuild failed: id=%s", lease.id)
    return {
        "missing_enqueued": missing,
        "stale_enqueued": stale,
        "claimed": len(leases),
        "changed": changed,
        "superseded": superseded,
        "failed": failed,
    }
