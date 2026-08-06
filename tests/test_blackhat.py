"""Black Hat connector + parser tests (pure, no network/DB).

Uses a small fixture mirroring the real sessions.json structure: a Briefings
session (kept), an Arsenal session (filtered out), and verifies content-hash
idempotency across polls.
"""

from __future__ import annotations

import json
from pathlib import Path

from ai_security_hot.config.sources import EndpointPolicy
from ai_security_hot.connectors.base import Checkpoint
from ai_security_hot.connectors.blackhat import BlackHatConnector
from ai_security_hot.domain.enums import ConnectorKind
from ai_security_hot.parsers.blackhat import BlackHatParser

_FIXTURE = {
    "sections": [
        {
            "label": "Wednesday | 10:15am",
            "date": "Wednesday",
            "sessions": [{"session_id": 56551}, {"session_id": 56552}],
        }
    ],
    "sessions": {
        "56551": {
            "id": 56551,
            "title": "Attacking and Defending AI Browsers",
            "program": "Black Hat USA 2026 Briefings",
            "track_1": "AI, ML & Data Science",
            "track_2": "Threat Hunting",
            "format": "Briefings",
            "duration": "40-Minute",
            "room": "South Seas C/D",
            "iso_start_date": "2026-08-06T10:15:00-07:00",
            "iso_end_date": "2026-08-06T10:55:00-07:00",
            "description": "<p><span>We attack and defend AI-powered browsers, "
            "demonstrating prompt-injection exfiltration.</span></p>",
            "takeaway": "1. AI browsers expand the prompt-injection surface.",
            "speakers": [{"person_id": 50311, "role": "Speaker"}],
            "public_tags": {"tag": [{"id": 51091, "name": "ON-DEMAND"}]},
        },
        "56552": {
            "id": 56552,
            "title": "OWASP EKS Goat",
            "program": "Black Hat USA 2026 Arsenal",  # should be filtered out
            "track_1": "Cloud Security",
            "format": "Major Update",
            "room": "Arsenal Station 8",
            "iso_start_date": "2026-08-06T11:00:00-07:00",
            "iso_end_date": "2026-08-06T11:20:00-07:00",
            "description": "<p>A vulnerable EKS environment for learning.</p>",
            "speakers": [],
        },
    },
    "speakers": [
        {"person_id": 50311, "first_name": "Jane", "last_name": "Doe", "company": "Example"}
    ],
}


def _policy(tmp_path: Path) -> EndpointPolicy:
    return EndpointPolicy.model_validate(
        {
            "id": "blackhat-test",
            "source_id": "blackhat",
            "connector": "playwright",
            "parser": "blackhat-v1",
            "url": "https://blackhat.com/us-26/briefings/schedule/",
            "egress": {"route": "direct"},
            "options": {"blackhat": {"data_file": str(tmp_path / "sessions.json")}},
        }
    )


def _write_fixture(tmp_path: Path) -> None:
    (tmp_path / "sessions.json").write_text(
        json.dumps(_FIXTURE, ensure_ascii=False), encoding="utf-8"
    )


def test_blackhat_connector_keeps_only_briefings(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    conn = BlackHatConnector(data_file=str(tmp_path / "sessions.json"))
    result = conn.poll(_policy(tmp_path), Checkpoint())
    # Only the Briefings session survives; Arsenal is filtered out.
    assert len(result.items) == 1
    item = result.items[0]
    assert item.native_id == "56551"
    assert item.connector_kind == ConnectorKind.PLAYWRIGHT
    assert item.raw_text is not None
    rec = json.loads(item.raw_text)
    assert rec["title"] == "Attacking and Defending AI Browsers"
    assert item.published_at is not None  # parsed from iso_start_date


def test_blackhat_connector_missing_file_is_noop(tmp_path: Path) -> None:
    # No sessions.json yet (playwright fetch hasn't run) → clean no-op, not error.
    conn = BlackHatConnector(data_file=str(tmp_path / "sessions.json"))
    result = conn.poll(_policy(tmp_path), Checkpoint())
    assert result.items == []
    assert result.not_modified is True


def test_blackhat_connector_content_hash_idempotent(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    conn = BlackHatConnector(data_file=str(tmp_path / "sessions.json"))
    policy = _policy(tmp_path)
    first = conn.poll(policy, Checkpoint())
    assert len(first.items) == 1
    # Second poll with known hashes → no re-emission (unchanged content).
    known = {first.items[0].native_id: first.items[0].content_hash}
    second = conn.poll(policy, Checkpoint(known_content_hashes=known))
    assert second.items == []


def test_blackhat_parser_maps_session_fields(tmp_path: Path) -> None:
    _write_fixture(tmp_path)
    conn = BlackHatConnector(data_file=str(tmp_path / "sessions.json"))
    result = conn.poll(_policy(tmp_path), Checkpoint())
    doc = BlackHatParser().parse(result.items[0])
    assert doc.title_original == "Attacking and Defending AI Browsers"
    assert doc.body_text is not None
    assert "prompt-injection" in doc.body_text  # HTML stripped, text kept
    assert doc.language == "en"
    assert doc.parse_quality >= 0.6
    assert doc.entities["tracks"] == ["AI, ML & Data Science", "Threat Hunting"]
    assert doc.entities["speaker_ids"] == ["50311"]
    assert doc.raw_metadata["room"] == "South Seas C/D"
    assert doc.published_at_utc is not None
