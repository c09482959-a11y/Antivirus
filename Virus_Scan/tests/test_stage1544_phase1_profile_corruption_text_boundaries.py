from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.models.profiles import (
    configure_engine_profile_corruption_policy,
    profile_corruption_events_snapshot,
)
from Virus_Scan.models.profiles.corruption import (
    profile_corruption_evidence,
    profile_corruption_event_key,
    profile_corruption_json_safe,
    profile_corruption_type,
)
from Virus_Scan.models.profiles.quarantine import handle_invalid_engine_profile
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database


class HostileText:
    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw __repr__ should not be invoked")


class HostilePath:
    def __init__(self, value: str) -> None:
        self._value = value

    def __fspath__(self) -> str:
        return self._value

    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw path __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw path __repr__ should not be invoked")


class TextHolder:
    def __init__(self, text: str) -> None:
        self.text = text

    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw holder __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw holder __repr__ should not be invoked")


class BadFspath:
    def __fspath__(self) -> str:  # pragma: no cover - exercised via safe boundary
        raise RuntimeError("unreadable fspath")

    def __str__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw bad fspath __str__ should not be invoked")

    def __repr__(self) -> str:  # pragma: no cover - must not be reached
        raise RuntimeError("raw bad fspath __repr__ should not be invoked")


def test_stage1544_profile_corruption_json_safe_rejects_hostile_text_without_raw_stringification() -> None:
    first_key = HostileText()
    second_key = HostileText()
    payload = {
        first_key: HostileText(),
        second_key: {HostileText(): {"nested", HostileText()}},
        "schema_version": float("nan"),
    }

    safe = profile_corruption_json_safe(payload)

    assert "profile_corruption_text_unavailable:HostileText" in safe
    assert "profile_corruption_text_unavailable:HostileText#1" in safe
    assert safe["schema_version"] == {
        "profile_value_unavailable": True,
        "reason": "non_finite_profile_corruption_value",
        "value": "nan",
    }
    assert safe["profile_corruption_text_unavailable:HostileText"] == {
        "profile_value_unavailable": True,
        "reason": "unsupported_profile_corruption_value",
        "value_type": "HostileText",
    }
    json.dumps(safe, sort_keys=True, allow_nan=False)


def test_stage1544_profile_corruption_event_key_is_stable_for_hostile_profile() -> None:
    profile = {
        "schema_version": HostileText(),
        HostileText(): [HostileText(), BadFspath()],
        "engine": TextHolder("renpy"),
    }

    first_key = profile_corruption_event_key("renpy", profile, TextHolder("schema_version invalid"))
    second_key = profile_corruption_event_key("renpy", profile, TextHolder("schema_version invalid"))

    assert first_key == second_key
    assert len(first_key) == 16


def test_stage1544_profile_corruption_evidence_uses_detached_text_and_explicit_unavailable_values(tmp_path: Path) -> None:
    profile = {"schema_version": HostileText()}
    evidence = profile_corruption_evidence(
        HostilePath(str(tmp_path / "renpy.json")),
        TextHolder("renpy"),
        TextHolder("invalid profile schema_version from hostile object"),
        profile=profile,
        policy=TextHolder("quarantine"),
        quarantined=True,
        scan_continued=True,
    )
    record = evidence.to_json()

    assert record["engine"] == "renpy"
    assert record["profile_path"].endswith("renpy.json")
    assert record["profile_corruption_reason"] == "invalid profile schema_version from hostile object"
    assert record["profile_corruption_type"] == "schema_version"
    assert record["profile_corruption_policy"] == "quarantine"
    assert "profile_quarantine_path" not in record
    assert record["actual_schema_version"] == {
        "profile_value_unavailable": True,
        "reason": "unsupported_profile_corruption_value",
        "value_type": "HostileText",
    }
    json.dumps(record, sort_keys=True, allow_nan=False)


def test_stage1544_profile_corruption_type_does_not_call_raw_str_on_unsupported_reason() -> None:
    assert profile_corruption_type(HostileText()) == "schema_contract"
    assert profile_corruption_type(TextHolder("malformed JSON decode failed")) == "malformed_json"


def test_stage1544_quarantine_logging_uses_json_safe_actual_schema_without_raw_str(tmp_path: Path) -> None:
    profiles_dir = bind_profile_database(tmp_path)
    configure_engine_profile_corruption_policy("quarantine")

    with pytest.raises(ProfileSchemaInvariantError, match="invalid profile schema_version"):
        handle_invalid_engine_profile(
            "renpy",
            TextHolder("invalid profile schema_version from direct hostile profile"),
            profile={"schema_version": HostileText()},
        )

    evidence = profile_corruption_events_snapshot()[-1]
    assert evidence["profile_corruption_type"] == "schema_version"
    assert evidence["actual_schema_version"] == {
        "profile_value_unavailable": True,
        "reason": "unsupported_profile_corruption_value",
        "value_type": "HostileText",
    }
    assert evidence["scan_continued"] is False
    assert not list(profiles_dir.glob("*.json"))
    json.dumps(make_json_safe(evidence), sort_keys=True, allow_nan=False)


def test_stage1544_hard_fail_raises_sanitized_reason_without_raw_str(tmp_path: Path) -> None:
    profiles_dir = bind_profile_database(tmp_path)
    configure_engine_profile_corruption_policy("hard-fail")

    with pytest.raises(ProfileSchemaInvariantError) as exc_info:
        handle_invalid_engine_profile(
            "renpy",
            HostileText(),
            profile={"schema_version": HostileText()},
        )

    assert exc_info.value.args == ("profile_corruption_text_unavailable:HostileText",)
