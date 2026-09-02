from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.models.profiles import (
    configure_engine_profile_corruption_policy, quarantine,
)
from Virus_Scan.models.profiles.corruption import profile_corruption_evidence
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.tests.support.sqlite_profile_state import bind_profile_database
from Virus_Scan.tests.support.static_inventory import read_python_file


class HostileValue:
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned text hook executed")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned repr hook executed")

    def __format__(self, spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned truthiness hook executed")

    def __eq__(self, other):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned equality hook executed")


class HostilePath(HostileValue):
    def __fspath__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned fspath hook executed")


def _reset() -> None:
    HostileValue.touched = 0
    HostilePath.touched = 0


def test_stage2023_profile_quarantine_logging_rejects_hostile_values_no_hook(
    tmp_path: Path, caplog,
) -> None:
    _reset()
    bind_profile_database(tmp_path)
    configure_engine_profile_corruption_policy("hard-fail")

    with pytest.raises(ProfileSchemaInvariantError):
        quarantine.handle_invalid_engine_profile(
            "renpy", HostileValue(), profile={"schema_version": HostileValue()},
        )

    assert HostileValue.touched == 0
    assert "profile_corruption_text_unavailable:HostileValue" in caplog.text
    event = quarantine.profile_corruption_events_snapshot()[-1]
    assert event["actual_schema_version"]["value_type"] == "HostileValue"


def test_stage2023_profile_corruption_path_uses_no_hook_path_text() -> None:
    _reset()

    record = profile_corruption_evidence(
        HostilePath(), "renpy", "schema", profile={"schema_version": 1},
    ).to_json()

    assert "profile_corruption_text_unavailable:HostilePath" in record["profile_path"]
    assert HostilePath.touched == 0


def test_stage2023_profile_quarantine_source_has_no_json_path_owner() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/quarantine.py"))

    assert "authoritative_model_state().replace_corrupt_profile" not in source
    assert "authoritative_model_state().record_profile_corruption_event" in source
    assert "def _profile_quarantine_path" not in source
    assert "def _log_profile_corruption" not in source
    assert ".invalid_schema" not in source
    assert "write_text(" not in source
