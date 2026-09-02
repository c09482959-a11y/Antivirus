from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import pytest

from Virus_Scan.models.profiles.schema import EngineProfileSchemaSnapshot, ProfileSchemaInvariantError



class HostileValue:
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __format__(self, _spec):  # pragma: no cover - must not execute
        return self._touch()

    def __int__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __eq__(self, _other):  # pragma: no cover - must not execute
        return self._touch()

    def __bool__(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileDict(dict):
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned mapping hook was invoked")

    def __iter__(self):  # pragma: no cover - must not execute
        return self._touch()

    def get(self, *_args, **_kwargs):  # pragma: no cover - must not execute
        return self._touch()

    def items(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_profile_schema_error_does_not_format_hostile_expected_engine() -> None:
    HostileValue.touched = 0

    with pytest.raises(ProfileSchemaInvariantError, match="other: profile must be an object"):
        EngineProfileSchemaSnapshot.from_profile(None, expected_engine=HostileValue())

    assert HostileValue.touched == 0


def test_stage2023_profile_schema_rejects_hostile_mapping_without_get_hooks() -> None:
    HostileDict.touched = 0

    with pytest.raises(ProfileSchemaInvariantError, match="renpy: profile must be an object"):
        EngineProfileSchemaSnapshot.from_profile(HostileDict({"engine": "renpy"}), expected_engine="renpy")

    assert HostileDict.touched == 0


def test_stage2023_profile_schema_rejects_hostile_schema_version_without_int_hook() -> None:
    HostileValue.touched = 0

    with pytest.raises(ProfileSchemaInvariantError, match="renpy: invalid profile schema_version"):
        EngineProfileSchemaSnapshot.from_profile(
            {
                "engine": "renpy",
                "schema_version": HostileValue(),
                "extension_baselines": {},
                "model_state": {},
            },
            expected_engine="renpy",
        )

    assert HostileValue.touched == 0


def test_stage2023_profile_schema_source_has_no_fstring_error_snippets() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/schema.py"))

    assert "ProfileSchemaInvariantError(f" not in source
    assert ".get('schema_version')" not in source
    assert "int(raw_schema)" not in source
