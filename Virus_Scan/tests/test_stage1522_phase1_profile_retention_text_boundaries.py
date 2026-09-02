from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.models.profiles.context import engine_extension_key, profile_context_container_root
from Virus_Scan.models.profiles.extension_learning import learn_extension_tags
from Virus_Scan.storage import DatabasePaths
from Virus_Scan.models.profiles.schema import (
    PROFILE_SCHEMA_VERSION,
    EngineProfileSchemaSnapshot,
)
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.models.retention import prune_counter_map


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.strip_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw caller __str__ was used
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves raw caller strip was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip was invoked")

    def __bool__(self):  # pragma: no cover - failure proves raw caller truthiness was used
        raise AssertionError("caller-owned bool was invoked")


def assert_not_probed(*values: HostileText) -> None:
    for value in values:
        assert value.strip_calls == 0


def test_stage1522_profile_schema_detaches_engine_text_before_strip_or_bool():
    engine = HostileText("RenPy")
    expected = HostileText("renpy")
    snapshot = EngineProfileSchemaSnapshot.from_profile(
        {
            "engine": engine,
            "schema_version": PROFILE_SCHEMA_VERSION,
            "extension_baselines": {},
            "model_state": {},
        },
        expected_engine=expected,
    )

    assert snapshot.engine == "renpy"
    assert type(snapshot.engine) is str
    assert snapshot.validate(expected_engine=expected) is True
    assert_not_probed(engine, expected)


def test_stage1522_sqlite_profiles_path_rejects_hostile_text_without_hooks(tmp_path):
    configured = HostileText(str(tmp_path / "profiles"))
    try:
        DatabasePaths.from_profiles_dir(configured)
    except ValueError as exc:
        assert str(exc) == "profiles_directory_required"
    else:
        raise AssertionError("hostile profiles path was accepted")
    assert_not_probed(configured)


def test_stage1522_profile_context_detaches_engine_and_path_text():
    engine = HostileText("RenPy")
    path = HostileText("game/script.rpy")

    assert profile_context_container_root(path) is None
    assert engine_extension_key(engine, path) == "renpy:.rpy"
    assert_not_probed(engine, path)


def test_stage1522_profile_retention_sort_keys_detach_hostile_text():
    first = HostileText("zeta")
    second = HostileText("alpha")
    counters = {first: 1, second: 2, "stable": 3}

    result = prune_counter_map(counters, 2)

    assert result is counters
    assert set(result.values()) == {2, 3}
    assert_not_probed(first, second)


def test_stage1522_extension_learning_detaches_tag_text_before_learning_counters():
    tag = HostileText(" custom_profile_tag ")
    baseline = default_extension_baseline(".rpy")

    learn_extension_tags(baseline, [tag])
    assert baseline["tags"] == {}
    assert_not_probed(tag)

    learn_extension_tags(baseline, physical_tag_evidence(("custom_profile_tag",)))
    assert "custom_profile_tag" in baseline["tags"]
