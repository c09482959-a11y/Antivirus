from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.models.profiles import persistence
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state



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

    def values(self):  # pragma: no cover - must not execute
        return self._touch()


class HostileEngine:
    touched = 0

    def _touch(self):
        type(self).touched += 1
        raise AssertionError("caller-owned engine hook was invoked")

    def __str__(self):  # pragma: no cover - must not execute
        return self._touch()

    def __format__(self, _spec):  # pragma: no cover - must not execute
        return self._touch()

    def __eq__(self, _other):  # pragma: no cover - must not execute
        return self._touch()

    def __bool__(self):  # pragma: no cover - must not execute
        return self._touch()


def test_stage2023_profile_update_marker_rejects_hostile_mapping_values_without_hooks() -> None:
    HostileDict.touched = 0
    profile = {
        "extension_baselines": HostileDict({"x": {"files": 9}}),
        "model_state": {"learning_rejections": HostileDict({"risk_too_high": 3})},
    }

    assert persistence.profile_update_marker(profile) == 0.0
    assert HostileDict.touched == 0


def test_stage2023_profile_engine_paths_reject_hostile_engine_formatting(tmp_path: Path) -> None:
    HostileEngine.touched = 0
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    configure_profiles_dir(str(profiles_dir))
    profile_persistence_state().bind_profiles_dir(str(profiles_dir))

    profile = default_engine_profile("other")
    persistence.save_engine_profile(HostileEngine(), profile, force=True)

    assert (profiles_dir / "model_state.sqlite3").exists()
    assert not tuple(profiles_dir.glob("*.json"))
    assert persistence.load_engine_profile("other")["engine"] == "other"
    assert HostileEngine.touched == 0


def test_stage2023_profile_persistence_source_has_no_backlog_unsafe_reads() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/persistence.py"))

    assert ".values()" not in source
    assert "f'{engine}.json'" not in source
    assert 'f"{engine}.json"' not in source
