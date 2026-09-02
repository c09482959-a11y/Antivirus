from pathlib import Path

import Virus_Scan.models.profiles as profiles
from Virus_Scan.models.profiles import replay_learning
from Virus_Scan.storage import DatabasePaths, authoritative_model_state
from Virus_Scan.tests.support.static_inventory import read_python_file


def test_stage1449_profile_replay_store_has_no_live_json_path_owner() -> None:
    assert not hasattr(profiles, "resolve_benign_candidate_store_path")
    assert not hasattr(replay_learning, "resolve_benign_candidate_store_path")
    assert "resolve_benign_candidate_store_path" not in profiles.__all__
    assert "resolve_benign_candidate_store_path" not in replay_learning.__all__


def test_stage1449_profile_package_does_not_publish_private_store_path_alias() -> None:
    assert "_benign_candidate_store_path" not in profiles.__all__
    assert "_benign_candidate_store_path" not in replay_learning.__all__
    assert not hasattr(profiles, "_benign_candidate_store_path")
    assert not hasattr(replay_learning, "_benign_candidate_store_path")


def test_stage1449_profile_replay_uses_authoritative_sqlite_boundary() -> None:
    replay_source = read_python_file(Path("Virus_Scan/models/profiles/replay_learning.py"))
    assert "learning_candidate_store" in replay_source
    assert "authoritative_model_state" not in replay_source
    assert "staged_benign_candidates.json" not in replay_source
    assert "write_profile_json" not in replay_source


def test_stage1449_database_paths_are_bounded_to_profiles_directory(tmp_path: Path) -> None:
    paths = DatabasePaths.from_profiles_dir(tmp_path / "profiles")
    authoritative_model_state().configure(paths.profiles_dir)
    assert paths.model_state.name == "model_state.sqlite3"
    assert paths.learning_candidates.name == "learning_candidates.sqlite3"
    assert paths.scan_cache.name == "scan_cache.sqlite3"
    assert paths.model_state.parent == paths.profiles_dir
    assert paths.learning_candidates.parent == paths.profiles_dir
