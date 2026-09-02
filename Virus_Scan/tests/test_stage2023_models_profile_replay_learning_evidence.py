from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from Virus_Scan.models.profiles import replay_learning
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.storage import learning_candidate_store
from Virus_Scan.tests.support.static_inventory import read_python_file


def _isolate_store(tmp_path: Path) -> Path:
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    configure_profiles_dir(profiles_dir)
    profile_persistence_state().bind_profiles_dir(str(profiles_dir))
    return profiles_dir


def test_stage2023_benign_candidate_commit_failure_propagates_and_keeps_dirty(tmp_path: Path) -> None:
    _isolate_store(tmp_path)
    store = default_staged_benign_store()
    state = profile_persistence_state()

    with patch.object(
        learning_candidate_store(), "commit_staged_store", side_effect=OSError("disk unavailable"),
    ), pytest.raises(OSError, match="disk unavailable"):
        replay_learning.save_benign_candidate_store(store)

    assert state.staged_dirty() is True


def test_stage2023_benign_candidate_flush_does_not_clear_dirty_on_commit_failure(tmp_path: Path) -> None:
    _isolate_store(tmp_path)
    state = profile_persistence_state()
    store = default_staged_benign_store()
    state.set_staged_cache(store, dirty=True)

    with patch.object(
        learning_candidate_store(), "commit_staged_store", side_effect=OSError("unit_test_save_failed"),
    ), pytest.raises(OSError, match="unit_test_save_failed"):
        replay_learning.flush_benign_candidate_store(force=True)

    assert state.staged_dirty() is True


def test_stage2023_profile_replay_learning_source_has_no_json_writer_or_false_sentinel() -> None:
    source = read_python_file(Path("Virus_Scan/models/profiles/replay_learning.py"))
    assert "write_profile_json" not in source
    assert "atomic_json_save" not in source
    assert "return False" not in source
    assert "if ok:" not in source
