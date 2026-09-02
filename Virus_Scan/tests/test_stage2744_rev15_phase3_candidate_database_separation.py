from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.storage import (
    AuthoritativeModelStateOwner,
    DatabasePaths,
    LearningCandidateStoreOwner,
    SQLiteLifecycleOwner,
)
from Virus_Scan.storage.contracts import (
    CANDIDATE_DATABASE_FILENAME,
)
def test_stage2744_database_paths_expose_exact_three_sqlite_roles(tmp_path: Path) -> None:
    paths = DatabasePaths.from_profiles_dir(tmp_path / "profiles")
    assert paths.model_state.name == "model_state.sqlite3"
    assert paths.learning_candidates.name == "learning_candidates.sqlite3"
    assert paths.scan_cache.name == "scan_cache.sqlite3"
    assert paths.learning_candidates.parent == paths.profiles_dir
    assert paths.learning_candidates.parent.name == "profiles"


def test_stage2744_candidate_state_is_physically_absent_from_model_authority(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    candidates = LearningCandidateStoreOwner(lifecycle)
    staged = default_staged_benign_store()

    transaction_id = candidates.commit_staged_store(
        staged, transaction_kind="stage2744_candidate_fixture",
    )

    assert len(transaction_id) == 64
    assert candidates.read_staged_store() == staged
    assert lifecycle.integrity_check("candidate").ok is True
    assert lifecycle.generation("candidate").path.endswith(CANDIDATE_DATABASE_FILENAME)
    model_tables = {
        str(row[0]) for row in lifecycle.connection("model").execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    candidate_tables = {
        str(row[0]) for row in lifecycle.connection("candidate").execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    assert not any(name.startswith("staged_") for name in model_tables)
    assert {
        "staged_candidates", "staged_observations", "staged_rejections", "staged_metadata",
        "candidate_transactions",
    }.issubset(candidate_tables)
    assert "staged_store" not in inspect.signature(AuthoritativeModelStateOwner.commit).parameters
    lifecycle.close()


def test_stage2744_invalid_candidate_state_cannot_mutate_model_database(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    candidates = LearningCandidateStoreOwner(lifecycle)
    authority = AuthoritativeModelStateOwner(lifecycle)
    before = tuple(lifecycle.connection("model").iterdump())

    with pytest.raises(ValueError, match="candidate_store_record_invalid"):
        candidates.commit_staged_store(
            {"schema_version": "invalid"}, transaction_kind="invalid_candidate_fixture",
        )

    assert tuple(lifecycle.connection("model").iterdump()) == before
    assert authority.read_profile("renpy") is None
    lifecycle.close()
