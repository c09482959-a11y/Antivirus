"""Stage2742 regression coverage for pytest writable-state isolation."""
from __future__ import annotations

import hashlib
from pathlib import Path

from Virus_Scan.models.api.profile_persistence import flush_authoritative_model_state
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.config_state import get_profiles_dir
from Virus_Scan.storage import sqlite_lifecycle


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_stage2742_pytest_default_sqlite_authority_is_outside_live_worktree() -> None:
    configured = get_profiles_dir(None)
    assert type(configured) is str and configured != ""
    profiles_dir = Path(configured).resolve()
    assert not profiles_dir.is_relative_to(REPOSITORY_ROOT.resolve())
    assert sqlite_lifecycle().paths().profiles_dir == profiles_dir


def test_stage2742_final_model_flush_cannot_mutate_live_worktree_database() -> None:
    live_model = REPOSITORY_ROOT / "profiles" / "model_state.sqlite3"
    before = _sha256(live_model)
    configure_runtime_cluster_state(RuntimeClusterState())

    result = flush_authoritative_model_state(force=True)

    assert result["ok"] is True
    assert _sha256(live_model) == before
    configured = Path(get_profiles_dir(None) or "").resolve()
    assert (configured / "model_state.sqlite3").is_file()
    assert sqlite_lifecycle().paths().profiles_dir == configured
