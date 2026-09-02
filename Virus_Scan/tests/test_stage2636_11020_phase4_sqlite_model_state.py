from __future__ import annotations

import inspect
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

import pytest

from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_state_to_json,
)
from Virus_Scan.models.profiles.learning_transaction import execute_learning_transaction
from Virus_Scan.models.profiles.bootstrap import ensure_authoritative_engine_profiles
from Virus_Scan.models.profiles.replay_learning import get_benign_candidate_store
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.runtime.cluster_state import RuntimeClusterState, configure_runtime_cluster_state
from Virus_Scan.runtime.config_state import configure_profiles_dir
from Virus_Scan.runtime.profile_persistence_state import profile_persistence_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_request
from Virus_Scan.storage import (
    AuthoritativeModelStateOwner,
    LearningCandidateStoreOwner,
    ModelStateRepository,
    authoritative_model_state,
    learning_candidate_store,
    SQLiteLifecycleOwner,
)
from Virus_Scan.storage.candidate_repository import LearningCandidateRepository


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def _owner(tmp_path: Path) -> SQLiteLifecycleOwner:
    owner = SQLiteLifecycleOwner()
    owner.configure(tmp_path / "profiles")
    return owner


def _runtime_snapshot() -> dict[str, object]:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )
    configure_runtime_cluster_state(RuntimeClusterState())
    snapshot = runtime_model_state_to_json()
    assert type(snapshot) is dict
    return snapshot


def _isolate_learning_runtime(tmp_path: Path) -> Path:
    profiles = tmp_path / "profiles"
    configure_profiles_dir(str(profiles))
    state = profile_persistence_state()
    state.bind_profiles_dir(str(profiles))
    state.set_staged_cache(default_staged_benign_store(), dirty=False)
    _runtime_snapshot()
    ensure_authoritative_engine_profiles()
    return profiles


def test_phase4_runtime_and_candidate_state_round_trip_without_semantic_loss(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    candidates = LearningCandidateRepository(owner)
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()

    with owner.transaction("model") as connection:
        repository.write_runtime_snapshot(connection, runtime)
    with owner.transaction("candidate") as connection:
        candidates.write_staged_store(connection, staged)

    assert _canonical(repository.read_runtime_snapshot()) == _canonical(runtime)
    assert candidates.read_staged_store() == staged
    model_tables = {
        str(row[0]) for row in owner.connection("model").execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    assert not any(name.startswith("staged_") for name in model_tables)
    owner.close()


def test_phase4_runtime_replay_domains_survive_when_empty(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    runtime = _runtime_snapshot()
    assert runtime["learning_applied_keys"] == {"filetype": (), "markov": ()}

    with owner.transaction("model") as connection:
        repository.write_runtime_snapshot(connection, runtime)

    loaded = repository.read_runtime_snapshot()
    assert loaded is not None
    assert loaded["learning_applied_keys"] == {"filetype": [], "markov": []}
    owner.close()


def test_phase4_model_and_candidate_transactions_roll_back_within_their_owners(tmp_path: Path) -> None:
    owner = _owner(tmp_path)
    repository = ModelStateRepository(owner)
    candidates = LearningCandidateRepository(owner)
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()

    with pytest.raises(RuntimeError, match="forced_phase4_failure"):
        with owner.transaction("model") as connection:
            repository.write_runtime_snapshot(connection, runtime)
            raise RuntimeError("forced_phase4_failure")
    with pytest.raises(RuntimeError, match="forced_phase4_candidate_failure"):
        with owner.transaction("candidate") as connection:
            candidates.write_staged_store(connection, staged)
            raise RuntimeError("forced_phase4_candidate_failure")

    assert owner.connection("model").execute(
        "SELECT count(*) FROM runtime_model_metadata"
    ).fetchone()[0] == 0
    assert owner.connection("candidate").execute(
        "SELECT count(*) FROM staged_metadata"
    ).fetchone()[0] == 0
    owner.close()


def test_phase4_authority_excludes_candidate_state_from_model_transaction(tmp_path: Path) -> None:
    lifecycle = _owner(tmp_path)
    authority = AuthoritativeModelStateOwner(lifecycle)
    candidate_owner = LearningCandidateStoreOwner(lifecycle)
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()
    profile = default_engine_profile("renpy")
    occurrence = {
        "engine": "renpy", "profile_scope": "default",
        "content_sha256": "c" * 64,
        "artifact_instance": "/corpus/first/script.rpy",
        "context_identity": {"learning_baseline_key": "renpy/.rpy"},
        "decision_ordinal": 7,
    }
    candidate_transaction_id = candidate_owner.commit_staged_store(
        staged, transaction_kind="test_candidate_state",
    )
    transaction_id = authority.commit(
        profiles=(profile,), runtime_snapshot=runtime, occurrences=(occurrence,),
        transaction_kind="learning_commit", replay_key="a" * 64,
    )

    assert len(transaction_id) == 64 and len(candidate_transaction_id) == 64
    assert authority.read_profile("renpy") == profile
    assert _canonical(authority.read_runtime_snapshot()) == _canonical(runtime)
    assert candidate_owner.read_staged_store() == staged
    occurrences = authority.read_content_occurrences(engine="renpy", content_sha256="c" * 64)
    assert len(occurrences) == 1
    assert not any(
        str(row[0]).startswith("staged_")
        for row in lifecycle.connection("model").execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    )
    lifecycle.close()


def test_phase4_invalid_candidate_state_cannot_mutate_model_authority(tmp_path: Path) -> None:
    lifecycle = _owner(tmp_path)
    authority = AuthoritativeModelStateOwner(lifecycle)
    candidate_owner = LearningCandidateStoreOwner(lifecycle)
    invalid_staged = {"schema_version": 1}

    with pytest.raises(ValueError):
        candidate_owner.commit_staged_store(
            invalid_staged, transaction_kind="invalid_candidate_state",
        )

    connection = lifecycle.connection("model")
    assert connection.execute("SELECT count(*) FROM profile_engines").fetchone()[0] == 0
    assert connection.execute("SELECT count(*) FROM runtime_model_metadata").fetchone()[0] == 0
    assert connection.execute("SELECT count(*) FROM authoritative_transactions").fetchone()[0] == 0
    lifecycle.close()


def test_phase4_superseded_runtime_model_json_owner_is_absent() -> None:
    jsonio_source = Path("Virus_Scan/core/jsonio.py").read_text(encoding="utf-8")
    init_source = Path(
        "Virus_Scan/models/init_parts/profile_and_learning_store_init.py"
    ).read_text(encoding="utf-8")
    snapshot_source = Path(
        "Virus_Scan/models/clustering/snapshots.py"
    ).read_text(encoding="utf-8")

    assert "def flush_runtime_model_state" not in jsonio_source
    assert "runtime_models.json" not in jsonio_source
    assert "RUNTIME_MODEL_STATE_PATH" not in init_source
    assert "runtime_models.json" not in init_source
    assert "def load_runtime_model_state" not in snapshot_source
    assert "def import_runtime_model_snapshot" not in snapshot_source
    assert "json.load" not in snapshot_source


def test_phase4_cluster_runtime_hydration_has_no_json_import_recall() -> None:
    lifecycle_source = Path("Virus_Scan/orchestration/lifecycle.py").read_text(encoding="utf-8")
    loader_source = Path(
        "Virus_Scan/orchestration/model_state_loader.py"
    ).read_text(encoding="utf-8")

    assert "import_runtime_model_snapshot" not in lifecycle_source
    assert "import_cluster_runtime_model_snapshot" not in lifecycle_source
    assert "authoritative_model_state().read_runtime_snapshot()" in loader_source
    assert "load_cluster_runtime_model_record" in loader_source


def test_phase4_profile_and_staged_json_bootstrap_owners_are_absent() -> None:
    routing_source = Path("Virus_Scan/routing/engine_detect.py").read_text(encoding="utf-8")
    lifecycle_source = Path("Virus_Scan/orchestration/lifecycle.py").read_text(encoding="utf-8")
    config_source = Path("Virus_Scan/runtime/config_state.py").read_text(encoding="utf-8")
    init_source = Path(
        "Virus_Scan/models/init_parts/profile_and_learning_store_init.py"
    ).read_text(encoding="utf-8")

    assert "ensure_profiles_exist" not in routing_source
    assert "atomic_json_save" not in routing_source
    assert "ensure_authoritative_engine_profiles()" in lifecycle_source
    assert "benign_candidate_store_path" not in config_source
    assert "BENIGN_CANDIDATE_STORE_PATH" not in init_source
    assert "staged_benign_candidates.json" not in init_source


def test_phase4_real_learning_commit_has_one_authoritative_transaction_identity(
    tmp_path: Path,
) -> None:
    _isolate_learning_runtime(tmp_path)
    sample = tmp_path / "game" / "script.rpy"
    sample.parent.mkdir(parents=True)
    sample.write_text("label start:\n    return\n", encoding="utf-8")
    request = accepted_learning_request(
        sample, flow=("asset", "runtime"),
        observation_id="phase4-authoritative-transaction-trace",
    )

    result = execute_learning_transaction(request, get_benign_candidate_store())

    assert result["learned"] is True
    transaction_id = result["transaction_id"]
    assert type(transaction_id) is str and len(transaction_id) == 64
    authority = authoritative_model_state()
    profile = authority.read_profile("renpy")
    assert profile is not None
    transaction = profile["model_state"]["learning_transactions"][
        request.decision.replay_key
    ]
    assert transaction["authoritative_transaction_id"] == transaction_id
    trace = authority.read_transaction_trace(transaction_id)
    assert trace is not None
    assert trace["transaction_kind"] == "learning_commit"
    assert trace["replay_key"] == request.decision.replay_key
    assert trace["status"] == "committed"
    assert trace["learning_decision"] == {
        "replay_key": request.decision.replay_key,
        "engine": "renpy",
        "profile_scope": "default",
        "status": "complete",
        "transaction_sha256": trace["learning_decision"]["transaction_sha256"],
    }
    assert {
        row["domain_kind"] for row in trace["domains"]
    } == {"profile", "runtime_models", "content_occurrence"}


def test_phase4_forced_failure_in_each_domain_rolls_back_every_domain(
    tmp_path: Path,
) -> None:
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()
    profile = default_engine_profile("renpy")
    occurrence = {
        "engine": "renpy", "profile_scope": "default",
        "content_sha256": "d" * 64,
        "artifact_instance": "/corpus/failure/script.rpy",
        "context_identity": {"learning_baseline_key": "renpy/.rpy"},
        "decision_ordinal": 8,
    }
    failure_tables = (
        "profile_engines", "runtime_model_metadata", "content_artifact_occurrences",
    )
    for ordinal, table in enumerate(failure_tables):
        lifecycle = _owner(tmp_path / str(ordinal))
        authority = AuthoritativeModelStateOwner(lifecycle)
        connection = lifecycle.connection("model")
        connection.execute(
            f"CREATE TEMP TRIGGER forced_domain_failure BEFORE INSERT ON main.{table} "
            "BEGIN SELECT RAISE(ABORT,'forced_phase4_domain_failure'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="forced_phase4_domain_failure"):
            authority.commit(
                profiles=(profile,), runtime_snapshot=runtime, occurrences=(occurrence,),
                transaction_kind="learning_commit", replay_key=chr(97 + ordinal) * 64,
            )
        for persisted_table in (
            "authoritative_transactions", "authoritative_transaction_domains",
            "profile_engines", "runtime_model_metadata", "content_artifact_occurrences",
        ):
            assert connection.execute(
                f"SELECT count(*) FROM {persisted_table}"
            ).fetchone()[0] == 0
        lifecycle.close()


def test_phase4_restart_reproduces_committed_state_and_trace(tmp_path: Path) -> None:
    profiles = tmp_path / "profiles"
    first_lifecycle = SQLiteLifecycleOwner()
    first_lifecycle.configure(profiles)
    first_authority = AuthoritativeModelStateOwner(first_lifecycle)
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()
    profile = default_engine_profile("renpy")
    first_candidates = LearningCandidateStoreOwner(first_lifecycle)
    first_candidates.commit_staged_store(staged, transaction_kind="phase4_restart_candidate")
    transaction_id = first_authority.commit(
        profiles=(profile,), runtime_snapshot=runtime,
        transaction_kind="phase4_restart", replay_key="f" * 64,
    )
    expected_trace = first_authority.read_transaction_trace(transaction_id)
    first_lifecycle.close()

    second_lifecycle = SQLiteLifecycleOwner()
    second_lifecycle.configure(profiles)
    second_authority = AuthoritativeModelStateOwner(second_lifecycle)
    assert second_authority.read_profile("renpy") == profile
    assert _canonical(second_authority.read_runtime_snapshot()) == _canonical(runtime)
    assert LearningCandidateStoreOwner(second_lifecycle).read_staged_store() == staged
    assert second_authority.read_transaction_trace(transaction_id) == expected_trace
    second_lifecycle.close()


def _authoritative_commit_fixture() -> tuple[
    tuple[dict[str, object], ...],
    dict[str, object],
    dict[str, object],
    tuple[dict[str, object], ...],
]:
    runtime = _runtime_snapshot()
    staged = default_staged_benign_store()
    profile = default_engine_profile("renpy")
    occurrence = {
        "engine": "renpy",
        "profile_scope": "default",
        "content_sha256": "e" * 64,
        "artifact_instance": "/corpus/statement-failure/script.rpy",
        "context_identity": {"learning_baseline_key": "renpy/.rpy"},
        "decision_ordinal": 9,
    }
    return (profile,), runtime, staged, (occurrence,)


def _database_dump(connection: sqlite3.Connection) -> tuple[str, ...]:
    return tuple(connection.iterdump())


def _write_authorizer_events(tmp_path: Path) -> tuple[tuple[int, str, str], ...]:
    lifecycle = _owner(tmp_path)
    authority = AuthoritativeModelStateOwner(lifecycle)
    profiles, runtime, staged, occurrences = _authoritative_commit_fixture()
    connection = lifecycle.connection("model")
    events: list[tuple[int, str, str]] = []
    write_actions = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}

    def authorizer(
        action: int,
        object_name: str | None,
        column_name: str | None,
        database_name: str | None,
        trigger_name: str | None,
    ) -> int:
        del trigger_name
        if action in write_actions and database_name == "main":
            events.append((action, object_name or "", column_name or ""))
        return sqlite3.SQLITE_OK

    connection.set_authorizer(authorizer)
    LearningCandidateStoreOwner(lifecycle).commit_staged_store(
        staged, transaction_kind="phase4_statement_inventory_candidate",
    )
    authority.commit(
        profiles=profiles, runtime_snapshot=runtime, occurrences=occurrences,
        transaction_kind="phase4_statement_inventory",
        replay_key="g" * 64,
    )
    connection.set_authorizer(None)
    lifecycle.close()
    assert events
    return tuple(events)


def test_phase4_every_authoritative_sqlite_write_event_rolls_back_exactly(
    tmp_path: Path,
) -> None:
    events = _write_authorizer_events(tmp_path / "inventory")
    write_actions = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}

    for denied_index, expected_event in enumerate(events):
        lifecycle = _owner(tmp_path / f"failure-{denied_index:03d}")
        authority = AuthoritativeModelStateOwner(lifecycle)
        profiles, runtime, staged, occurrences = _authoritative_commit_fixture()
        connection = lifecycle.connection("model")
        before = _database_dump(connection)
        current_index = -1
        observed: list[tuple[int, str, str]] = []

        def authorizer(
            action: int,
            object_name: str | None,
            column_name: str | None,
            database_name: str | None,
            trigger_name: str | None,
        ) -> int:
            nonlocal current_index
            del trigger_name
            if action in write_actions and database_name == "main":
                current_index += 1
                event = (action, object_name or "", column_name or "")
                observed.append(event)
                if current_index == denied_index:
                    return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorizer)
        with pytest.raises(sqlite3.DatabaseError):
            authority.commit(
                profiles=profiles, runtime_snapshot=runtime, occurrences=occurrences,
                transaction_kind="phase4_statement_failure",
                replay_key=f"{denied_index:064x}",
            )
        connection.set_authorizer(None)
        assert observed[denied_index] == expected_event
        assert _database_dump(connection) == before
        lifecycle.close()
