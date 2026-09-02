from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from Virus_Scan.models.profiles.persistence_snapshot import persisted_engine_profile_snapshot
from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.storage.contracts import DatabaseBackupArtifact
from Virus_Scan.storage.model_authority import AuthoritativeModelStateOwner
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleError, SQLiteLifecycleOwner


def _owner(tmp_path: Path) -> tuple[SQLiteLifecycleOwner, AuthoritativeModelStateOwner]:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    return lifecycle, AuthoritativeModelStateOwner(lifecycle)


def _profile(engine: str, *, updated: float = 0.0) -> dict[str, object]:
    value = default_engine_profile(engine)
    value["updated"] = updated
    return persisted_engine_profile_snapshot(value, expected_engine=engine)


def test_phase5_bootstrap_and_commit_activate_chained_tamper_evident_generation(
    tmp_path: Path,
) -> None:
    lifecycle, owner = _owner(tmp_path)
    bootstrap = owner.read_active_model_generation()
    assert bootstrap.previous_generation_id == ""
    assert bootstrap.previous_generation_manifest_hash == ""
    assert bootstrap.canonical_state_digest == owner._repository.canonical_model_state_digest(
        lifecycle.connection("model")
    )

    transaction_id = owner.commit(
        profiles=(_profile("renpy"),),
        transaction_kind="phase5_generation_commit",
        policy_identity="phase5_generation_test_policy_v1",
    )
    active = owner.read_active_model_generation()
    assert active.previous_generation_id == bootstrap.generation_id
    assert active.previous_generation_manifest_hash == bootstrap.manifest_sha256()
    assert active.promotion_transaction_id == transaction_id
    assert active.policy_identity == "phase5_generation_test_policy_v1"
    assert owner.read_model_generation(active.generation_id) == active
    pointer = lifecycle.connection("model").execute(
        "SELECT generation_id,promotion_transaction_id FROM active_model_generation WHERE singleton_id=1"
    ).fetchone()
    assert tuple(pointer) == (active.generation_id, transaction_id)
    lifecycle.close()


def test_phase5_generation_activation_failure_rolls_back_state_manifest_and_pointer(
    tmp_path: Path,
) -> None:
    lifecycle, owner = _owner(tmp_path)
    before = owner.read_active_model_generation()
    before_count = lifecycle.connection("model").execute(
        "SELECT count(*) FROM authoritative_transactions"
    ).fetchone()[0]
    connection = lifecycle.connection("model")
    connection.execute(
        "CREATE TRIGGER phase5_reject_active_generation_update "
        "BEFORE UPDATE ON active_model_generation BEGIN "
        "SELECT RAISE(ABORT, 'phase5_injected_activation_failure'); END"
    )
    with pytest.raises(Exception, match="phase5_injected_activation_failure"):
        owner.commit(
            profiles=(_profile("renpy"),),
            transaction_kind="phase5_generation_activation_failure",
        )
    connection.execute("DROP TRIGGER phase5_reject_active_generation_update")

    after = owner.read_active_model_generation()
    assert after == before
    assert owner.read_profile("renpy") is None
    assert lifecycle.connection("model").execute(
        "SELECT count(*) FROM authoritative_transactions"
    ).fetchone()[0] == before_count
    lifecycle.close()


def test_phase5_active_generation_detects_post_write_model_state_tamper(tmp_path: Path) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.commit(
        profiles=(_profile("renpy"),),
        transaction_kind="phase5_generation_tamper_fixture",
    )
    owner.read_active_model_generation()
    with lifecycle.transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET updated_value=? WHERE engine_id=? AND profile_scope='default'",
            (999.0, "renpy"),
        )
    with pytest.raises(SQLiteLifecycleError, match="active_model_generation_state_tampered"):
        owner.read_active_model_generation()
    lifecycle.close()


def test_phase5_known_good_backup_restores_exact_prior_generation_and_state(tmp_path: Path) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.commit(
        profiles=(_profile("renpy", updated=1.0),),
        transaction_kind="phase5_backup_generation_one",
    )
    generation_one = owner.read_active_model_generation()
    profile_one = owner.read_profile("renpy")
    backup = owner.create_known_good_backup()
    assert backup.kind == "model"
    assert backup.model_generation_id == generation_one.generation_id
    assert backup.model_generation_manifest_sha256 == generation_one.manifest_sha256()
    assert backup.canonical_state_digest == generation_one.canonical_state_digest

    owner.commit(
        profiles=(_profile("renpy", updated=2.0),),
        transaction_kind="phase5_backup_generation_two",
    )
    generation_two = owner.read_active_model_generation()
    assert generation_two.generation_id != generation_one.generation_id
    assert owner.read_profile("renpy") != profile_one

    restored = owner.restore_known_good_backup(backup)
    assert restored == generation_one
    assert owner.read_profile("renpy") == profile_one
    assert lifecycle.integrity_check("model").ok is True
    lifecycle.close()


def test_phase5_backup_digest_substitution_fails_before_restore(tmp_path: Path) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.commit(
        profiles=(_profile("renpy"),),
        transaction_kind="phase5_backup_substitution_fixture",
    )
    backup = owner.create_known_good_backup()
    bad = replace(backup, backup_sha256="0" * 64)
    active_before = owner.read_active_model_generation()
    with pytest.raises(SQLiteLifecycleError, match="sqlite_backup_restore_artifact_invalid"):
        owner.restore_known_good_backup(bad)
    assert owner.read_active_model_generation() == active_before
    lifecycle.close()


def test_phase5_backup_contract_rejects_model_identity_omission(tmp_path: Path) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.read_active_model_generation()
    generation = lifecycle.generation("model")
    with pytest.raises(ValueError, match="database_backup_model_generation_identity_invalid"):
        DatabaseBackupArtifact(
            kind="model",
            source_database_path=generation.path,
            backup_path=str(tmp_path / "bad.sqlite3"),
            backup_sha256="0" * 64,
            schema_version=generation.schema_version,
            schema_digest=generation.schema_digest,
            database_generation_id=generation.generation_id,
            created_ns=0,
        )
    lifecycle.close()


def test_phase5_precommit_rejects_existing_state_tamper_before_new_generation(
    tmp_path: Path,
) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.commit(
        profiles=(_profile("renpy", updated=1.0), _profile("media", updated=1.0)),
        transaction_kind="phase5_precommit_tamper_seed",
    )
    before = owner.read_active_model_generation()
    before_media = owner.read_profile("media")
    with lifecycle.transaction("model") as connection:
        connection.execute(
            "UPDATE profile_engines SET updated_value=? "
            "WHERE engine_id=? AND profile_scope='default'",
            (999.0, "renpy"),
        )
    with pytest.raises(SQLiteLifecycleError, match="active_model_generation_state_tampered"):
        owner.commit(
            profiles=(_profile("media", updated=2.0),),
            transaction_kind="phase5_precommit_tamper_rejected",
        )
    assert owner._repository.read_active_model_generation() == before
    assert owner.read_profile("media") == before_media
    lifecycle.close()


def test_phase5_active_generation_rejects_parent_manifest_chain_tamper(tmp_path: Path) -> None:
    lifecycle, owner = _owner(tmp_path)
    owner.commit(
        profiles=(_profile("renpy", updated=1.0),),
        transaction_kind="phase5_lineage_generation_one",
    )
    generation_one = owner.read_active_model_generation()
    owner.commit(
        profiles=(_profile("renpy", updated=2.0),),
        transaction_kind="phase5_lineage_generation_two",
    )
    with lifecycle.transaction("model") as connection:
        connection.execute(
            "UPDATE model_generation_manifests SET manifest_sha256=? WHERE generation_id=?",
            ("0" * 64, generation_one.generation_id),
        )
    with pytest.raises(SQLiteLifecycleError, match="active_model_generation_lineage_tampered"):
        owner.read_active_model_generation()
    lifecycle.close()
