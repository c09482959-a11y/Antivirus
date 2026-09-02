from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.models.profiles.snapshots import default_engine_profile
from Virus_Scan.storage import (
    AuthoritativeModelStateOwner,
    ModelDatabaseGrowthPolicy,
    SQLiteLifecycleError,
    SQLiteLifecycleOwner,
)
from Virus_Scan.storage.model_maintenance import model_database_storage_bytes


def _authority(tmp_path: Path) -> tuple[SQLiteLifecycleOwner, AuthoritativeModelStateOwner]:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    return lifecycle, AuthoritativeModelStateOwner(lifecycle)


def _bounded_policy(**overrides: int) -> ModelDatabaseGrowthPolicy:
    values = {
        "report_bytes": 10**12,
        "prune_bytes": 10**12 + 1,
        "vacuum_bytes": 10**12 + 2,
        "abnormal_bytes": 10**12 + 3,
        "fail_closed_bytes": 10**12 + 4,
        "max_unreferenced_transactions": 2,
        "max_corruption_events_per_profile": 2,
        "max_retired_generations": 2,
        "max_occurrences_per_profile": 2,
        "max_model_events": 2,
        "incremental_vacuum_pages": 8,
    }
    values.update(overrides)
    return ModelDatabaseGrowthPolicy(**values)


def _corruption_event(index: int) -> dict[str, object]:
    return {
        "profile_corruption_event_key": f"{index:016x}",
        "engine": "renpy",
        "profile_corruption_type": "invalid_profile_schema",
        "profile_corruption_policy": "quarantine",
        "profile_quarantined": True,
        "scan_continued": True,
    }


def test_phase6_growth_policy_defaults_match_plan_thresholds() -> None:
    policy = ModelDatabaseGrowthPolicy()
    mib = 1024 * 1024
    assert (
        policy.report_bytes,
        policy.prune_bytes,
        policy.vacuum_bytes,
        policy.abnormal_bytes,
        policy.fail_closed_bytes,
    ) == (250 * mib, 400 * mib, 600 * mib, 750 * mib, 1024 * mib)


@pytest.mark.parametrize(
    "values,reason",
    [
        ((1, 1, 2, 3, 4), "model_database_growth_threshold_order_invalid"),
        ((0, 1, 2, 3, 4), "model_database_growth_threshold_invalid"),
    ],
)
def test_phase6_growth_policy_rejects_invalid_thresholds(
    values: tuple[int, ...], reason: str,
) -> None:
    with pytest.raises(ValueError, match=reason):
        ModelDatabaseGrowthPolicy(
            report_bytes=values[0], prune_bytes=values[1],
            vacuum_bytes=values[2], abnormal_bytes=values[3],
            fail_closed_bytes=values[4],
        )


def test_phase6_authoritative_history_is_bounded_without_deleting_current_commit(
    tmp_path: Path,
) -> None:
    lifecycle, authority = _authority(tmp_path)
    authority.configure_growth_policy(_bounded_policy(max_unreferenced_transactions=1))
    transaction_ids = tuple(
        authority.commit(transaction_kind=f"maintenance_probe_{index}")
        for index in range(4)
    )
    rows = lifecycle.connection("model").execute(
        "SELECT transaction_id FROM authoritative_transactions ORDER BY committed_ns,transaction_id"
    ).fetchall()
    assert len(rows) == 1
    assert str(rows[0][0]) == transaction_ids[-1]
    assert authority.read_transaction_trace(transaction_ids[-1]) is not None
    lifecycle.close()


def test_phase6_corruption_and_occurrence_history_use_configured_bounds(
    tmp_path: Path,
) -> None:
    lifecycle, authority = _authority(tmp_path)
    authority.configure_growth_policy(_bounded_policy())
    for index in range(5):
        authority.record_profile_corruption_event(event=_corruption_event(index))
    assert len(authority.read_profile_corruption_events(engine="renpy")) == 2

    occurrences = tuple({
        "engine": "renpy",
        "profile_scope": "default",
        "content_sha256": "a" * 64,
        "artifact_instance": f"/corpus/path-{index}.rpy",
        "context_identity": {"learning_baseline_key": "renpy/.rpy"},
        "decision_ordinal": index,
    } for index in range(5))
    authority.commit(
        profiles=(default_engine_profile("renpy"),),
        occurrences=occurrences,
        transaction_kind="bounded_occurrence_commit",
    )
    retained = authority.read_content_occurrences(
        engine="renpy", content_sha256="a" * 64,
    )
    assert len(retained) == 2
    assert {row["last_decision_ordinal"] for row in retained} == {3, 4}
    lifecycle.close()


def test_phase6_capacity_rejection_occurs_before_authoritative_mutation(
    tmp_path: Path,
) -> None:
    lifecycle, authority = _authority(tmp_path)
    authority.commit(transaction_kind="capacity_baseline")
    authority.maintain_database(force=True)
    authority.configure_growth_policy(ModelDatabaseGrowthPolicy(
        report_bytes=1,
        prune_bytes=2,
        vacuum_bytes=3,
        abnormal_bytes=4,
        fail_closed_bytes=5,
        incremental_vacuum_pages=8,
    ))
    before = lifecycle.connection("model").execute(
        "SELECT count(*) FROM authoritative_transactions"
    ).fetchone()[0]
    with pytest.raises(SQLiteLifecycleError, match="model_database_capacity_exceeded"):
        authority.commit(
            transaction_kind="capacity_rejected",
        )
    after = lifecycle.connection("model").execute(
        "SELECT count(*) FROM authoritative_transactions"
    ).fetchone()[0]
    assert after == before
    lifecycle.close()


def test_phase6_forced_maintenance_checkpoints_vacuums_and_checks_integrity(
    tmp_path: Path,
) -> None:
    lifecycle, authority = _authority(tmp_path)
    authority.commit(transaction_kind="maintenance_baseline")
    authority.configure_growth_policy(ModelDatabaseGrowthPolicy(
        report_bytes=1,
        prune_bytes=2,
        vacuum_bytes=3,
        abnormal_bytes=10**12,
        fail_closed_bytes=10**12 + 1,
        incremental_vacuum_pages=8,
    ))
    result = authority.maintain_database(force=True)
    assert result.checkpoint is not None
    assert result.vacuum_performed is True
    assert result.integrity_ok is True
    assert result.storage_bytes_after >= 0
    lifecycle.close()
