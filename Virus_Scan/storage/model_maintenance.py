"""Deterministic growth governance for the authoritative model database."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class ModelDatabaseGrowthPolicy:
    """Validated byte thresholds and relational history bounds."""

    report_bytes: int = 250 * _MIB
    prune_bytes: int = 400 * _MIB
    vacuum_bytes: int = 600 * _MIB
    abnormal_bytes: int = 750 * _MIB
    fail_closed_bytes: int = 1024 * _MIB
    max_unreferenced_transactions: int = 4096
    max_corruption_events_per_profile: int = 1024
    max_retired_generations: int = 64
    max_occurrences_per_profile: int = 4096
    max_model_events: int = 4096
    incremental_vacuum_pages: int = 1024

    def __post_init__(self) -> None:
        thresholds = (
            self.report_bytes,
            self.prune_bytes,
            self.vacuum_bytes,
            self.abnormal_bytes,
            self.fail_closed_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in thresholds):
            raise ValueError("model_database_growth_threshold_invalid")
        if thresholds != tuple(sorted(thresholds)) or len(set(thresholds)) != len(thresholds):
            raise ValueError("model_database_growth_threshold_order_invalid")
        limits = (
            self.max_unreferenced_transactions,
            self.max_corruption_events_per_profile,
            self.max_retired_generations,
            self.max_occurrences_per_profile,
            self.max_model_events,
            self.incremental_vacuum_pages,
        )
        if any(type(value) is not int or value <= 0 for value in limits):
            raise ValueError("model_database_growth_limit_invalid")


@dataclass(frozen=True, slots=True)
class ModelDatabasePruneResult:
    unreferenced_transactions: int
    corruption_events: int
    retired_generations: int
    content_occurrences: int
    model_events: int

    @property
    def total_rows(self) -> int:
        return (
            self.unreferenced_transactions
            + self.corruption_events
            + self.retired_generations
            + self.content_occurrences
            + self.model_events
        )

    def to_record(self) -> dict[str, int]:
        return {
            "unreferenced_transactions": self.unreferenced_transactions,
            "corruption_events": self.corruption_events,
            "retired_generations": self.retired_generations,
            "content_occurrences": self.content_occurrences,
            "model_events": self.model_events,
            "total_rows": self.total_rows,
        }


@dataclass(frozen=True, slots=True)
class ModelDatabaseMaintenanceResult:
    storage_bytes_before: int
    storage_bytes_after: int
    projected_growth_bytes: int
    level: str
    prune: ModelDatabasePruneResult
    checkpoint: tuple[int, int, int] | None
    integrity_ok: bool | None
    vacuum_performed: bool

    def to_record(self) -> dict[str, object]:
        return {
            "storage_bytes_before": self.storage_bytes_before,
            "storage_bytes_after": self.storage_bytes_after,
            "projected_growth_bytes": self.projected_growth_bytes,
            "level": self.level,
            "prune": self.prune.to_record(),
            "checkpoint": self.checkpoint,
            "integrity_ok": self.integrity_ok,
            "vacuum_performed": self.vacuum_performed,
        }


def model_database_storage_bytes(database_path: Path) -> int:
    """Return database, WAL, and shared-memory bytes for one SQLite authority."""
    if type(database_path) is not Path:
        database_path = Path(database_path)
    total = 0
    for path in (database_path, Path(str(database_path) + "-wal"), Path(str(database_path) + "-shm")):
        try:
            total += path.stat().st_size
        except FileNotFoundError:
            continue
    return total


def growth_level(size_bytes: int, policy: ModelDatabaseGrowthPolicy) -> str:
    if type(size_bytes) is not int or size_bytes < 0:
        raise ValueError("model_database_size_invalid")
    if size_bytes >= policy.fail_closed_bytes:
        return "fail_closed"
    if size_bytes >= policy.abnormal_bytes:
        return "abnormal"
    if size_bytes >= policy.vacuum_bytes:
        return "vacuum"
    if size_bytes >= policy.prune_bytes:
        return "prune"
    if size_bytes >= policy.report_bytes:
        return "report"
    return "normal"


def _delete_count(connection: object, statement: str, parameters: tuple[object, ...]) -> int:
    before = int(connection.total_changes)
    connection.execute(statement, parameters)
    return int(connection.total_changes) - before


def prune_model_history(
    connection: object, policy: ModelDatabaseGrowthPolicy, *,
    protected_transaction_ids: tuple[str, ...] = (),
) -> ModelDatabasePruneResult:
    """Prune only redundant history; replay/idempotency decisions remain durable."""
    if type(protected_transaction_ids) is not tuple or any(
        type(value) is not str or len(value) != 64 for value in protected_transaction_ids
    ):
        raise ValueError("model_database_protected_transaction_invalid")
    protected_clause = ""
    protected_parameters: tuple[object, ...] = ()
    if protected_transaction_ids:
        placeholders = ",".join("?" for _value in protected_transaction_ids)
        protected_clause = f"AND candidate.transaction_id NOT IN ({placeholders}) "
        protected_parameters = tuple(protected_transaction_ids)
    protected_unreferenced = 0
    if protected_transaction_ids:
        placeholders = ",".join("?" for _value in protected_transaction_ids)
        protected_unreferenced = int(connection.execute(
            "SELECT count(*) FROM authoritative_transactions AS candidate "
            f"WHERE candidate.transaction_id IN ({placeholders}) "
            "AND NOT EXISTS (SELECT 1 FROM learning_decisions AS decision "
            "WHERE decision.transaction_id=candidate.transaction_id)",
            protected_transaction_ids,
        ).fetchone()[0])
    retained_unreferenced = max(
        0, policy.max_unreferenced_transactions - protected_unreferenced,
    )
    transaction_statement = (
        "DELETE FROM authoritative_transactions WHERE transaction_id IN ("
        "SELECT transaction_id FROM authoritative_transactions AS candidate "
        "WHERE NOT EXISTS (SELECT 1 FROM learning_decisions AS decision "
        "WHERE decision.transaction_id=candidate.transaction_id) "
        + protected_clause
        + "ORDER BY committed_ns DESC,transaction_id DESC LIMIT -1 OFFSET ?)"
    )
    transactions = _delete_count(
        connection, transaction_statement,
        protected_parameters + (retained_unreferenced,),
    )
    corruption = _delete_count(
        connection,
        "DELETE FROM profile_corruption_events WHERE event_id IN ("
        "SELECT event_id FROM (SELECT event_id,ROW_NUMBER() OVER ("
        "PARTITION BY engine_id,profile_scope ORDER BY event_id DESC) AS ordinal "
        "FROM profile_corruption_events) WHERE ordinal>?)",
        (policy.max_corruption_events_per_profile,),
    )
    generations = _delete_count(
        connection,
        "DELETE FROM database_generations WHERE generation_id IN ("
        "SELECT generation_id FROM database_generations AS candidate "
        "WHERE status='retired' AND NOT EXISTS (SELECT 1 FROM profile_engines AS profile "
        "WHERE profile.generation_id=candidate.generation_id) "
        "ORDER BY created_ns DESC,generation_id DESC LIMIT -1 OFFSET ?)",
        (policy.max_retired_generations,),
    )
    occurrences = _delete_count(
        connection,
        "DELETE FROM content_artifact_occurrences WHERE rowid IN ("
        "SELECT rowid FROM (SELECT rowid,ROW_NUMBER() OVER ("
        "PARTITION BY engine_id,profile_scope ORDER BY last_decision_ordinal DESC,"
        "content_sha256,artifact_instance,model_context_digest) AS ordinal "
        "FROM content_artifact_occurrences) WHERE ordinal>?)",
        (policy.max_occurrences_per_profile,),
    )
    events = _delete_count(
        connection,
        "DELETE FROM model_events WHERE event_id IN (SELECT event_id FROM model_events "
        "ORDER BY event_id DESC LIMIT -1 OFFSET ?)",
        (policy.max_model_events,),
    )
    return ModelDatabasePruneResult(
        unreferenced_transactions=transactions,
        corruption_events=corruption,
        retired_generations=generations,
        content_occurrences=occurrences,
        model_events=events,
    )


EMPTY_MODEL_DATABASE_PRUNE_RESULT = ModelDatabasePruneResult(0, 0, 0, 0, 0)


__all__ = (
    "EMPTY_MODEL_DATABASE_PRUNE_RESULT",
    "ModelDatabaseGrowthPolicy",
    "ModelDatabaseMaintenanceResult",
    "ModelDatabasePruneResult",
    "growth_level",
    "model_database_storage_bytes",
    "prune_model_history",
)
