"""Single authoritative transaction owner for mutable model truth."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
from threading import RLock
import time

from Virus_Scan.storage.model_maintenance import (
    EMPTY_MODEL_DATABASE_PRUNE_RESULT,
    ModelDatabaseGrowthPolicy,
    ModelDatabaseMaintenanceResult,
    growth_level,
    model_database_storage_bytes,
    prune_model_history,
)
from Virus_Scan.storage.model_generation_contracts import ModelGenerationManifest
from Virus_Scan.storage.model_repository import ModelStateRepository
from Virus_Scan.storage.contracts import DatabaseBackupArtifact
from Virus_Scan.storage.sqlite_lifecycle import (
    SQLiteLifecycleError,
    SQLiteLifecycleOwner,
    sqlite_lifecycle,
)


_MODEL_APPLICATION_VERSION = "stage2758_11020_rev18_model_state_v1"
_MODEL_FEATURE_SCHEMA_IDENTITY = "model_state_relational_schema_v3"
_MODEL_DEPENDENCY_GRAPH_IDENTITY = "model_state_dependency_graph_v1"
_MODEL_BOOTSTRAP_POLICY_IDENTITY = "model_generation_bootstrap_v1"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _transaction_identity(
    *, transaction_kind: str, replay_key: str, state_digest: str,
) -> str:
    if replay_key:
        return hashlib.sha256(
            ("authoritative:" + transaction_kind + ":" + replay_key).encode("utf-8")
        ).hexdigest()
    return hashlib.sha256(
        ("authoritative:" + transaction_kind + ":" + state_digest).encode("utf-8")
    ).hexdigest()


class AuthoritativeModelStateOwner:
    """Own one physical commit across profiles and all runtime model domains."""

    def __init__(self, lifecycle: SQLiteLifecycleOwner | None = None) -> None:
        self._lifecycle = sqlite_lifecycle() if lifecycle is None else lifecycle
        self._repository = ModelStateRepository(self._lifecycle)
        self._lock = RLock()
        self._growth_policy = ModelDatabaseGrowthPolicy()

    def configure(self, profiles_dir: object) -> None:
        self._lifecycle.configure(profiles_dir)

    def configure_growth_policy(self, policy: ModelDatabaseGrowthPolicy) -> None:
        if type(policy) is not ModelDatabaseGrowthPolicy:
            raise TypeError("model_database_growth_policy_required")
        with self._lock:
            self._growth_policy = policy

    def growth_policy(self) -> ModelDatabaseGrowthPolicy:
        with self._lock:
            return self._growth_policy

    def _storage_bytes(self) -> int:
        return model_database_storage_bytes(self._lifecycle.paths().model_state)

    def maintain_database(
        self, *, force: bool = False, projected_growth_bytes: int = 0,
    ) -> ModelDatabaseMaintenanceResult:
        if type(force) is not bool:
            raise TypeError("model_database_maintenance_force_required")
        if type(projected_growth_bytes) is not int or projected_growth_bytes < 0:
            raise ValueError("model_database_projected_growth_invalid")
        with self._lock:
            policy = self._growth_policy
            before = self._storage_bytes()
            projected = before + projected_growth_bytes
            prune = EMPTY_MODEL_DATABASE_PRUNE_RESULT
            checkpoint: tuple[int, int, int] | None = None
            integrity_ok: bool | None = None
            vacuum_performed = False
            if force or projected >= policy.prune_bytes:
                with self._lifecycle.transaction("model") as connection:
                    prune = prune_model_history(connection, policy)
                checkpoint = self._lifecycle.checkpoint(
                    "model", mode="TRUNCATE" if projected >= policy.vacuum_bytes else "PASSIVE",
                )
                if projected >= policy.vacuum_bytes:
                    self._lifecycle.incremental_vacuum(
                        "model", pages=policy.incremental_vacuum_pages,
                    )
                    vacuum_performed = True
                    integrity_ok = self._lifecycle.integrity_check("model").ok
                    if not integrity_ok:
                        raise SQLiteLifecycleError("model_database_integrity_failed")
            after = self._storage_bytes()
            level = growth_level(after + projected_growth_bytes, policy)
            if level == "fail_closed":
                raise SQLiteLifecycleError("model_database_capacity_exceeded")
            return ModelDatabaseMaintenanceResult(
                storage_bytes_before=before,
                storage_bytes_after=after,
                projected_growth_bytes=projected_growth_bytes,
                level=level,
                prune=prune,
                checkpoint=checkpoint,
                integrity_ok=integrity_ok,
                vacuum_performed=vacuum_performed,
            )

    def _prepare_write(self, state: object) -> None:
        projected_growth = len(_canonical_json(state).encode("utf-8"))
        self.maintain_database(projected_growth_bytes=projected_growth)

    def _prune_within_transaction(
        self, connection: object, *, transaction_id: str,
    ) -> None:
        prune_model_history(
            connection, self._growth_policy,
            protected_transaction_ids=(transaction_id,),
        )

    @staticmethod
    def transaction_identity(
        *, transaction_kind: str, replay_key: str = "", state_digest: str = "",
    ) -> str:
        if type(transaction_kind) is not str or not transaction_kind:
            raise ValueError("authoritative_transaction_kind_invalid")
        if type(replay_key) is not str or (replay_key and len(replay_key) != 64):
            raise ValueError("authoritative_replay_key_invalid")
        if type(state_digest) is not str or (state_digest and len(state_digest) != 64):
            raise ValueError("authoritative_state_digest_invalid")
        if not replay_key and not state_digest:
            raise ValueError("authoritative_transaction_identity_source_required")
        return _transaction_identity(
            transaction_kind=transaction_kind, replay_key=replay_key,
            state_digest=state_digest,
        )

    def read_transaction_trace(
        self, transaction_id: str,
    ) -> dict[str, object] | None:
        return self._repository.read_transaction_trace(transaction_id)

    def read_profile(self, engine: str, *, profile_scope: str = "default") -> dict[str, object] | None:
        return self._repository.read_profile(engine, profile_scope=profile_scope)

    def find_learning_replay_key(
        self, *, engine: str, content_sha256: str,
        context_identity: Mapping[str, str], observation_digest: str,
        profile_scope: str = "default",
    ) -> str | None:
        return self._repository.find_learning_replay_key(
            engine=engine, profile_scope=profile_scope,
            content_sha256=content_sha256, context_identity=context_identity,
            observation_digest=observation_digest,
        )

    def read_content_occurrences(
        self, *, engine: str, content_sha256: str, profile_scope: str = "default",
    ) -> tuple[dict[str, object], ...]:
        return self._repository.read_content_occurrences(
            engine=engine, profile_scope=profile_scope,
            content_sha256=content_sha256,
        )

    def read_runtime_snapshot(self) -> dict[str, object] | None:
        return self._repository.read_runtime_snapshot()

    def read_profile_corruption_events(
        self, *, engine: str | None = None, profile_scope: str = "default",
    ) -> tuple[dict[str, object], ...]:
        return self._repository.read_profile_corruption_events(
            engine=engine, profile_scope=profile_scope,
        )

    def model_database_path(self) -> str:
        return str(self._lifecycle.paths().model_state)

    def _validate_active_generation_in_transaction(
        self, connection: object, manifest: ModelGenerationManifest,
    ) -> None:
        try:
            self._repository.validate_model_generation_lineage(
                manifest, connection=connection,
            )
            persisted_domains = self._repository.read_persisted_model_domain_digests(
                connection
            )
            actual_domains = self._repository.reconstruct_model_domain_digests()
            if actual_domains != persisted_domains:
                raise SQLiteLifecycleError("active_model_generation_state_tampered")
            current_digest = self._repository.canonical_domain_digest_map_digest(
                actual_domains
            )
            if current_digest != manifest.canonical_state_digest:
                raise SQLiteLifecycleError("active_model_generation_state_tampered")
        except ValueError as exc:
            raise SQLiteLifecycleError(
                "active_model_generation_lineage_tampered"
            ) from exc

    def _ensure_active_generation_in_transaction(
        self, connection: object, *, now_ns: int,
    ) -> ModelGenerationManifest:
        active = self._repository.read_active_model_generation(connection=connection)
        if active is not None:
            self._validate_active_generation_in_transaction(connection, active)
            return active
        persisted_domains = self._repository.read_persisted_model_domain_digests(connection)
        actual_domains = self._repository.reconstruct_model_domain_digests()
        if persisted_domains:
            if persisted_domains != actual_domains:
                raise SQLiteLifecycleError("model_generation_bootstrap_domain_digest_mismatch")
        else:
            for domain_identity, state_digest in sorted(actual_domains.items()):
                self._repository.write_model_domain_digest(
                    connection,
                    domain_identity=domain_identity,
                    state_digest=state_digest,
                    updated_ns=now_ns,
                )
        state_digest = self._repository.canonical_model_state_digest(connection)
        bootstrap_transaction_id = hashlib.sha256(
            ("model-generation-bootstrap:" + state_digest).encode("utf-8")
        ).hexdigest()
        manifest = ModelGenerationManifest.build(
            application_model_version=_MODEL_APPLICATION_VERSION,
            created_at_ns=now_ns,
            previous_generation_id="",
            previous_generation_manifest_hash="",
            canonical_state_digest=state_digest,
            promotion_transaction_id=bootstrap_transaction_id,
            feature_schema_identity=_MODEL_FEATURE_SCHEMA_IDENTITY,
            policy_identity=_MODEL_BOOTSTRAP_POLICY_IDENTITY,
            dependency_graph_identity=_MODEL_DEPENDENCY_GRAPH_IDENTITY,
            evaluation_release_identity="",
        )
        self._repository.write_model_generation_manifest(connection, manifest)
        self._repository.activate_model_generation(
            connection, manifest, activated_ns=now_ns,
        )
        return manifest

    def ensure_active_model_generation(self) -> ModelGenerationManifest:
        """Ensure a first immutable generation exists for valid current state."""
        with self._lock:
            with self._lifecycle.transaction("model") as connection:
                manifest = self._ensure_active_generation_in_transaction(
                    connection, now_ns=time.time_ns(),
                )
        return manifest

    def read_model_generation(
        self, generation_id: str,
    ) -> ModelGenerationManifest | None:
        return self._repository.read_model_generation_manifest(generation_id)

    def read_active_model_generation(
        self, *, validate_state: bool = True,
    ) -> ModelGenerationManifest:
        if type(validate_state) is not bool:
            raise TypeError("model_generation_validate_state_flag_required")
        with self._lock:
            manifest = self.ensure_active_model_generation()
            if validate_state:
                self._validate_active_generation_in_transaction(
                    self._lifecycle.connection("model"), manifest,
                )
        return manifest

    def create_known_good_backup(self) -> DatabaseBackupArtifact:
        """Create a SQLite-native backup bound to the active model generation."""
        with self._lock:
            manifest = self.read_active_model_generation(validate_state=True)
            artifact = self._lifecycle.create_known_good_backup(
                "model",
                model_generation_id=manifest.generation_id,
                model_generation_manifest_sha256=manifest.manifest_sha256(),
                canonical_state_digest=manifest.canonical_state_digest,
            )
        return artifact

    def restore_known_good_backup(
        self, artifact: DatabaseBackupArtifact,
    ) -> ModelGenerationManifest:
        """Restore and semantically validate one known-good authoritative backup."""
        if type(artifact) is not DatabaseBackupArtifact or artifact.kind != "model":
            raise TypeError("authoritative_model_backup_artifact_required")
        with self._lock:
            self._lifecycle.validate_known_good_backup(artifact)
            rollback = self.create_known_good_backup()
            try:
                self._lifecycle.restore_known_good_backup(
                    artifact, rollback_artifact=rollback,
                )
                restored = self._repository.read_active_model_generation()
                if restored is None:
                    raise SQLiteLifecycleError("restored_model_generation_missing")
                connection = self._lifecycle.connection("model")
                persisted_domains = self._repository.read_persisted_model_domain_digests(connection)
                actual_domains = self._repository.reconstruct_model_domain_digests()
                actual_state_digest = self._repository.canonical_domain_digest_map_digest(
                    actual_domains
                )
                if (
                    restored.generation_id != artifact.model_generation_id
                    or restored.manifest_sha256()
                    != artifact.model_generation_manifest_sha256
                    or restored.canonical_state_digest != artifact.canonical_state_digest
                    or actual_domains != persisted_domains
                    or actual_state_digest != artifact.canonical_state_digest
                ):
                    raise SQLiteLifecycleError("restored_model_generation_semantic_mismatch")
            except (OSError, ValueError, SQLiteLifecycleError) as exc:
                try:
                    self._lifecycle.restore_known_good_backup(
                        rollback, rollback_artifact=artifact,
                    )
                except (OSError, ValueError, SQLiteLifecycleError) as rollback_exc:
                    raise SQLiteLifecycleError(
                        "authoritative_model_restore_and_rollback_failed"
                    ) from rollback_exc
                raise SQLiteLifecycleError("authoritative_model_restore_failed") from exc
        return restored

    def _activate_generation_for_commit(
        self,
        connection: object,
        *,
        previous: ModelGenerationManifest,
        transaction_id: str,
        now_ns: int,
        policy_identity: str,
        feature_schema_identity: str,
        dependency_graph_identity: str,
        evaluation_release_identity: str,
        application_model_version: str,
    ) -> ModelGenerationManifest:
        state_digest = self._repository.canonical_model_state_digest(connection)
        manifest = ModelGenerationManifest.build(
            application_model_version=application_model_version,
            created_at_ns=now_ns,
            previous_generation_id=previous.generation_id,
            previous_generation_manifest_hash=previous.manifest_sha256(),
            canonical_state_digest=state_digest,
            promotion_transaction_id=transaction_id,
            feature_schema_identity=feature_schema_identity,
            policy_identity=policy_identity,
            dependency_graph_identity=dependency_graph_identity,
            evaluation_release_identity=evaluation_release_identity,
        )
        self._repository.write_model_generation_manifest(connection, manifest)
        self._repository.activate_model_generation(
            connection, manifest, activated_ns=now_ns,
        )
        return manifest

    def record_profile_corruption_event(
        self, *, event: Mapping[str, object], profile_scope: str = "default",
    ) -> str:
        state_digest = _digest({"event": event, "profile_scope": profile_scope})
        transaction_id = _transaction_identity(
            transaction_kind="profile_corruption", replay_key="",
            state_digest=state_digest,
        )
        now_ns = time.time_ns()
        with self._lock:
            self._prepare_write({"event": event, "profile_scope": profile_scope})
            with self._lifecycle.transaction("model") as connection:
                existing = connection.execute(
                    "SELECT state_digest,status FROM authoritative_transactions WHERE transaction_id=?",
                    (transaction_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing[0]) != state_digest or str(existing[1]) != "committed":
                        raise ValueError("authoritative_transaction_identity_conflict")
                    return transaction_id
                self._repository.write_profile_corruption_event(
                    connection, event, profile_scope=profile_scope, created_ns=now_ns,
                )
                connection.execute(
                    "INSERT INTO authoritative_transactions(transaction_id,transaction_kind,replay_key,"
                    "state_digest,created_ns,committed_ns,status) VALUES(?,?,?,?,?,?,?)",
                    (
                        transaction_id, "profile_corruption", "", state_digest,
                        now_ns, now_ns, "committed",
                    ),
                )
                self._prune_within_transaction(
                    connection, transaction_id=transaction_id,
                )
        return transaction_id

    @staticmethod
    def _write_domain_trace(
        connection: object, *, transaction_id: str, domain_kind: str,
        domain_identity: str, state: object,
    ) -> None:
        if type(domain_identity) is not str or not domain_identity or len(domain_identity) > 4096:
            raise ValueError("authoritative_domain_identity_invalid")
        connection.execute(
            "INSERT INTO authoritative_transaction_domains("
            "transaction_id,domain_kind,domain_identity,state_digest) VALUES(?,?,?,?)",
            (transaction_id, domain_kind, domain_identity, _digest(state)),
        )

    def commit(
        self, *, profiles: Sequence[Mapping[str, object]] = (),
        runtime_snapshot: Mapping[str, object] | None = None,
        occurrences: Sequence[Mapping[str, object]] = (),
        transaction_kind: str,
        replay_key: str = "",
        policy_identity: str = "",
        feature_schema_identity: str = _MODEL_FEATURE_SCHEMA_IDENTITY,
        dependency_graph_identity: str = _MODEL_DEPENDENCY_GRAPH_IDENTITY,
        evaluation_release_identity: str = "",
        application_model_version: str = _MODEL_APPLICATION_VERSION,
    ) -> str:
        if type(transaction_kind) is not str or not transaction_kind:
            raise ValueError("authoritative_transaction_kind_invalid")
        if type(replay_key) is not str or (replay_key and len(replay_key) != 64):
            raise ValueError("authoritative_replay_key_invalid")
        if type(profiles) not in (tuple, list):
            raise TypeError("authoritative_profiles_sequence_required")
        if type(occurrences) not in (tuple, list):
            raise TypeError("authoritative_occurrences_sequence_required")
        if type(policy_identity) is not str:
            raise TypeError("model_generation_policy_identity_required")
        if not policy_identity:
            policy_identity = "model_state_commit:" + transaction_kind
        for field_name, value, allow_empty in (
            ("feature_schema_identity", feature_schema_identity, False),
            ("dependency_graph_identity", dependency_graph_identity, False),
            ("evaluation_release_identity", evaluation_release_identity, True),
            ("application_model_version", application_model_version, False),
        ):
            if type(value) is not str or (not allow_empty and not value):
                raise ValueError("model_generation_" + field_name + "_invalid")
        state_record = {
            "profiles": list(profiles),
            "runtime_snapshot": runtime_snapshot,
            "occurrences": list(occurrences),
        }
        state_digest = _digest(state_record)
        transaction_id = self.transaction_identity(
            transaction_kind=transaction_kind, replay_key=replay_key,
            state_digest=state_digest,
        )
        now_ns = time.time_ns()
        with self._lock:
            self._prepare_write(state_record)
            with self._lifecycle.transaction("model") as connection:
                previous_generation = self._ensure_active_generation_in_transaction(
                    connection, now_ns=now_ns,
                )
                existing = connection.execute(
                    "SELECT state_digest,status FROM authoritative_transactions WHERE transaction_id=?",
                    (transaction_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing[0]) != state_digest or str(existing[1]) != "committed":
                        raise ValueError("authoritative_transaction_identity_conflict")
                    return transaction_id
                connection.execute(
                    "INSERT INTO authoritative_transactions(transaction_id,transaction_kind,replay_key,"
                    "state_digest,created_ns,committed_ns,status) VALUES(?,?,?,?,?,?,?)",
                    (
                        transaction_id, transaction_kind, replay_key, state_digest,
                        now_ns, now_ns, "committed",
                    ),
                )
                for profile in profiles:
                    self._repository.write_profile(connection, profile)
                    engine = profile.get("engine")
                    if type(engine) is not str or not engine:
                        raise ValueError("model_profile_identity_invalid")
                    persisted_profile = self._repository.read_profile(engine)
                    if persisted_profile is None:
                        raise ValueError("model_profile_persisted_state_missing")
                    profile_digest = _digest(persisted_profile)
                    self._repository.write_model_domain_digest(
                        connection,
                        domain_identity="profile:" + engine + ":default",
                        state_digest=profile_digest,
                        updated_ns=now_ns,
                    )
                    self._write_domain_trace(
                        connection, transaction_id=transaction_id,
                        domain_kind="profile", domain_identity=engine + ":default",
                        state=profile,
                    )
                if runtime_snapshot is not None:
                    self._repository.write_runtime_snapshot(connection, runtime_snapshot)
                    persisted_runtime_snapshot = self._repository.read_runtime_snapshot()
                    if persisted_runtime_snapshot is None:
                        raise ValueError("runtime_model_persisted_state_missing")
                    self._repository.write_model_domain_digest(
                        connection,
                        domain_identity="runtime_models:global",
                        state_digest=_digest(persisted_runtime_snapshot),
                        updated_ns=now_ns,
                    )
                    self._write_domain_trace(
                        connection, transaction_id=transaction_id,
                        domain_kind="runtime_models", domain_identity="global",
                        state=runtime_snapshot,
                    )
                for occurrence in occurrences:
                    self._repository.write_content_occurrence(connection, occurrence)
                    self._write_domain_trace(
                        connection, transaction_id=transaction_id,
                        domain_kind="content_occurrence",
                        domain_identity=(
                            str(occurrence.get("content_sha256", "")) + ":"
                            + str(occurrence.get("artifact_instance", ""))
                        ),
                        state=occurrence,
                    )
                self._prune_within_transaction(
                    connection, transaction_id=transaction_id,
                )
                if profiles or runtime_snapshot is not None:
                    self._activate_generation_for_commit(
                        connection,
                        previous=previous_generation,
                        transaction_id=transaction_id,
                        now_ns=now_ns,
                        policy_identity=policy_identity,
                        feature_schema_identity=feature_schema_identity,
                        dependency_graph_identity=dependency_graph_identity,
                        evaluation_release_identity=evaluation_release_identity,
                        application_model_version=application_model_version,
                    )
        return transaction_id


_AUTHORITY = AuthoritativeModelStateOwner()


def authoritative_model_state() -> AuthoritativeModelStateOwner:
    return _AUTHORITY


__all__ = ("AuthoritativeModelStateOwner", "authoritative_model_state")
