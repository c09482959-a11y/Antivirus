"""Typed authoritative model-state repository through the lifecycle owner."""
from __future__ import annotations

from Virus_Scan.contracts.runtime_model_state import (
    RUNTIME_MODEL_STATE_SCHEMA_VERSION,
    runtime_model_state_envelope_error,
)

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.storage.model_generation_contracts import (
    ModelGenerationManifest,
    canonical_record_sha256,
)
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleOwner, sqlite_lifecycle

_PROFILE_SCOPE_DEFAULT = "default"
_EXTENSION_SECTION_TABLES = MappingProxyType({
    "behavior_buckets": "profile_extension_behavior_buckets",
    "tags": "profile_extension_tags",
    "tag_evidence": "profile_extension_tag_evidence",
    "chains": "profile_extension_chains",
    "timeline_baseline": "profile_extension_timeline",
    "risk": "profile_extension_risk",
    "learning_gate": "profile_extension_learning_gate",
    "vector_baseline": "profile_extension_vector",
})
_MODEL_MAP_TABLES = MappingProxyType({
    "vector_baselines": "profile_vector_baselines",
    "temporal_baselines": "profile_temporal_baselines",
    "markov_baselines": "profile_markov_baselines",
    "cluster_baselines": "profile_cluster_baselines",
    "learning_rejections": "profile_learning_rejections",
    "learning_applied_keys": "profile_learning_applied_keys",
})

_MODEL_STATE_DOMAIN_METADATA_PREFIX = "model_state_domain_digest:"
_MODEL_SINGLETON_TABLES = MappingProxyType({
    "contamination": "profile_contamination_state",
    "decision_history": "profile_decision_history_state",
})


def _canonical_json(value: object) -> tuple[str, str]:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _schema_identity(value: object, fallback: str) -> str:
    if type(value) is dict:
        schema = value.get("schema_version")
        if type(schema) in (str, int) and str(schema):
            return str(schema)
    return fallback


def _state_map(value: object, field: str) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"model_profile_{field}_invalid")
    if any(type(key) is not str or not key for key in value):
        raise ValueError(f"model_profile_{field}_key_invalid")
    return value


def _decision_context(decision: object) -> dict[str, str]:
    if type(decision) is not dict:
        return {}
    rows = decision.get("context_identity")
    if type(rows) not in (list, tuple):
        return {}
    result: dict[str, str] = {}
    for row in rows:
        if type(row) not in (list, tuple) or len(row) != 2:
            continue
        key, value = row
        if type(key) is str and key and type(value) is str:
            result[key] = value
    return result


def _content_identity(context: Mapping[str, str]) -> tuple[str, str]:
    value = context.get("content_sha256", "")
    if len(value) == 64 and all(character in "0123456789abcdef" for character in value):
        return value, "verified"
    artifact = context.get("artifact_identity", "")
    if artifact.startswith("sha256:"):
        digest = artifact[7:]
        if len(digest) == 64 and all(character in "0123456789abcdef" for character in digest):
            return digest, "verified"
    return "", "unavailable"


def _validate_profile_storage_record(profile: object) -> Mapping[str, object]:
    if not isinstance(profile, Mapping):
        raise ValueError("model_profile_record_invalid")
    engine = profile.get("engine")
    schema = profile.get("schema_version")
    created = profile.get("created")
    updated = profile.get("updated")
    if (
        type(engine) is not str or not engine
        or type(schema) is not int or schema <= 0
        or type(created) not in (int, float) or isinstance(created, bool)
        or type(updated) not in (int, float) or isinstance(updated, bool)
        or type(profile.get("extension_baselines")) is not dict
        or type(profile.get("model_state")) is not dict
    ):
        raise ValueError("model_profile_record_invalid")
    return profile


class ModelStateRepository:
    """Own relational profile/model reads and writes; callers own transactions."""

    def __init__(self, lifecycle: SQLiteLifecycleOwner | None = None) -> None:
        self._lifecycle = sqlite_lifecycle() if lifecycle is None else lifecycle

    def ensure_engine(
        self, connection: object, profile: Mapping[str, object], *,
        profile_scope: str = _PROFILE_SCOPE_DEFAULT,
    ) -> None:
        engine = profile.get("engine")
        schema = profile.get("schema_version")
        created = profile.get("created")
        updated = profile.get("updated")
        if type(engine) is not str or not engine or type(schema) is not int:
            raise ValueError("model_profile_identity_invalid")
        if type(profile_scope) is not str or not profile_scope:
            raise ValueError("model_profile_scope_invalid")
        if type(created) not in (int, float) or type(updated) not in (int, float):
            raise ValueError("model_profile_clock_invalid")
        generation = self._lifecycle.generation("model")
        connection.execute(
            "INSERT INTO profile_engines(engine_id,profile_scope,profile_schema_version,created_value,updated_value,generation_id) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(engine_id,profile_scope) DO UPDATE SET "
            "profile_schema_version=excluded.profile_schema_version,created_value=excluded.created_value,"
            "updated_value=excluded.updated_value,generation_id=excluded.generation_id",
            (engine, profile_scope, schema, float(created), float(updated), generation.generation_id),
        )

    def _write_extension_sections(
        self, connection: object, *, engine: str, profile_scope: str,
        baseline_key: str, baseline: Mapping[str, object],
    ) -> None:
        section_names = [
            field for field in _EXTENSION_SECTION_TABLES if field in baseline
        ]
        section_names_json, _section_names_digest = _canonical_json(section_names)
        connection.execute(
            "INSERT INTO profile_extensions(engine_id,profile_scope,baseline_key,file_count,section_names_json) "
            "VALUES(?,?,?,?,?)",
            (engine, profile_scope, baseline_key, baseline["files"], section_names_json),
        )
        for field, table in _EXTENSION_SECTION_TABLES.items():
            if field not in baseline:
                continue
            value = baseline[field]
            payload, digest = _canonical_json(value)
            connection.execute(
                f"INSERT INTO {table}(engine_id,profile_scope,baseline_key,schema_identity,payload_json,payload_sha256) "
                "VALUES(?,?,?,?,?,?)",
                (engine, profile_scope, baseline_key, _schema_identity(value, field + "_current"), payload, digest),
            )

    def _write_model_maps(
        self, connection: object, *, engine: str, profile_scope: str,
        model_state: Mapping[str, object],
    ) -> None:
        for field, table in _MODEL_MAP_TABLES.items():
            values = _state_map(model_state[field], field)
            for key in sorted(values):
                value = values[key]
                payload, digest = _canonical_json(value)
                connection.execute(
                    f"INSERT INTO {table}(engine_id,profile_scope,state_key,schema_identity,payload_json,payload_sha256) "
                    "VALUES(?,?,?,?,?,?)",
                    (engine, profile_scope, key, _schema_identity(value, field + "_current"), payload, digest),
                )
        for field, table in _MODEL_SINGLETON_TABLES.items():
            value = model_state[field]
            payload, digest = _canonical_json(value)
            connection.execute(
                f"INSERT INTO {table}(engine_id,profile_scope,schema_identity,payload_json,payload_sha256) "
                "VALUES(?,?,?,?,?)",
                (engine, profile_scope, _schema_identity(value, field + "_current"), payload, digest),
            )
        versions = _state_map(model_state["feature_registry_versions"], "feature_registry_versions")
        for name in sorted(versions):
            identity = versions[name]
            if type(identity) is not str or not identity:
                raise ValueError("model_feature_registry_identity_invalid")
            connection.execute(
                "INSERT INTO profile_feature_registry_versions(engine_id,profile_scope,feature_name,schema_identity) "
                "VALUES(?,?,?,?)",
                (engine, profile_scope, name, identity),
            )

    def _write_transactions(
        self, connection: object, *, engine: str, profile_scope: str,
        transactions: Mapping[str, object],
    ) -> None:
        for replay_key in sorted(transactions):
            transaction = transactions[replay_key]
            if type(transaction) is not dict or len(replay_key) != 64:
                raise ValueError("learning_transaction_record_invalid")
            decision = transaction.get("decision")
            decision_json, decision_digest = _canonical_json(decision)
            context = _decision_context(decision)
            context_json, context_digest = _canonical_json(context)
            del context_json
            content_sha256 = transaction.get("content_sha256", "")
            if type(content_sha256) is not str:
                raise ValueError("learning_transaction_content_identity_invalid")
            if content_sha256:
                if len(content_sha256) != 64 or any(
                    character not in "0123456789abcdef" for character in content_sha256
                ):
                    raise ValueError("learning_transaction_content_identity_invalid")
                content_status = "verified"
            else:
                content_sha256, content_status = _content_identity(context)
            artifact_instance = transaction.get("artifact_instance", "")
            if type(artifact_instance) is not str:
                raise ValueError("learning_transaction_artifact_instance_invalid")
            if not artifact_instance:
                artifact_instance = (
                    context.get("artifact_instance")
                    or context.get("file_path")
                    or context.get("artifact_identity")
                    or ""
                )
            observation_digest = transaction.get("observation_digest")
            ordinal = transaction.get("decision_ordinal")
            status = transaction.get("status")
            completed = transaction.get("completed_targets")
            failed = transaction.get("failed_targets")
            if (
                type(observation_digest) is not str or len(observation_digest) != 64
                or type(ordinal) is not int or ordinal < 0
                or status not in {"pending", "partial", "complete", "rejected", "failed"}
                or type(completed) is not int or completed < 0
                or type(failed) is not int or failed < 0
            ):
                raise ValueError("learning_transaction_identity_invalid")
            record = {key: value for key, value in transaction.items() if key != "targets"}
            transaction_json, transaction_digest = _canonical_json(record)
            transaction_id = transaction.get("authoritative_transaction_id")
            if (
                status == "complete"
                and (
                    type(transaction_id) is not str
                    or len(transaction_id) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in transaction_id
                    )
                )
            ):
                raise ValueError("learning_transaction_authority_identity_invalid")
            if status != "complete":
                raise ValueError("learning_transaction_incomplete_persistence_rejected")
            connection.execute(
                "INSERT INTO learning_decisions(transaction_id,replay_key,engine_id,profile_scope,content_sha256,"
                "content_identity_status,artifact_instance,model_context_digest,observation_digest,decision_digest,"
                "decision_ordinal,status,completed_targets,failed_targets,transaction_json,transaction_sha256,"
                "created_ns,committed_ns) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    transaction_id, replay_key, engine, profile_scope, content_sha256,
                    content_status, artifact_instance, context_digest, observation_digest,
                    decision_digest, ordinal, status, completed, failed, transaction_json,
                    transaction_digest, ordinal, ordinal if status == "complete" else None,
                ),
            )
            targets = transaction.get("targets")
            order = transaction.get("target_order")
            if type(targets) is not dict or type(order) is not list:
                raise ValueError("learning_transaction_targets_invalid")
            for target_ordinal, target_name in enumerate(order):
                state = targets.get(target_name)
                if type(target_name) is not str or type(state) is not dict:
                    raise ValueError("learning_transaction_target_invalid")
                output, output_digest = _canonical_json(state.get("output", {}))
                connection.execute(
                    "INSERT INTO learning_targets(transaction_id,target_ordinal,target_name,status,attempts,reason,"
                    "output_json,output_sha256) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        transaction_id, target_ordinal, target_name, state.get("status"),
                        state.get("attempts"), state.get("reason"), output, output_digest,
                    ),
                )

    def write_profile(
        self, connection: object, profile: Mapping[str, object], *,
        profile_scope: str = _PROFILE_SCOPE_DEFAULT,
    ) -> None:
        profile = _validate_profile_storage_record(profile)
        engine = profile.get("engine")
        if type(engine) is not str or not engine:
            raise ValueError("model_profile_identity_invalid")
        self.ensure_engine(connection, profile, profile_scope=profile_scope)
        transaction_ids = tuple(
            row[0] for row in connection.execute(
                "SELECT transaction_id FROM learning_decisions WHERE engine_id=? AND profile_scope=?",
                (engine, profile_scope),
            )
        )
        for transaction_id in transaction_ids:
            connection.execute("DELETE FROM learning_decisions WHERE transaction_id=?", (transaction_id,))
        connection.execute(
            "DELETE FROM profile_extensions WHERE engine_id=? AND profile_scope=?",
            (engine, profile_scope),
        )
        for table in (*_MODEL_MAP_TABLES.values(), *_MODEL_SINGLETON_TABLES.values()):
            connection.execute(
                f"DELETE FROM {table} WHERE engine_id=? AND profile_scope=?",
                (engine, profile_scope),
            )
        connection.execute(
            "DELETE FROM profile_feature_registry_versions WHERE engine_id=? AND profile_scope=?",
            (engine, profile_scope),
        )
        extension_baselines = _state_map(profile.get("extension_baselines"), "extension_baselines")
        model_state = _state_map(profile.get("model_state"), "model_state")
        for baseline_key in sorted(extension_baselines):
            baseline = extension_baselines[baseline_key]
            if type(baseline) is not dict:
                raise ValueError("model_extension_baseline_invalid")
            self._write_extension_sections(
                connection, engine=engine, profile_scope=profile_scope,
                baseline_key=baseline_key, baseline=baseline,
            )
        self._write_model_maps(
            connection, engine=engine, profile_scope=profile_scope,
            model_state=model_state,
        )
        self._write_transactions(
            connection, engine=engine, profile_scope=profile_scope,
            transactions=_state_map(model_state["learning_transactions"], "learning_transactions"),
        )

    def _read_payload_map(
        self, connection: object, table: str, *, engine: str, profile_scope: str,
    ) -> dict[str, object]:
        return {
            str(row[0]): json.loads(str(row[1]))
            for row in connection.execute(
                f"SELECT state_key,payload_json FROM {table} WHERE engine_id=? AND profile_scope=? ORDER BY state_key",
                (engine, profile_scope),
            )
        }

    def _read_transactions(
        self, connection: object, *, engine: str, profile_scope: str,
    ) -> dict[str, object]:
        transactions: dict[str, object] = {}
        for row in connection.execute(
            "SELECT transaction_id,replay_key,transaction_json FROM learning_decisions "
            "WHERE engine_id=? AND profile_scope=? ORDER BY decision_ordinal,replay_key",
            (engine, profile_scope),
        ):
            transaction_id, replay_key = str(row[0]), str(row[1])
            record = json.loads(str(row[2]))
            targets: dict[str, object] = {}
            order: list[str] = []
            for target in connection.execute(
                "SELECT target_name,status,attempts,reason,output_json FROM learning_targets "
                "WHERE transaction_id=? ORDER BY target_ordinal",
                (transaction_id,),
            ):
                name = str(target[0])
                order.append(name)
                targets[name] = {
                    "status": str(target[1]), "attempts": int(target[2]),
                    "reason": str(target[3]), "output": json.loads(str(target[4])),
                }
            record["target_order"] = order
            record["targets"] = targets
            transactions[replay_key] = record
        return transactions

    def read_transaction_trace(self, transaction_id: str) -> dict[str, object] | None:
        if (
            type(transaction_id) is not str or len(transaction_id) != 64
            or any(character not in "0123456789abcdef" for character in transaction_id)
        ):
            raise ValueError("authoritative_transaction_query_invalid")
        connection = self._lifecycle.connection("model")
        row = connection.execute(
            "SELECT transaction_kind,replay_key,state_digest,created_ns,committed_ns,status "
            "FROM authoritative_transactions WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        if row is None:
            return None
        domains = tuple({
            "domain_kind": str(domain[0]),
            "domain_identity": str(domain[1]),
            "state_digest": str(domain[2]),
        } for domain in connection.execute(
            "SELECT domain_kind,domain_identity,state_digest "
            "FROM authoritative_transaction_domains WHERE transaction_id=? "
            "ORDER BY domain_kind,domain_identity",
            (transaction_id,),
        ))
        learning = connection.execute(
            "SELECT replay_key,engine_id,profile_scope,status,transaction_sha256 "
            "FROM learning_decisions WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        return {
            "transaction_id": transaction_id,
            "transaction_kind": str(row[0]),
            "replay_key": str(row[1]),
            "state_digest": str(row[2]),
            "created_ns": int(row[3]),
            "committed_ns": int(row[4]),
            "status": str(row[5]),
            "domains": domains,
            "learning_decision": None if learning is None else {
                "replay_key": str(learning[0]),
                "engine": str(learning[1]),
                "profile_scope": str(learning[2]),
                "status": str(learning[3]),
                "transaction_sha256": str(learning[4]),
            },
        }

    def find_learning_replay_key(
        self, *, engine: str, profile_scope: str = _PROFILE_SCOPE_DEFAULT,
        content_sha256: str, context_identity: Mapping[str, str],
        observation_digest: str,
    ) -> str | None:
        if (
            type(content_sha256) is not str or len(content_sha256) != 64
            or type(observation_digest) is not str or len(observation_digest) != 64
        ):
            return None
        _context_json, context_digest = _canonical_json(dict(context_identity))
        row = self._lifecycle.connection("model").execute(
            "SELECT replay_key FROM learning_decisions WHERE engine_id=? AND profile_scope=? "
            "AND content_sha256=? AND model_context_digest=? AND observation_digest=? "
            "AND status='complete'",
            (engine, profile_scope, content_sha256, context_digest, observation_digest),
        ).fetchone()
        return None if row is None else str(row[0])

    def write_content_occurrence(
        self, connection: object, occurrence: Mapping[str, object],
    ) -> None:
        engine = occurrence.get("engine")
        profile_scope = occurrence.get("profile_scope", _PROFILE_SCOPE_DEFAULT)
        content_sha256 = occurrence.get("content_sha256")
        artifact_instance = occurrence.get("artifact_instance")
        context_identity = occurrence.get("context_identity")
        decision_ordinal = occurrence.get("decision_ordinal")
        if (
            type(engine) is not str or not engine
            or type(profile_scope) is not str or not profile_scope
            or type(content_sha256) is not str or len(content_sha256) != 64
            or any(character not in "0123456789abcdef" for character in content_sha256)
            or type(artifact_instance) is not str or not artifact_instance
            or len(artifact_instance) > 4096
            or not isinstance(context_identity, Mapping)
            or type(decision_ordinal) is not int or decision_ordinal < 0
        ):
            raise ValueError("content_artifact_occurrence_invalid")
        _context_json, context_digest = _canonical_json(dict(context_identity))
        connection.execute(
            "INSERT INTO content_artifact_occurrences(engine_id,profile_scope,content_sha256,"
            "artifact_instance,model_context_digest,occurrence_count,first_decision_ordinal,last_decision_ordinal) "
            "VALUES(?,?,?,?,?,1,?,?) ON CONFLICT(engine_id,profile_scope,content_sha256,"
            "artifact_instance,model_context_digest) DO UPDATE SET "
            "occurrence_count=MIN(1000000000,content_artifact_occurrences.occurrence_count+1),"
            "last_decision_ordinal=MAX(content_artifact_occurrences.last_decision_ordinal,"
            "excluded.last_decision_ordinal)",
            (
                engine, profile_scope, content_sha256, artifact_instance, context_digest,
                decision_ordinal, decision_ordinal,
            ),
        )

    def read_content_occurrences(
        self, *, engine: str, content_sha256: str,
        profile_scope: str = _PROFILE_SCOPE_DEFAULT,
    ) -> tuple[dict[str, object], ...]:
        if (
            type(engine) is not str or not engine
            or type(profile_scope) is not str or not profile_scope
            or type(content_sha256) is not str or len(content_sha256) != 64
        ):
            raise ValueError("content_artifact_occurrence_query_invalid")
        rows = self._lifecycle.connection("model").execute(
            "SELECT artifact_instance,model_context_digest,occurrence_count,"
            "first_decision_ordinal,last_decision_ordinal "
            "FROM content_artifact_occurrences WHERE engine_id=? AND profile_scope=? "
            "AND content_sha256=? ORDER BY artifact_instance,model_context_digest",
            (engine, profile_scope, content_sha256),
        )
        return tuple({
            "artifact_instance": str(row[0]),
            "model_context_digest": str(row[1]),
            "occurrence_count": int(row[2]),
            "first_decision_ordinal": int(row[3]),
            "last_decision_ordinal": int(row[4]),
        } for row in rows)

    def write_profile_corruption_event(
        self, connection: object, event: Mapping[str, object], *,
        profile_scope: str = _PROFILE_SCOPE_DEFAULT, created_ns: int,
    ) -> None:
        if type(event) is not dict or type(profile_scope) is not str or not profile_scope:
            raise ValueError("profile_corruption_event_invalid")
        event_key = event.get("profile_corruption_event_key")
        engine = event.get("engine")
        corruption_type = event.get("profile_corruption_type")
        policy = event.get("profile_corruption_policy")
        quarantined = event.get("profile_quarantined")
        scan_continued = event.get("scan_continued")
        if (
            type(event_key) is not str or len(event_key) != 16
            or type(engine) is not str or not engine
            or type(corruption_type) is not str or not corruption_type
            or policy not in {"hard-fail", "quarantine"}
            or type(quarantined) is not bool
            or type(scan_continued) is not bool
            or type(created_ns) is not int or created_ns < 0
        ):
            raise ValueError("profile_corruption_event_invalid")
        payload, digest = _canonical_json(event)
        connection.execute(
            "INSERT INTO profile_corruption_events(event_key,engine_id,profile_scope,corruption_type,"
            "policy,quarantined,scan_continued,event_json,event_sha256,created_ns) "
            "VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_key) DO NOTHING",
            (
                event_key, engine, profile_scope, corruption_type, policy,
                int(quarantined), int(scan_continued), payload, digest, created_ns,
            ),
        )

    def read_profile_corruption_events(
        self, *, engine: str | None = None, profile_scope: str = _PROFILE_SCOPE_DEFAULT,
    ) -> tuple[dict[str, object], ...]:
        connection = self._lifecycle.connection("model")
        if engine is None:
            rows = connection.execute(
                "SELECT event_json FROM profile_corruption_events ORDER BY event_id"
            )
        else:
            rows = connection.execute(
                "SELECT event_json FROM profile_corruption_events "
                "WHERE engine_id=? AND profile_scope=? ORDER BY event_id",
                (engine, profile_scope),
            )
        return tuple(json.loads(str(row[0])) for row in rows)

    def read_profile(
        self, engine: str, *, profile_scope: str = _PROFILE_SCOPE_DEFAULT,
    ) -> dict[str, object] | None:
        connection = self._lifecycle.connection("model")
        root = connection.execute(
            "SELECT profile_schema_version,created_value,updated_value FROM profile_engines "
            "WHERE engine_id=? AND profile_scope=?",
            (engine, profile_scope),
        ).fetchone()
        if root is None:
            return None
        baselines: dict[str, object] = {}
        for extension_row in connection.execute(
            "SELECT baseline_key,file_count,section_names_json FROM profile_extensions "
            "WHERE engine_id=? AND profile_scope=? ORDER BY baseline_key",
            (engine, profile_scope),
        ):
            baseline_key = str(extension_row[0])
            section_names = json.loads(str(extension_row[2]))
            if type(section_names) is not list or any(
                type(field) is not str or field not in _EXTENSION_SECTION_TABLES
                for field in section_names
            ):
                raise ValueError("model_extension_section_identity_invalid")
            baseline: dict[str, object] = {
                "extension": baseline_key, "files": int(extension_row[1]),
            }
            for field in section_names:
                table = _EXTENSION_SECTION_TABLES[field]
                row = connection.execute(
                    f"SELECT payload_json FROM {table} WHERE engine_id=? AND profile_scope=? AND baseline_key=?",
                    (engine, profile_scope, baseline_key),
                ).fetchone()
                if row is None:
                    raise ValueError("model_extension_section_missing:" + field)
                baseline[field] = json.loads(str(row[0]))
            baselines[baseline_key] = baseline
        model_state: dict[str, object] = {
            field: self._read_payload_map(
                connection, table, engine=engine, profile_scope=profile_scope,
            )
            for field, table in _MODEL_MAP_TABLES.items()
        }
        for field, table in _MODEL_SINGLETON_TABLES.items():
            row = connection.execute(
                f"SELECT payload_json FROM {table} WHERE engine_id=? AND profile_scope=?",
                (engine, profile_scope),
            ).fetchone()
            if row is None:
                raise ValueError("model_singleton_state_missing:" + field)
            model_state[field] = json.loads(str(row[0]))
        model_state["feature_registry_versions"] = {
            str(row[0]): str(row[1])
            for row in connection.execute(
                "SELECT feature_name,schema_identity FROM profile_feature_registry_versions "
                "WHERE engine_id=? AND profile_scope=? ORDER BY feature_name",
                (engine, profile_scope),
            )
        }
        model_state["learning_transactions"] = self._read_transactions(
            connection, engine=engine, profile_scope=profile_scope,
        )
        profile = {
            "engine": engine,
            "schema_version": int(root[0]),
            "extension_baselines": baselines,
            "model_state": model_state,
            "created": float(root[1]),
            "updated": float(root[2]),
        }
        return profile


    @staticmethod
    def _replace_metadata(connection: object, key: str, value: object) -> None:
        payload, digest = _canonical_json(value)
        connection.execute(
            "INSERT INTO runtime_model_metadata(key,payload_json,payload_sha256) VALUES(?,?,?)",
            (key, payload, digest),
        )

    def write_runtime_snapshot(self, connection: object, snapshot: Mapping[str, object]) -> None:
        envelope_error = runtime_model_state_envelope_error(snapshot)
        if envelope_error is not None:
            raise ValueError("runtime_model_snapshot_invalid:" + envelope_error)
        if snapshot["schema_version"] != RUNTIME_MODEL_STATE_SCHEMA_VERSION:
            raise ValueError("runtime_model_snapshot_invalid:runtime_model_snapshot_schema_unsupported")
        for table in (
            "runtime_model_metadata", "markov_transitions", "markov_tag_baselines",
            "markov_tag_pair_baselines", "filetype_baselines", "temporal_nodes",
            "temporal_learning_keys", "microclusters", "cluster_node_assignments",
            "cluster_learning_keys", "model_replay_keys",
        ):
            connection.execute(f"DELETE FROM {table}")
        for key in (
            "schema_version", "updated", "markov_state_schema_version",
            "markov_state_migration_evidence",
        ):
            if key not in snapshot:
                raise ValueError("runtime_model_metadata_missing:" + key)
            self._replace_metadata(connection, key, snapshot[key])
        if "model_state_unavailable_reasons" in snapshot:
            self._replace_metadata(
                connection, "model_state_unavailable_reasons",
                snapshot["model_state_unavailable_reasons"],
            )
        transitions = snapshot.get("transition_counts")
        if type(transitions) not in (list, tuple):
            raise ValueError("runtime_transition_rows_invalid")
        for row in transitions:
            if type(row) is not dict:
                raise ValueError("runtime_transition_row_invalid")
            target = row.get("target")
            count = row.get("count")
            if type(target) is not str or not target or type(count) is not int or count <= 0:
                raise ValueError("runtime_transition_row_invalid")
            key_record = {key: value for key, value in row.items() if key not in {"target", "count"}}
            key_json, key_digest = _canonical_json(key_record)
            connection.execute(
                "INSERT INTO markov_transitions(transition_key_digest,transition_key_json,target_state,observation_count) "
                "VALUES(?,?,?,?)",
                (key_digest, key_json, target, count),
            )
        tags = snapshot.get("global_tag_baseline")
        if type(tags) is not dict:
            raise ValueError("runtime_tag_baseline_invalid")
        for tag in sorted(tags):
            count = tags[tag]
            if type(tag) is not str or not tag or type(count) is not int or count <= 0:
                raise ValueError("runtime_tag_baseline_invalid")
            connection.execute(
                "INSERT INTO markov_tag_baselines(tag,observation_count) VALUES(?,?)",
                (tag, count),
            )
        pairs = snapshot.get("global_tag_pair_baseline")
        if type(pairs) not in (list, tuple):
            raise ValueError("runtime_pair_baseline_invalid")
        for row in pairs:
            if type(row) is not dict:
                raise ValueError("runtime_pair_baseline_invalid")
            first, second, count = row.get("a"), row.get("b"), row.get("count")
            if (
                type(first) is not str or type(second) is not str or not first or not second
                or first > second or type(count) is not int or count <= 0
            ):
                raise ValueError("runtime_pair_baseline_invalid")
            connection.execute(
                "INSERT INTO markov_tag_pair_baselines(first_tag,second_tag,observation_count) VALUES(?,?,?)",
                (first, second, count),
            )
        filetypes = snapshot.get("filetype_baseline")
        if type(filetypes) is not dict:
            raise ValueError("runtime_filetype_baseline_invalid")
        for filetype_key in sorted(filetypes):
            values = filetypes[filetype_key]
            if type(filetype_key) is not str or not filetype_key or type(values) is not dict:
                raise ValueError("runtime_filetype_baseline_invalid")
            for feature in sorted(values):
                count = values[feature]
                if type(feature) is not str or not feature or type(count) is not int or count <= 0:
                    raise ValueError("runtime_filetype_baseline_invalid")
                connection.execute(
                    "INSERT INTO filetype_baselines(filetype_key,feature_key,observation_count) VALUES(?,?,?)",
                    (filetype_key, feature, count),
                )
        temporal = snapshot.get("temporal_state")
        if type(temporal) is not dict or type(temporal.get("nodes")) is not dict:
            raise ValueError("runtime_temporal_state_invalid")
        self._replace_metadata(connection, "temporal_schema_version", temporal.get("schema_version"))
        for node in sorted(temporal["nodes"]):
            payload, digest = _canonical_json(temporal["nodes"][node])
            connection.execute(
                "INSERT INTO temporal_nodes(node_identity,payload_json,payload_sha256) VALUES(?,?,?)",
                (node, payload, digest),
            )
        temporal_keys = temporal.get("applied_learning_keys")
        if type(temporal_keys) is not list:
            raise ValueError("runtime_temporal_learning_keys_invalid")
        for row in temporal_keys:
            if type(row) is not dict:
                raise ValueError("runtime_temporal_learning_keys_invalid")
            connection.execute(
                "INSERT INTO temporal_learning_keys(replay_key,decision_ordinal) VALUES(?,?)",
                (row.get("replay_key"), row.get("decision_ordinal")),
            )
        cluster = snapshot.get("cluster_state")
        if type(cluster) is not dict or type(cluster.get("microclusters")) is not dict:
            raise ValueError("runtime_cluster_state_invalid")
        self._replace_metadata(connection, "cluster_schema_version", cluster.get("schema"))
        clusters = cluster["microclusters"]
        for cluster_id in sorted(clusters):
            payload, digest = _canonical_json(clusters[cluster_id])
            connection.execute(
                "INSERT INTO microclusters(cluster_id,payload_json,payload_sha256) VALUES(?,?,?)",
                (cluster_id, payload, digest),
            )
        node_map = cluster.get("node_cluster_map")
        vectors = cluster.get("node_feature_vectors")
        if type(node_map) is not dict or type(vectors) is not dict:
            raise ValueError("runtime_cluster_assignments_invalid")
        for node in sorted(node_map):
            vector = vectors.get(node)
            vector_json = vector_digest = None
            if vector is not None:
                vector_json, vector_digest = _canonical_json(vector)
            connection.execute(
                "INSERT INTO cluster_node_assignments(node_identity,cluster_id,feature_vector_json,feature_vector_sha256) "
                "VALUES(?,?,?,?)",
                (node, node_map[node], vector_json, vector_digest),
            )
        cluster_keys = cluster.get("applied_learning_keys")
        if type(cluster_keys) is not dict:
            raise ValueError("runtime_cluster_learning_keys_invalid")
        for replay_key, ordinal in sorted(cluster_keys.items(), key=lambda row: (row[1], row[0])):
            connection.execute(
                "INSERT INTO cluster_learning_keys(replay_key,decision_ordinal) VALUES(?,?)",
                (replay_key, ordinal),
            )
        learning = snapshot.get("learning_applied_keys")
        if type(learning) is not dict:
            raise ValueError("runtime_learning_keys_invalid")
        learning_domains = sorted(learning)
        self._replace_metadata(connection, "learning_domains", learning_domains)
        for domain in learning_domains:
            keys = learning[domain]
            if type(keys) not in (list, tuple):
                raise ValueError("runtime_learning_keys_invalid")
            for ordinal, replay_key in enumerate(keys):
                connection.execute(
                    "INSERT INTO model_replay_keys(domain,replay_key,decision_ordinal) VALUES(?,?,?)",
                    (domain, replay_key, ordinal),
                )

    @staticmethod
    def _runtime_transition_sort_key(row: Mapping[str, object]) -> tuple[object, ...]:
        return (
            row.get("type", ""), repr(row.get("flow", row.get("event", ""))),
            row.get("target", ""), row.get("context", ""),
            row.get("previous_stage", ""), row.get("source_event", ""),
            row.get("flow_class", ""),
        )

    def read_runtime_snapshot(self) -> dict[str, object] | None:
        connection = self._lifecycle.connection("model")
        metadata = {
            str(row[0]): json.loads(str(row[1]))
            for row in connection.execute(
                "SELECT key,payload_json FROM runtime_model_metadata ORDER BY key"
            )
        }
        if not metadata:
            return None
        transitions: list[dict[str, object]] = []
        for row in connection.execute(
            "SELECT transition_key_json,target_state,observation_count FROM markov_transitions"
        ):
            record = json.loads(str(row[0]))
            record["target"] = str(row[1])
            record["count"] = int(row[2])
            transitions.append(record)
        transitions.sort(key=self._runtime_transition_sort_key)
        tags = {
            str(row[0]): int(row[1])
            for row in connection.execute(
                "SELECT tag,observation_count FROM markov_tag_baselines ORDER BY tag"
            )
        }
        pairs = [
            {"a": str(row[0]), "b": str(row[1]), "count": int(row[2])}
            for row in connection.execute(
                "SELECT first_tag,second_tag,observation_count FROM markov_tag_pair_baselines "
                "ORDER BY first_tag,second_tag"
            )
        ]
        filetypes: dict[str, dict[str, int]] = {}
        for row in connection.execute(
            "SELECT filetype_key,feature_key,observation_count FROM filetype_baselines "
            "ORDER BY filetype_key,feature_key"
        ):
            filetypes.setdefault(str(row[0]), {})[str(row[1])] = int(row[2])
        temporal = {
            "schema_version": metadata["temporal_schema_version"],
            "nodes": {
                str(row[0]): json.loads(str(row[1]))
                for row in connection.execute(
                    "SELECT node_identity,payload_json FROM temporal_nodes ORDER BY node_identity"
                )
            },
            "applied_learning_keys": [
                {"replay_key": str(row[0]), "decision_ordinal": int(row[1])}
                for row in connection.execute(
                    "SELECT replay_key,decision_ordinal FROM temporal_learning_keys "
                    "ORDER BY decision_ordinal,replay_key"
                )
            ],
        }
        microclusters = {
            str(row[0]): json.loads(str(row[1]))
            for row in connection.execute(
                "SELECT cluster_id,payload_json FROM microclusters ORDER BY cluster_id"
            )
        }
        node_map: dict[str, str] = {}
        vectors: dict[str, object] = {}
        for row in connection.execute(
            "SELECT node_identity,cluster_id,feature_vector_json FROM cluster_node_assignments "
            "ORDER BY node_identity"
        ):
            node = str(row[0])
            node_map[node] = str(row[1])
            if row[2] is not None:
                vectors[node] = json.loads(str(row[2]))
        cluster = {
            "schema": metadata["cluster_schema_version"],
            "microclusters": microclusters,
            "node_cluster_map": node_map,
            "node_feature_vectors": vectors,
            "applied_learning_keys": {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT replay_key,decision_ordinal FROM cluster_learning_keys "
                    "ORDER BY decision_ordinal,replay_key"
                )
            },
        }
        domains = metadata.get("learning_domains")
        if type(domains) is not list or any(type(domain) is not str or not domain for domain in domains):
            raise ValueError("runtime_learning_domains_invalid")
        learning: dict[str, list[str]] = {domain: [] for domain in domains}
        for row in connection.execute(
            "SELECT domain,replay_key FROM model_replay_keys ORDER BY domain,decision_ordinal,replay_key"
        ):
            domain = str(row[0])
            if domain not in learning:
                raise ValueError("runtime_learning_domain_row_invalid")
            learning[domain].append(str(row[1]))
        snapshot: dict[str, object] = {
            "schema_version": metadata["schema_version"],
            "updated": metadata["updated"],
            "markov_state_schema_version": metadata["markov_state_schema_version"],
            "markov_state_migration_evidence": metadata["markov_state_migration_evidence"],
            "transition_counts": transitions,
            "global_tag_baseline": tags,
            "global_tag_pair_baseline": pairs,
            "filetype_baseline": filetypes,
            "cluster_state": cluster,
            "temporal_state": temporal,
            "learning_applied_keys": learning,
        }
        if "model_state_unavailable_reasons" in metadata:
            snapshot["model_state_unavailable_reasons"] = metadata["model_state_unavailable_reasons"]
        return snapshot

    @staticmethod
    def canonical_domain_digest_map_digest(
        domain_digests: Mapping[str, str],
    ) -> str:
        normalized = tuple(sorted((str(key), str(value)) for key, value in domain_digests.items()))
        if any(
            not key
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for key, value in normalized
        ):
            raise ValueError("model_state_domain_digest_map_invalid")
        return hashlib.sha256(
            json.dumps(
                normalized,
                sort_keys=False,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def read_persisted_model_domain_digests(connection: object) -> dict[str, str]:
        rows = connection.execute(
            "SELECT key,value FROM database_metadata WHERE key LIKE ? ORDER BY key",
            (_MODEL_STATE_DOMAIN_METADATA_PREFIX + "%",),
        )
        result: dict[str, str] = {}
        for row in rows:
            key = str(row[0])
            value = str(row[1])
            domain = key[len(_MODEL_STATE_DOMAIN_METADATA_PREFIX):]
            if (
                not domain
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError("model_state_domain_digest_metadata_invalid")
            result[domain] = value
        return result

    @staticmethod
    def write_model_domain_digest(
        connection: object, *, domain_identity: str, state_digest: str, updated_ns: int,
    ) -> None:
        if type(domain_identity) is not str or not domain_identity:
            raise ValueError("model_state_domain_identity_invalid")
        if (
            type(state_digest) is not str
            or len(state_digest) != 64
            or any(character not in "0123456789abcdef" for character in state_digest)
        ):
            raise ValueError("model_state_domain_digest_invalid")
        if type(updated_ns) is not int or updated_ns < 0:
            raise ValueError("model_state_domain_digest_time_invalid")
        connection.execute(
            "INSERT INTO database_metadata(key,value,updated_ns) VALUES(?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_ns=excluded.updated_ns",
            (_MODEL_STATE_DOMAIN_METADATA_PREFIX + domain_identity, state_digest, updated_ns),
        )

    def reconstruct_model_domain_digests(self) -> dict[str, str]:
        """Reconstruct current semantic domain digests for integrity/recovery proof."""
        connection = self._lifecycle.connection("model")
        result: dict[str, str] = {}
        rows = connection.execute(
            "SELECT engine_id,profile_scope FROM profile_engines ORDER BY engine_id,profile_scope"
        ).fetchall()
        for row in rows:
            engine, profile_scope = str(row[0]), str(row[1])
            profile = self.read_profile(engine, profile_scope=profile_scope)
            if profile is None:
                raise ValueError("model_state_profile_digest_source_missing")
            _payload, digest = _canonical_json(profile)
            result[f"profile:{engine}:{profile_scope}"] = digest
        runtime_snapshot = self.read_runtime_snapshot()
        if runtime_snapshot is not None:
            _payload, digest = _canonical_json(runtime_snapshot)
            result["runtime_models:global"] = digest
        return result

    def canonical_model_state_digest(self, connection: object) -> str:
        """Return the O(domain-count) persisted state digest used on commit."""
        return self.canonical_domain_digest_map_digest(
            self.read_persisted_model_domain_digests(connection)
        )

    @staticmethod
    def write_model_generation_manifest(
        connection: object, manifest: ModelGenerationManifest,
    ) -> str:
        if type(manifest) is not ModelGenerationManifest:
            raise TypeError("model_generation_manifest_required")
        record = manifest.to_record()
        payload, digest = _canonical_json(record)
        existing = connection.execute(
            "SELECT manifest_sha256 FROM model_generation_manifests WHERE generation_id=?",
            (manifest.generation_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise ValueError("model_generation_manifest_identity_conflict")
            return manifest.generation_id
        connection.execute(
            "INSERT INTO model_generation_manifests("
            "generation_id,manifest_schema_version,manifest_json,manifest_sha256,"
            "canonical_state_digest,previous_generation_id,previous_generation_manifest_hash,"
            "promotion_transaction_id,application_model_version,feature_schema_identity,"
            "policy_identity,dependency_graph_identity,evaluation_release_identity,created_ns"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                manifest.generation_id,
                manifest.schema_version,
                payload,
                digest,
                manifest.canonical_state_digest,
                manifest.previous_generation_id,
                manifest.previous_generation_manifest_hash,
                manifest.promotion_transaction_id,
                manifest.application_model_version,
                manifest.feature_schema_identity,
                manifest.policy_identity,
                manifest.dependency_graph_identity,
                manifest.evaluation_release_identity,
                manifest.created_at_ns,
            ),
        )
        return manifest.generation_id

    def read_model_generation_manifest(
        self, generation_id: str, *, connection: object | None = None,
    ) -> ModelGenerationManifest | None:
        if (
            type(generation_id) is not str
            or len(generation_id) != 64
            or any(character not in "0123456789abcdef" for character in generation_id)
        ):
            raise ValueError("model_generation_id_invalid")
        source = self._lifecycle.connection("model") if connection is None else connection
        row = source.execute(
            "SELECT manifest_json,manifest_sha256,canonical_state_digest,"
            "previous_generation_id,previous_generation_manifest_hash,promotion_transaction_id,"
            "application_model_version,feature_schema_identity,policy_identity,"
            "dependency_graph_identity,evaluation_release_identity,created_ns,manifest_schema_version "
            "FROM model_generation_manifests WHERE generation_id=?",
            (generation_id,),
        ).fetchone()
        if row is None:
            return None
        record = json.loads(str(row[0]))
        digest = canonical_record_sha256(record)
        if digest != str(row[1]):
            raise ValueError("model_generation_manifest_digest_mismatch")
        manifest = ModelGenerationManifest.from_record(record)
        if manifest.generation_id != generation_id:
            raise ValueError("model_generation_manifest_row_identity_mismatch")
        expected_columns = (
            manifest.canonical_state_digest,
            manifest.previous_generation_id,
            manifest.previous_generation_manifest_hash,
            manifest.promotion_transaction_id,
            manifest.application_model_version,
            manifest.feature_schema_identity,
            manifest.policy_identity,
            manifest.dependency_graph_identity,
            manifest.evaluation_release_identity,
            manifest.created_at_ns,
            manifest.schema_version,
        )
        actual_columns = tuple(row[index] for index in range(2, 13))
        if tuple(str(value) if index != 9 else int(value) for index, value in enumerate(actual_columns)) != tuple(
            str(value) if index != 9 else int(value) for index, value in enumerate(expected_columns)
        ):
            raise ValueError("model_generation_manifest_column_mismatch")
        return manifest

    def read_active_model_generation(
        self, *, connection: object | None = None,
    ) -> ModelGenerationManifest | None:
        source = self._lifecycle.connection("model") if connection is None else connection
        row = source.execute(
            "SELECT generation_id,promotion_transaction_id FROM active_model_generation "
            "WHERE singleton_id=1"
        ).fetchone()
        if row is None:
            return None
        generation_id = str(row[0])
        manifest = self.read_model_generation_manifest(
            generation_id, connection=source,
        )
        if manifest is None:
            raise ValueError("active_model_generation_manifest_missing")
        if str(row[1]) != manifest.promotion_transaction_id:
            raise ValueError("active_model_generation_transaction_mismatch")
        return manifest

    def validate_model_generation_lineage(
        self, manifest: ModelGenerationManifest, *, connection: object | None = None,
    ) -> None:
        """Validate complete immutable parent/hash continuity before generation trust."""
        if type(manifest) is not ModelGenerationManifest:
            raise TypeError("model_generation_manifest_required")
        source = self._lifecycle.connection("model") if connection is None else connection
        maximum = int(source.execute(
            "SELECT count(*) FROM model_generation_manifests"
        ).fetchone()[0]) + 1
        current = manifest
        seen: set[str] = set()
        for _depth in range(maximum):
            if current.generation_id in seen:
                raise ValueError("model_generation_lineage_cycle")
            seen.add(current.generation_id)
            previous_id = current.previous_generation_id
            previous_hash = current.previous_generation_manifest_hash
            if not previous_id:
                if previous_hash:
                    raise ValueError("model_generation_root_hash_invalid")
                return
            if not previous_hash:
                raise ValueError("model_generation_parent_hash_missing")
            previous = self.read_model_generation_manifest(
                previous_id, connection=source,
            )
            if previous is None:
                raise ValueError("model_generation_parent_missing")
            if previous.manifest_sha256() != previous_hash:
                raise ValueError("model_generation_parent_hash_mismatch")
            if previous.created_at_ns > current.created_at_ns:
                raise ValueError("model_generation_lineage_clock_invalid")
            current = previous
        raise ValueError("model_generation_lineage_unbounded")

    @staticmethod
    def activate_model_generation(
        connection: object, manifest: ModelGenerationManifest, *, activated_ns: int,
    ) -> None:
        if type(manifest) is not ModelGenerationManifest:
            raise TypeError("model_generation_manifest_required")
        if type(activated_ns) is not int or activated_ns < 0:
            raise ValueError("model_generation_activation_time_invalid")
        if not manifest.promotion_transaction_id:
            raise ValueError("model_generation_activation_transaction_required")
        connection.execute(
            "INSERT INTO active_model_generation(singleton_id,generation_id,activated_ns,promotion_transaction_id) "
            "VALUES(1,?,?,?) ON CONFLICT(singleton_id) DO UPDATE SET "
            "generation_id=excluded.generation_id,activated_ns=excluded.activated_ns,"
            "promotion_transaction_id=excluded.promotion_transaction_id",
            (
                manifest.generation_id,
                activated_ns,
                manifest.promotion_transaction_id,
            ),
        )



__all__ = ("ModelStateRepository",)
