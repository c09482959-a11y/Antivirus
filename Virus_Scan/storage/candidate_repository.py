"""Non-authoritative learning-candidate repository through the SQLite lifecycle owner."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from Virus_Scan.storage.model_generation_contracts import (
    CandidateObservation,
    ModelCandidateQuarantineManifest,
    PromotionAuditRecord,
    PromotionIntentRecord,
    canonical_record_sha256,
)
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleOwner, sqlite_lifecycle


def _canonical_json(value: object) -> tuple[str, str]:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    return encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _validate_staged_storage_record(store: object) -> Mapping[str, object]:
    if not isinstance(store, Mapping):
        raise ValueError("candidate_store_record_invalid")
    ledger = store.get("observation_ledger")
    if (
        type(store.get("schema_version")) is not str
        or type(store.get("candidates")) is not dict
        or type(store.get("promotions")) is not int
        or store.get("promotions", -1) < 0
        or type(store.get("rejections")) is not dict
        or type(ledger) is not dict
        or type(ledger.get("schema_version")) is not str
        or type(ledger.get("entries")) is not dict
    ):
        raise ValueError("candidate_store_record_invalid")
    return store


class LearningCandidateRepository:
    """Own normalized non-authoritative candidate-state rows."""

    def __init__(self, lifecycle: SQLiteLifecycleOwner | None = None) -> None:
        self._lifecycle = sqlite_lifecycle() if lifecycle is None else lifecycle

    def write_staged_store(self, connection: object, store: Mapping[str, object]) -> None:
        store = _validate_staged_storage_record(store)
        for table in (
            "staged_candidates", "staged_observations", "staged_rejections",
            "staged_metadata",
        ):
            connection.execute(f"DELETE FROM {table}")
        metadata = {
            "schema_version": store["schema_version"],
            "promotions": store["promotions"],
            "observation_ledger_schema": store["observation_ledger"]["schema_version"],
        }
        if "retention" in store:
            metadata["retention"] = store["retention"]
        for key, value in metadata.items():
            payload, digest = _canonical_json(value)
            connection.execute(
                "INSERT INTO staged_metadata(key,payload_json,payload_sha256) VALUES(?,?,?)",
                (key, payload, digest),
            )
        for candidate_key, candidate in sorted(store["candidates"].items()):
            payload, digest = _canonical_json(candidate)
            connection.execute(
                "INSERT INTO staged_candidates(candidate_key,content_sha256,engine_id,extension,payload_json,payload_sha256) "
                "VALUES(?,?,?,?,?,?)",
                (
                    candidate_key, candidate["sha256"], candidate["engine"],
                    candidate["extension"], payload, digest,
                ),
            )
        for observation_id, entry in sorted(store["observation_ledger"]["entries"].items()):
            connection.execute(
                "INSERT INTO staged_observations(observation_id,observation_digest,replay_key,decision_ordinal,"
                "candidate_key,status,reason,promoted) VALUES(?,?,?,?,?,?,?,?)",
                (
                    observation_id, entry["observation_digest"], entry["replay_key"],
                    entry["decision_ordinal"], entry["candidate_key"], entry["status"],
                    entry["reason"], int(entry["promoted"]),
                ),
            )
        for reason, count in sorted(store["rejections"].items()):
            connection.execute(
                "INSERT INTO staged_rejections(reason,rejection_count) VALUES(?,?)",
                (reason, count),
            )

    @staticmethod
    def _record_payload(record: dict[str, object]) -> tuple[str, str]:
        return _canonical_json(record)

    def write_candidate_observation(
        self, connection: object, observation: CandidateObservation,
    ) -> str:
        if type(observation) is not CandidateObservation:
            raise TypeError("candidate_observation_required")
        record = observation.to_record()
        payload, digest = self._record_payload(record)
        evidence_ids_json, _ = _canonical_json(record["evidence_ids"])
        normalized_value_json, _ = _canonical_json(record["normalized_value"])
        confidence_context_json, _ = _canonical_json(record["confidence_context"])
        existing = connection.execute(
            "SELECT record_sha256 FROM candidate_observations WHERE candidate_id=?",
            (observation.candidate_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise ValueError("candidate_observation_identity_conflict")
            return observation.candidate_id
        connection.execute(
            "INSERT INTO candidate_observations("
            "candidate_id,schema_version,scan_id,artifact_identity,artifact_sha256,"
            "physical_target_identity,member_identity,evidence_ids_json,evidence_snapshot_id,"
            "authority_class,evidence_type,producer_id,producer_version,model_id,model_generation,"
            "external_source,observed_at,normalized_value_json,confidence_context_json,"
            "source_independence_key,replay_key,semantic_domain,proposed_effect,record_json,record_sha256"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation.candidate_id, observation.schema_version, observation.scan_id,
                observation.artifact_identity, observation.artifact_sha256,
                observation.physical_target_identity, observation.member_identity, evidence_ids_json,
                observation.evidence_snapshot_id, observation.authority_class, observation.evidence_type,
                observation.producer_id, observation.producer_version, observation.model_id,
                observation.model_generation, observation.external_source, observation.observed_at,
                normalized_value_json, confidence_context_json, observation.source_independence_key,
                observation.replay_key, observation.semantic_domain, observation.proposed_effect, payload, digest,
            ),
        )
        return observation.candidate_id

    def read_candidate_observation(self, candidate_id: str) -> CandidateObservation | None:
        if type(candidate_id) is not str or len(candidate_id) != 64:
            raise ValueError("candidate_observation_id_invalid")
        connection = self._lifecycle.connection("candidate")
        row = connection.execute(
            "SELECT record_json,record_sha256,schema_version,scan_id,artifact_identity,artifact_sha256,"
            "physical_target_identity,member_identity,evidence_ids_json,evidence_snapshot_id,"
            "authority_class,evidence_type,producer_id,producer_version,model_id,model_generation,"
            "external_source,observed_at,normalized_value_json,confidence_context_json,"
            "source_independence_key,replay_key,semantic_domain,proposed_effect "
            "FROM candidate_observations WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        record = json.loads(str(row[0]))
        if canonical_record_sha256(record) != str(row[1]):
            raise ValueError("candidate_observation_record_digest_mismatch")
        value = CandidateObservation.from_record(record)
        if value.candidate_id != candidate_id:
            raise ValueError("candidate_observation_row_identity_mismatch")
        expected = (
            value.schema_version, value.scan_id, value.artifact_identity, value.artifact_sha256,
            value.physical_target_identity, value.member_identity, list(value.evidence_ids),
            value.evidence_snapshot_id, value.authority_class, value.evidence_type, value.producer_id,
            value.producer_version, value.model_id, value.model_generation, value.external_source,
            value.observed_at, value.normalized_value, [list(pair) for pair in value.confidence_context],
            value.source_independence_key, value.replay_key, value.semantic_domain, value.proposed_effect,
        )
        actual = (
            str(row[2]), str(row[3]), str(row[4]), str(row[5]), str(row[6]), str(row[7]),
            json.loads(str(row[8])), str(row[9]), str(row[10]), str(row[11]), str(row[12]),
            str(row[13]), str(row[14]), str(row[15]), str(row[16]), int(row[17]),
            json.loads(str(row[18])), json.loads(str(row[19])), str(row[20]), str(row[21]),
            str(row[22]), str(row[23]),
        )
        if actual != expected:
            raise ValueError("candidate_observation_column_mismatch")
        return value

    def read_candidate_observation_by_replay_key(
        self, replay_key: str,
    ) -> CandidateObservation | None:
        if type(replay_key) is not str or len(replay_key) != 64:
            raise ValueError("candidate_replay_key_invalid")
        connection = self._lifecycle.connection("candidate")
        rows = connection.execute(
            "SELECT candidate_id FROM candidate_observations WHERE replay_key=? "
            "ORDER BY candidate_id LIMIT 2",
            (replay_key,),
        ).fetchall()
        if len(rows) > 1:
            raise ValueError("candidate_replay_identity_duplicated")
        if not rows:
            return None
        return self.read_candidate_observation(str(rows[0][0]))

    def independent_candidate_ids(
        self, *, semantic_domain: str, proposed_effect: str, limit: int,
    ) -> tuple[str, ...]:
        if type(semantic_domain) is not str or not semantic_domain:
            raise ValueError("candidate_semantic_domain_invalid")
        if type(proposed_effect) is not str or not proposed_effect:
            raise ValueError("candidate_proposed_effect_invalid")
        if type(limit) is not int or type(limit) is bool or limit <= 0 or limit > 256:
            raise ValueError("candidate_independence_limit_invalid")
        connection = self._lifecycle.connection("candidate")
        rows = connection.execute(
            "SELECT MIN(candidate_id) AS candidate_id, source_independence_key "
            "FROM candidate_observations "
            "WHERE semantic_domain=? AND proposed_effect=? "
            "GROUP BY source_independence_key "
            "ORDER BY source_independence_key LIMIT ?",
            (semantic_domain, proposed_effect, limit),
        ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def write_promotion_intent(
        self, connection: object, intent: PromotionIntentRecord,
    ) -> str:
        if type(intent) is not PromotionIntentRecord:
            raise TypeError("promotion_intent_record_required")
        record = intent.to_record()
        payload, digest = self._record_payload(record)
        candidate_ids_json, _ = _canonical_json(record["candidate_ids"])
        existing = connection.execute(
            "SELECT intent_sha256,status FROM promotion_intents WHERE promotion_intent_id=?",
            (intent.promotion_intent_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise ValueError("promotion_intent_identity_conflict")
            return intent.promotion_intent_id
        connection.execute(
            "INSERT INTO promotion_intents("
            "promotion_intent_id,current_candidate_id,candidate_ids_json,source_generation_id,"
            "authoritative_transaction_id,replay_key,semantic_domain,proposed_effect,"
            "required_independent_sources,status,created_at_ns,finalized_at_ns,intent_json,intent_sha256"
            ") VALUES(?,?,?,?,?,?,?,?,?,'pending',?,0,?,?)",
            (
                intent.promotion_intent_id, intent.current_candidate_id, candidate_ids_json,
                intent.source_generation_id, intent.authoritative_transaction_id,
                intent.replay_key, intent.semantic_domain, intent.proposed_effect,
                intent.required_independent_sources, intent.created_at_ns, payload, digest,
            ),
        )
        return intent.promotion_intent_id

    def _promotion_intent_from_row(
        self, row: object,
    ) -> tuple[PromotionIntentRecord, str, int]:
        if row is None:
            raise ValueError("promotion_intent_row_missing")
        record = json.loads(str(row[0]))
        if canonical_record_sha256(record) != str(row[1]):
            raise ValueError("promotion_intent_record_digest_mismatch")
        intent = PromotionIntentRecord.from_record(record)
        status = str(row[2])
        finalized_at_ns = int(row[3])
        if status not in {"pending", "finalized", "aborted"}:
            raise ValueError("promotion_intent_status_invalid")
        if (status == "pending") != (finalized_at_ns == 0):
            raise ValueError("promotion_intent_terminal_time_invalid")
        return intent, status, finalized_at_ns

    def read_promotion_intent(
        self, promotion_intent_id: str,
    ) -> tuple[PromotionIntentRecord, str, int] | None:
        if type(promotion_intent_id) is not str or len(promotion_intent_id) != 64:
            raise ValueError("promotion_intent_id_invalid")
        connection = self._lifecycle.connection("candidate")
        row = connection.execute(
            "SELECT intent_json,intent_sha256,status,finalized_at_ns "
            "FROM promotion_intents WHERE promotion_intent_id=?",
            (promotion_intent_id,),
        ).fetchone()
        if row is None:
            return None
        intent, status, finalized_at_ns = self._promotion_intent_from_row(row)
        if intent.promotion_intent_id != promotion_intent_id:
            raise ValueError("promotion_intent_row_identity_mismatch")
        return intent, status, finalized_at_ns

    def read_promotion_intent_by_replay_key(
        self, replay_key: str,
    ) -> tuple[PromotionIntentRecord, str, int] | None:
        if type(replay_key) is not str or len(replay_key) != 64:
            raise ValueError("promotion_intent_replay_key_invalid")
        connection = self._lifecycle.connection("candidate")
        row = connection.execute(
            "SELECT intent_json,intent_sha256,status,finalized_at_ns "
            "FROM promotion_intents WHERE replay_key=?",
            (replay_key,),
        ).fetchone()
        if row is None:
            return None
        intent, status, finalized_at_ns = self._promotion_intent_from_row(row)
        if intent.replay_key != replay_key:
            raise ValueError("promotion_intent_replay_row_mismatch")
        return intent, status, finalized_at_ns

    def read_pending_promotion_intents(
        self, *, limit: int = 256,
    ) -> tuple[PromotionIntentRecord, ...]:
        if type(limit) is not int or type(limit) is bool or limit <= 0 or limit > 4096:
            raise ValueError("promotion_intent_limit_invalid")
        connection = self._lifecycle.connection("candidate")
        rows = connection.execute(
            "SELECT intent_json,intent_sha256,status,finalized_at_ns FROM promotion_intents "
            "WHERE status='pending' ORDER BY created_at_ns,promotion_intent_id LIMIT ?",
            (limit,),
        ).fetchall()
        result: list[PromotionIntentRecord] = []
        for row in rows:
            intent, status, _finalized_at_ns = self._promotion_intent_from_row(row)
            if status != "pending":
                raise ValueError("promotion_intent_pending_query_inconsistent")
            result.append(intent)
        return tuple(result)

    def finalize_promotion_intent(
        self, connection: object, *, promotion_intent_id: str,
        status: str, finalized_at_ns: int,
    ) -> None:
        if type(promotion_intent_id) is not str or len(promotion_intent_id) != 64:
            raise ValueError("promotion_intent_id_invalid")
        if status not in {"finalized", "aborted"}:
            raise ValueError("promotion_intent_terminal_status_invalid")
        if type(finalized_at_ns) is not int or type(finalized_at_ns) is bool or finalized_at_ns <= 0:
            raise ValueError("promotion_intent_finalized_at_invalid")
        row = connection.execute(
            "SELECT intent_json,intent_sha256,status,finalized_at_ns FROM promotion_intents "
            "WHERE promotion_intent_id=?",
            (promotion_intent_id,),
        ).fetchone()
        if row is None:
            raise ValueError("promotion_intent_missing")
        intent, current_status, current_finalized = self._promotion_intent_from_row(row)
        if intent.promotion_intent_id != promotion_intent_id:
            raise ValueError("promotion_intent_row_identity_mismatch")
        if current_status == status:
            if current_finalized <= 0:
                raise ValueError("promotion_intent_terminal_time_invalid")
            return
        if current_status != "pending":
            raise ValueError("promotion_intent_terminal_transition_invalid")
        connection.execute(
            "UPDATE promotion_intents SET status=?,finalized_at_ns=? "
            "WHERE promotion_intent_id=? AND status='pending'",
            (status, finalized_at_ns, promotion_intent_id),
        )
        if int(connection.execute("SELECT changes()").fetchone()[0]) != 1:
            raise ValueError("promotion_intent_terminal_transition_failed")

    def write_model_candidate_manifest(
        self, connection: object, manifest: ModelCandidateQuarantineManifest,
    ) -> str:
        if type(manifest) is not ModelCandidateQuarantineManifest:
            raise TypeError("model_candidate_quarantine_manifest_required")
        record = manifest.to_record()
        payload, digest = self._record_payload(record)
        existing = connection.execute(
            "SELECT manifest_sha256 FROM model_candidate_quarantine WHERE candidate_id=?",
            (manifest.candidate_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise ValueError("model_candidate_manifest_identity_conflict")
            return manifest.candidate_id
        connection.execute(
            "INSERT INTO model_candidate_quarantine("
            "candidate_id,manifest_schema_version,payload_sha256,payload_size,payload_object_key,"
            "trainer_version,code_source_generation,feature_schema_identity,dependency_graph_identity,"
            "calibration_identity,evaluation_release_identity,parent_model_generation_id,"
            "model_id,model_version,model_schema_identity,policy_identity,admitted_at_ns,manifest_json,manifest_sha256"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                manifest.candidate_id, manifest.schema_version, manifest.payload_sha256, manifest.payload_size,
                manifest.payload_object_key, manifest.trainer_version, manifest.code_source_generation,
                manifest.feature_schema_identity, manifest.dependency_graph_identity, manifest.calibration_identity,
                manifest.evaluation_release_identity, manifest.parent_model_generation_id,
                manifest.model_id, manifest.model_version, manifest.model_schema_identity, manifest.policy_identity,
                manifest.admitted_at_ns, payload, digest,
            ),
        )
        return manifest.candidate_id

    def read_model_candidate_manifest(
        self, candidate_id: str,
    ) -> ModelCandidateQuarantineManifest | None:
        if type(candidate_id) is not str or len(candidate_id) != 64:
            raise ValueError("model_candidate_id_invalid")
        connection = self._lifecycle.connection("candidate")
        row = connection.execute(
            "SELECT manifest_json,manifest_sha256,manifest_schema_version,payload_sha256,payload_size,"
            "payload_object_key,trainer_version,code_source_generation,feature_schema_identity,"
            "dependency_graph_identity,calibration_identity,evaluation_release_identity,"
            "parent_model_generation_id,model_id,model_version,model_schema_identity,policy_identity,admitted_at_ns "
            "FROM model_candidate_quarantine WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        record = json.loads(str(row[0]))
        if canonical_record_sha256(record) != str(row[1]):
            raise ValueError("model_candidate_manifest_digest_mismatch")
        value = ModelCandidateQuarantineManifest.from_record(record)
        if value.candidate_id != candidate_id:
            raise ValueError("model_candidate_manifest_row_identity_mismatch")
        expected = (
            value.schema_version, value.payload_sha256, value.payload_size, value.payload_object_key,
            value.trainer_version, value.code_source_generation, value.feature_schema_identity,
            value.dependency_graph_identity, value.calibration_identity, value.evaluation_release_identity,
            value.parent_model_generation_id, value.model_id, value.model_version,
            value.model_schema_identity, value.policy_identity, value.admitted_at_ns,
        )
        actual = tuple(
            int(item) if index in {2, 15} else str(item)
            for index, item in enumerate(row[2:18])
        )
        if actual != expected:
            raise ValueError("model_candidate_manifest_column_mismatch")
        return value

    def write_promotion_audit(
        self, connection: object, audit: PromotionAuditRecord,
    ) -> str:
        if type(audit) is not PromotionAuditRecord:
            raise TypeError("promotion_audit_record_required")
        record = audit.to_record()
        payload, digest = self._record_payload(record)
        existing = connection.execute(
            "SELECT record_sha256 FROM promotion_audits WHERE promotion_id=?",
            (audit.promotion_id,),
        ).fetchone()
        if existing is not None:
            if str(existing[0]) != digest:
                raise ValueError("promotion_audit_identity_conflict")
            return audit.promotion_id
        connection.execute(
            "INSERT INTO promotion_audits("
            "promotion_id,schema_version,source_generation_id,proposed_target_generation_id,"
            "accepted,created_at_ns,application_version,record_json,record_sha256"
            ") VALUES(?,?,?,?,?,?,?,?,?)",
            (
                audit.promotion_id, audit.schema_version, audit.source_generation_id,
                audit.proposed_target_generation_id, int(audit.accepted), audit.created_at_ns,
                audit.application_version, payload, digest,
            ),
        )
        return audit.promotion_id

    def read_promotion_audit(self, promotion_id: str) -> PromotionAuditRecord | None:
        if type(promotion_id) is not str or len(promotion_id) != 64:
            raise ValueError("promotion_audit_id_invalid")
        connection = self._lifecycle.connection("candidate")
        row = connection.execute(
            "SELECT record_json,record_sha256,schema_version,source_generation_id,"
            "proposed_target_generation_id,accepted,created_at_ns,application_version "
            "FROM promotion_audits WHERE promotion_id=?",
            (promotion_id,),
        ).fetchone()
        if row is None:
            return None
        record = json.loads(str(row[0]))
        if canonical_record_sha256(record) != str(row[1]):
            raise ValueError("promotion_audit_record_digest_mismatch")
        value = PromotionAuditRecord.from_record(record)
        if value.promotion_id != promotion_id:
            raise ValueError("promotion_audit_row_identity_mismatch")
        expected = (
            value.schema_version, value.source_generation_id, value.proposed_target_generation_id,
            int(value.accepted), value.created_at_ns, value.application_version,
        )
        actual = (str(row[2]), str(row[3]), str(row[4]), int(row[5]), int(row[6]), str(row[7]))
        if actual != expected:
            raise ValueError("promotion_audit_column_mismatch")
        return value

    def read_staged_store(self) -> dict[str, object] | None:
        connection = self._lifecycle.connection("candidate")
        metadata = {
            str(row[0]): json.loads(str(row[1]))
            for row in connection.execute(
                "SELECT key,payload_json FROM staged_metadata ORDER BY key"
            )
        }
        if not metadata:
            return None
        store: dict[str, object] = {
            "schema_version": metadata["schema_version"],
            "candidates": {
                str(row[0]): json.loads(str(row[1]))
                for row in connection.execute(
                    "SELECT candidate_key,payload_json FROM staged_candidates ORDER BY candidate_key"
                )
            },
            "promotions": metadata["promotions"],
            "rejections": {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT reason,rejection_count FROM staged_rejections ORDER BY reason"
                )
            },
            "observation_ledger": {
                "schema_version": metadata["observation_ledger_schema"],
                "entries": {},
            },
        }
        if "retention" in metadata:
            store["retention"] = metadata["retention"]
        entries = store["observation_ledger"]["entries"]
        for row in connection.execute(
            "SELECT observation_id,observation_digest,replay_key,decision_ordinal,candidate_key,status,reason,promoted "
            "FROM staged_observations ORDER BY decision_ordinal,observation_id"
        ):
            entries[str(row[0])] = {
                "observation_id": str(row[0]),
                "observation_digest": str(row[1]),
                "replay_key": str(row[2]),
                "decision_ordinal": int(row[3]),
                "candidate_key": str(row[4]),
                "status": str(row[5]),
                "reason": str(row[6]),
                "promoted": bool(row[7]),
            }
        return store


__all__ = ("LearningCandidateRepository",)
