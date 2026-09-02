from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from Virus_Scan.models.profiles.staged_store_schema import default_staged_benign_store
from Virus_Scan.storage.candidate_store import LearningCandidateStoreOwner
from Virus_Scan.storage.contracts import DatabaseGeneration
from Virus_Scan.storage.model_generation_contracts import (
    CANDIDATE_OBSERVATION_SCHEMA_VERSION,
    MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION,
    MODEL_GENERATION_MANIFEST_SCHEMA_VERSION,
    PROMOTION_AUDIT_SCHEMA_VERSION,
    PROMOTION_INTENT_SCHEMA_VERSION,
    CandidateObservation,
    ModelCandidateQuarantineManifest,
    ModelGenerationManifest,
    PromotionAuditRecord,
    PromotionIntentRecord,
)
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleError, SQLiteLifecycleOwner


def _candidate_observation() -> CandidateObservation:
    return CandidateObservation.build(
        scan_id="scan-1",
        artifact_identity="sha256:" + "1" * 64,
        artifact_sha256="1" * 64,
        physical_target_identity="file:fixture.exe",
        evidence_ids=("evidence-a", "evidence-b"),
        evidence_snapshot_id="snapshot-1",
        authority_class="A",
        evidence_type="static_operation",
        producer_id="fixture-scanner",
        producer_version="1",
        observed_at=123,
        normalized_value={"operation": "process_open", "target": "lsass"},
        confidence_context=(("directness", "direct"), ("integrity", "verified")),
        source_independence_key="2" * 64,
        replay_key="3" * 64,
        semantic_domain="credential_access",
        proposed_effect="candidate_profile_update",
    )


def _model_candidate() -> ModelCandidateQuarantineManifest:
    payload = "4" * 64
    return ModelCandidateQuarantineManifest.build(
        payload_sha256=payload,
        payload_size=4096,
        payload_object_key="sha256:" + payload,
        trainer_version="trainer-v1",
        code_source_generation="source-generation-1",
        feature_schema_identity="feature-schema-v1",
        dataset_manifest_ids=("dataset-a", "dataset-b"),
        split_manifest_ids=("split-a",),
        dependency_graph_identity="dependency-v1",
        calibration_identity="calibration-v1",
        evaluation_release_identity="evaluation-v1",
        parent_model_generation_id="",
        model_id="profiles",
        model_version="profile-model-v1",
        model_schema_identity="model-schema-v1",
        policy_identity="policy-v1",
        admitted_at_ns=456,
    )


def _promotion_intent(observation: CandidateObservation) -> PromotionIntentRecord:
    candidate_ids = tuple(sorted((observation.candidate_id, "a" * 64, "b" * 64)))
    return PromotionIntentRecord.build(
        current_candidate_id=observation.candidate_id,
        candidate_ids=candidate_ids,
        source_generation_id="6" * 64,
        authoritative_transaction_id="7" * 64,
        replay_key=observation.replay_key,
        semantic_domain=observation.semantic_domain,
        proposed_effect=observation.proposed_effect,
        required_independent_sources=3,
        created_at_ns=700,
    )


def _promotion_audit(*, accepted: bool = True) -> PromotionAuditRecord:
    return PromotionAuditRecord.build(
        candidate_ids=("5" * 64,),
        source_generation_id="6" * 64,
        proposed_target_generation_id="7" * 64,
        accepted=accepted,
        rejection_reasons=() if accepted else ("semantic_validation_failed",),
        semantic_validators_executed=("provenance", "semantic"),
        bounds_evaluated=("artifact_cap", "source_cap"),
        replay_decision="unique",
        independence_decision="independent",
        provenance_roots=("physical-root-a",),
        state_delta_summary={"profiles": 1, "markov": 0},
        created_at_ns=789,
        application_version="stage2758",
        model_versions=(("profiles", "v1"),),
    )


def _model_manifest() -> ModelGenerationManifest:
    return ModelGenerationManifest.build(
        application_model_version="stage2758",
        created_at_ns=999,
        previous_generation_id="8" * 64,
        previous_generation_manifest_hash="9" * 64,
        canonical_state_digest="a" * 64,
        promotion_transaction_id="b" * 64,
        feature_schema_identity="feature-schema-v1",
        policy_identity="policy-v1",
        dependency_graph_identity="dependency-v1",
        evaluation_release_identity="evaluation-v1",
    )


def test_phase4_candidate_observation_is_exact_current_immutable_and_label_free() -> None:
    observation = _candidate_observation()
    record = observation.to_record()

    assert record["schema_version"] == CANDIDATE_OBSERVATION_SCHEMA_VERSION
    assert record["authority_class"] == "A"
    assert "corpus_intent_reference" not in record
    assert CandidateObservation.from_record(record) == observation

    stale = dict(record)
    stale["schema_version"] = "candidate_observation_v0"
    with pytest.raises(ValueError, match="schema_unsupported"):
        CandidateObservation.from_record(stale)

    injected = dict(record)
    injected["corpus_intent_reference"] = "forbidden"
    with pytest.raises(ValueError, match="record_invalid"):
        CandidateObservation.from_record(injected)

    obsolete_time_name = dict(record)
    obsolete_time_name["observed_at_ns"] = obsolete_time_name.pop("observed_at")
    with pytest.raises(ValueError, match="record_invalid"):
        CandidateObservation.from_record(obsolete_time_name)

    changed = dict(record)
    changed["semantic_domain"] = "different"
    with pytest.raises(ValueError, match="identity_mismatch"):
        CandidateObservation.from_record(changed)


def test_phase4_promotion_intent_is_exact_current_immutable_and_fail_closed() -> None:
    observation = _candidate_observation()
    intent = _promotion_intent(observation)
    record = intent.to_record()

    assert record["schema_version"] == PROMOTION_INTENT_SCHEMA_VERSION
    assert PromotionIntentRecord.from_record(record) == intent
    stale = dict(record)
    stale["schema_version"] = "promotion_intent_v0"
    with pytest.raises(ValueError, match="schema_unsupported"):
        PromotionIntentRecord.from_record(stale)
    changed = dict(record)
    changed["required_independent_sources"] = 2
    with pytest.raises(ValueError, match="identity_mismatch"):
        PromotionIntentRecord.from_record(changed)
    insufficient = dict(record)
    insufficient["candidate_ids"] = [observation.candidate_id]
    insufficient["promotion_intent_id"] = hashlib.sha256(
        json.dumps(
            {key: value for key, value in insufficient.items() if key != "promotion_intent_id"},
            sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValueError, match="independent_support_insufficient"):
        PromotionIntentRecord.from_record(insufficient)


def test_phase4_promotion_intent_persists_only_in_candidate_db_and_transitions_once(
    tmp_path: Path,
) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    store = LearningCandidateStoreOwner(lifecycle)
    model_before = tuple(lifecycle.connection("model").iterdump())
    observation = _candidate_observation()
    store.record_candidate_observation(observation)
    # The intent cohort is allowed to refer to immutable candidate identities whose
    # support rows are verified by the promotion owner before this intent is minted.
    # Insert two distinct candidate observations so the test mirrors that invariant.
    for suffix, source_key in (("a", "4"), ("b", "5")):
        extra = CandidateObservation.build(
            scan_id="scan-" + suffix,
            artifact_identity="sha256:" + suffix * 64,
            artifact_sha256=suffix * 64,
            physical_target_identity="file:" + suffix + ".exe",
            evidence_ids=("evidence-" + suffix,),
            evidence_snapshot_id="snapshot-" + suffix,
            authority_class="A",
            evidence_type="static_operation",
            producer_id="fixture-scanner",
            producer_version="1",
            observed_at=123,
            normalized_value={"operation": "process_open", "target": "lsass"},
            confidence_context=(("directness", "direct"),),
            source_independence_key=source_key * 64,
            replay_key=("8" if suffix == "a" else "9") * 64,
            semantic_domain=observation.semantic_domain,
            proposed_effect=observation.proposed_effect,
        )
        store.record_candidate_observation(extra)
    candidate_ids = store.independent_candidate_ids(
        semantic_domain=observation.semantic_domain,
        proposed_effect=observation.proposed_effect,
        limit=3,
    )
    intent = PromotionIntentRecord.build(
        current_candidate_id=observation.candidate_id,
        candidate_ids=tuple(sorted(candidate_ids)),
        source_generation_id="6" * 64,
        authoritative_transaction_id="7" * 64,
        replay_key=observation.replay_key,
        semantic_domain=observation.semantic_domain,
        proposed_effect=observation.proposed_effect,
        required_independent_sources=3,
        created_at_ns=700,
    )
    assert store.record_promotion_intent(intent) == intent.promotion_intent_id
    restored = store.read_promotion_intent(intent.promotion_intent_id)
    assert restored == (intent, "pending", 0)
    assert store.read_promotion_intent_by_replay_key(intent.replay_key) == restored
    assert store.pending_promotion_intents() == (intent,)
    store.finalize_promotion_intent(intent.promotion_intent_id, status="finalized")
    terminal = store.read_promotion_intent(intent.promotion_intent_id)
    assert terminal is not None and terminal[0] == intent and terminal[1] == "finalized"
    assert terminal[2] > 0
    assert store.pending_promotion_intents() == ()
    store.finalize_promotion_intent(intent.promotion_intent_id, status="finalized")
    with pytest.raises(ValueError, match="terminal_transition_invalid"):
        store.finalize_promotion_intent(intent.promotion_intent_id, status="aborted")
    assert tuple(lifecycle.connection("model").iterdump()) == model_before
    lifecycle.close()


def test_phase4_candidate_custody_records_persist_only_in_candidate_database(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    store = LearningCandidateStoreOwner(lifecycle)
    model_before = tuple(lifecycle.connection("model").iterdump())

    observation = _candidate_observation()
    candidate = _model_candidate()
    audit = _promotion_audit()

    assert store.record_candidate_observation(observation) == observation.candidate_id
    assert store.record_model_candidate_manifest(candidate) == candidate.candidate_id
    assert store.record_promotion_audit(audit) == audit.promotion_id
    assert store.read_candidate_observation(observation.candidate_id) == observation
    assert store.read_model_candidate_manifest(candidate.candidate_id) == candidate
    assert store.read_promotion_audit(audit.promotion_id) == audit

    candidate_tables = {
        str(row[0])
        for row in lifecycle.connection("candidate").execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    assert {
        "candidate_observations",
        "model_candidate_quarantine",
        "promotion_audits",
    }.issubset(candidate_tables)
    assert tuple(lifecycle.connection("model").iterdump()) == model_before
    lifecycle.close()


def test_phase4_candidate_custody_detects_post_write_payload_tamper(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    store = LearningCandidateStoreOwner(lifecycle)
    observation = _candidate_observation()
    store.record_candidate_observation(observation)

    with lifecycle.transaction("candidate") as connection:
        record = observation.to_record()
        record["semantic_domain"] = "tampered"
        connection.execute(
            "UPDATE candidate_observations SET record_json=? WHERE candidate_id=?",
            (json.dumps(record, sort_keys=True, separators=(",", ":")), observation.candidate_id),
        )

    with pytest.raises(ValueError, match="record_digest_mismatch"):
        store.read_candidate_observation(observation.candidate_id)
    lifecycle.close()


def test_phase4_model_candidate_and_promotion_audit_schemas_are_fail_closed() -> None:
    candidate = _model_candidate()
    assert candidate.to_record()["schema_version"] == MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION
    assert candidate.payload_object_key == "sha256:" + candidate.payload_sha256
    assert ModelCandidateQuarantineManifest.from_record(candidate.to_record()) == candidate

    candidate_stale = candidate.to_record()
    candidate_stale["schema_version"] = "model_candidate_quarantine_v0"
    with pytest.raises(ValueError, match="schema_unsupported"):
        ModelCandidateQuarantineManifest.from_record(candidate_stale)

    audit = _promotion_audit(accepted=False)
    assert audit.to_record()["schema_version"] == PROMOTION_AUDIT_SCHEMA_VERSION
    assert PromotionAuditRecord.from_record(audit.to_record()) == audit

    invalid = audit.to_record()
    invalid["rejection_reasons"] = []
    with pytest.raises(ValueError, match="rejection_reason_required"):
        PromotionAuditRecord.from_record(invalid)



def test_phase4_model_candidate_binds_model_identity_and_version() -> None:
    candidate = _model_candidate()
    record = candidate.to_record()
    assert record["model_id"] == "profiles"
    assert record["model_version"] == "profile-model-v1"
    missing = dict(record)
    missing.pop("model_id")
    with pytest.raises(ValueError, match="record_invalid"):
        ModelCandidateQuarantineManifest.from_record(missing)


def test_phase4_candidate_relational_projection_tamper_fails_closed(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    store = LearningCandidateStoreOwner(lifecycle)
    observation = _candidate_observation()
    store.record_candidate_observation(observation)
    with lifecycle.transaction("candidate") as connection:
        connection.execute(
            "UPDATE candidate_observations SET semantic_domain='tampered' WHERE candidate_id=?",
            (observation.candidate_id,),
        )
    with pytest.raises(ValueError, match="candidate_observation_column_mismatch"):
        store.read_candidate_observation(observation.candidate_id)
    lifecycle.close()


def test_phase4_model_candidate_and_promotion_audit_projection_tamper_fails_closed(tmp_path: Path) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    store = LearningCandidateStoreOwner(lifecycle)
    candidate = _model_candidate()
    store.record_model_candidate_manifest(candidate)
    with lifecycle.transaction("candidate") as connection:
        connection.execute(
            "UPDATE model_candidate_quarantine SET model_version='tampered' WHERE candidate_id=?",
            (candidate.candidate_id,),
        )
    with pytest.raises(ValueError, match="model_candidate_manifest_column_mismatch"):
        store.read_model_candidate_manifest(candidate.candidate_id)

    audit = _promotion_audit(accepted=False)
    store.record_promotion_audit(audit)
    with lifecycle.transaction("candidate") as connection:
        connection.execute(
            "UPDATE promotion_audits SET application_version='tampered' WHERE promotion_id=?",
            (audit.promotion_id,),
        )
    with pytest.raises(ValueError, match="promotion_audit_column_mismatch"):
        store.read_promotion_audit(audit.promotion_id)
    lifecycle.close()

def test_phase4_model_generation_manifest_is_distinct_from_database_generation() -> None:
    manifest = _model_manifest()
    record = manifest.to_record()
    assert record["schema_version"] == MODEL_GENERATION_MANIFEST_SCHEMA_VERSION
    assert len(manifest.manifest_sha256()) == 64
    assert ModelGenerationManifest.from_record(record) == manifest
    assert not isinstance(manifest, DatabaseGeneration)

    changed = dict(record)
    changed["canonical_state_digest"] = "c" * 64
    with pytest.raises(ValueError, match="identity_mismatch"):
        ModelGenerationManifest.from_record(changed)

    lineage_broken = dict(record)
    lineage_broken["previous_generation_manifest_hash"] = ""
    with pytest.raises(ValueError, match="lineage_incomplete"):
        ModelGenerationManifest.from_record(lineage_broken)



@pytest.mark.parametrize(
    ("kind", "stale_versions"),
    (("model", (1, 2)), ("candidate", (1, 2, 3))),
)
def test_phase4_existing_sqlite_schema_admission_is_exact_current_only(
    tmp_path: Path, kind: str, stale_versions: tuple[int, ...],
) -> None:
    profiles = tmp_path / "profiles"
    for stale_version in stale_versions:
        current = SQLiteLifecycleOwner()
        current.configure(profiles)
        connection = current.connection(kind)
        connection.execute(
            "UPDATE database_metadata SET value=?,updated_ns=? WHERE key='schema_version'",
            (str(stale_version), 1),
        )
        connection.execute(f"PRAGMA user_version = {stale_version}")
        current.close()

        rejected = SQLiteLifecycleOwner()
        rejected.configure(profiles)
        with pytest.raises(SQLiteLifecycleError, match="sqlite_database_identity_mismatch"):
            rejected.generation(kind)
        rejected.close()

        # Recreate a current database for the next stale-version case; stale state is
        # deliberately not auto-migrated or treated as a recoverable runtime format.
        path = profiles / (
            "model_state.sqlite3" if kind == "model" else "learning_candidates.sqlite3"
        )
        for suffix in ("", "-wal", "-shm"):
            candidate_path = Path(str(path) + suffix)
            candidate_path.unlink(missing_ok=True)


def test_phase4_current_candidate_schema_preserves_canonical_staged_and_custody_roles(
    tmp_path: Path,
) -> None:
    lifecycle = SQLiteLifecycleOwner()
    lifecycle.configure(tmp_path / "profiles")
    candidate = lifecycle.connection("candidate")
    tables = {
        str(row[0]) for row in candidate.execute(
            "SELECT name FROM sqlite_schema WHERE type='table'"
        )
    }
    assert {
        "candidate_transactions",
        "staged_candidates",
        "staged_observations",
        "staged_rejections",
        "staged_metadata",
        "candidate_observations",
        "model_candidate_quarantine",
        "promotion_audits",
        "promotion_intents",
    }.issubset(tables)
    assert lifecycle.integrity_check("candidate").ok is True
    lifecycle.close()
