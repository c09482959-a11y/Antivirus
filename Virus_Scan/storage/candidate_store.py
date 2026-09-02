"""Single non-authoritative learning-candidate custody owner."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from threading import RLock
import time

from Virus_Scan.storage.candidate_repository import LearningCandidateRepository
from Virus_Scan.storage.model_generation_contracts import (
    CandidateObservation,
    ModelCandidateQuarantineManifest,
    PromotionAuditRecord,
    PromotionIntentRecord,
    canonical_record_sha256,
)
from Virus_Scan.storage.sqlite_lifecycle import SQLiteLifecycleOwner, sqlite_lifecycle


def _digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _transaction_identity(*, transaction_kind: str, replay_key: str, state_digest: str) -> str:
    return hashlib.sha256(
        (
            "candidate:" + transaction_kind + ":" + replay_key + ":" + state_digest
        ).encode("utf-8")
    ).hexdigest()


class LearningCandidateStoreOwner:
    """Own candidate/quarantine persistence without model authority."""

    def __init__(self, lifecycle: SQLiteLifecycleOwner | None = None) -> None:
        self._lifecycle = sqlite_lifecycle() if lifecycle is None else lifecycle
        self._repository = LearningCandidateRepository(self._lifecycle)
        self._lock = RLock()

    def configure(self, profiles_dir: object) -> None:
        self._lifecycle.configure(profiles_dir)

    def database_path(self) -> str:
        return str(self._lifecycle.paths().learning_candidates)

    def read_staged_store(self) -> dict[str, object] | None:
        return self._repository.read_staged_store()

    def _record_custody_transaction(
        self, connection: object, *, transaction_kind: str, replay_key: str,
        state_digest: str, related_authoritative_transaction_id: str = "",
    ) -> str:
        transaction_id = _transaction_identity(
            transaction_kind=transaction_kind, replay_key=replay_key,
            state_digest=state_digest,
        )
        now_ns = time.time_ns()
        existing = connection.execute(
            "SELECT state_digest,status,related_authoritative_transaction_id "
            "FROM candidate_transactions WHERE transaction_id=?",
            (transaction_id,),
        ).fetchone()
        if existing is not None:
            if (
                str(existing[0]) != state_digest
                or str(existing[1]) != "committed"
                or str(existing[2]) != related_authoritative_transaction_id
            ):
                raise ValueError("candidate_transaction_identity_conflict")
            return transaction_id
        connection.execute(
            "INSERT INTO candidate_transactions("
            "transaction_id,transaction_kind,replay_key,state_digest,"
            "related_authoritative_transaction_id,created_ns,committed_ns,status"
            ") VALUES(?,?,?,?,?,?,?,?)",
            (
                transaction_id, transaction_kind, replay_key, state_digest,
                related_authoritative_transaction_id, now_ns, now_ns, "committed",
            ),
        )
        return transaction_id

    def record_candidate_observation(self, observation: CandidateObservation) -> str:
        if type(observation) is not CandidateObservation:
            raise TypeError("candidate_observation_required")
        record = observation.to_record()
        state_digest = canonical_record_sha256(record)
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                self._repository.write_candidate_observation(connection, observation)
                self._record_custody_transaction(
                    connection, transaction_kind="candidate_observation",
                    replay_key=observation.replay_key, state_digest=state_digest,
                )
        return observation.candidate_id

    def read_candidate_observation(self, candidate_id: str) -> CandidateObservation | None:
        return self._repository.read_candidate_observation(candidate_id)

    def read_candidate_observation_by_replay_key(
        self, replay_key: str,
    ) -> CandidateObservation | None:
        return self._repository.read_candidate_observation_by_replay_key(replay_key)

    def independent_candidate_ids(
        self, *, semantic_domain: str, proposed_effect: str, limit: int,
    ) -> tuple[str, ...]:
        return self._repository.independent_candidate_ids(
            semantic_domain=semantic_domain, proposed_effect=proposed_effect, limit=limit,
        )

    def record_promotion_intent(self, intent: PromotionIntentRecord) -> str:
        if type(intent) is not PromotionIntentRecord:
            raise TypeError("promotion_intent_record_required")
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                self._repository.write_promotion_intent(connection, intent)
        return intent.promotion_intent_id

    def read_promotion_intent(
        self, promotion_intent_id: str,
    ) -> tuple[PromotionIntentRecord, str, int] | None:
        return self._repository.read_promotion_intent(promotion_intent_id)

    def read_promotion_intent_by_replay_key(
        self, replay_key: str,
    ) -> tuple[PromotionIntentRecord, str, int] | None:
        return self._repository.read_promotion_intent_by_replay_key(replay_key)

    def pending_promotion_intents(
        self, *, limit: int = 256,
    ) -> tuple[PromotionIntentRecord, ...]:
        return self._repository.read_pending_promotion_intents(limit=limit)

    def finalize_promotion_intent(
        self, promotion_intent_id: str, *, status: str,
    ) -> None:
        now_ns = time.time_ns()
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                self._repository.finalize_promotion_intent(
                    connection,
                    promotion_intent_id=promotion_intent_id,
                    status=status,
                    finalized_at_ns=now_ns,
                )

    def record_model_candidate_manifest(
        self, manifest: ModelCandidateQuarantineManifest,
    ) -> str:
        if type(manifest) is not ModelCandidateQuarantineManifest:
            raise TypeError("model_candidate_quarantine_manifest_required")
        record = manifest.to_record()
        state_digest = canonical_record_sha256(record)
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                self._repository.write_model_candidate_manifest(connection, manifest)
                self._record_custody_transaction(
                    connection, transaction_kind="model_candidate_quarantine",
                    replay_key="", state_digest=state_digest,
                )
        return manifest.candidate_id

    def read_model_candidate_manifest(
        self, candidate_id: str,
    ) -> ModelCandidateQuarantineManifest | None:
        return self._repository.read_model_candidate_manifest(candidate_id)

    def record_promotion_audit(
        self, audit: PromotionAuditRecord, *,
        related_authoritative_transaction_id: str = "",
    ) -> str:
        if type(audit) is not PromotionAuditRecord:
            raise TypeError("promotion_audit_record_required")
        if (
            type(related_authoritative_transaction_id) is not str
            or (related_authoritative_transaction_id and len(related_authoritative_transaction_id) != 64)
        ):
            raise ValueError("candidate_related_authoritative_transaction_invalid")
        record = audit.to_record()
        state_digest = canonical_record_sha256(record)
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                self._repository.write_promotion_audit(connection, audit)
                self._record_custody_transaction(
                    connection, transaction_kind="promotion_audit", replay_key="",
                    state_digest=state_digest,
                    related_authoritative_transaction_id=related_authoritative_transaction_id,
                )
        return audit.promotion_id

    def read_promotion_audit(self, promotion_id: str) -> PromotionAuditRecord | None:
        return self._repository.read_promotion_audit(promotion_id)

    def commit_staged_store(
        self, store: Mapping[str, object], *, transaction_kind: str,
        replay_key: str = "", related_authoritative_transaction_id: str = "",
    ) -> str:
        if type(transaction_kind) is not str or not transaction_kind:
            raise ValueError("candidate_transaction_kind_invalid")
        if type(replay_key) is not str or (replay_key and len(replay_key) != 64):
            raise ValueError("candidate_replay_key_invalid")
        if (
            type(related_authoritative_transaction_id) is not str
            or (
                related_authoritative_transaction_id
                and len(related_authoritative_transaction_id) != 64
            )
        ):
            raise ValueError("candidate_related_authoritative_transaction_invalid")
        state_digest = _digest(store)
        transaction_id = _transaction_identity(
            transaction_kind=transaction_kind,
            replay_key=replay_key,
            state_digest=state_digest,
        )
        now_ns = time.time_ns()
        with self._lock:
            with self._lifecycle.transaction("candidate") as connection:
                existing = connection.execute(
                    "SELECT state_digest,status,related_authoritative_transaction_id "
                    "FROM candidate_transactions WHERE transaction_id=?",
                    (transaction_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing[0]) != state_digest
                        or str(existing[1]) != "committed"
                        or str(existing[2]) != related_authoritative_transaction_id
                    ):
                        raise ValueError("candidate_transaction_identity_conflict")
                    return transaction_id
                self._repository.write_staged_store(connection, store)
                connection.execute(
                    "INSERT INTO candidate_transactions(transaction_id,transaction_kind,replay_key,state_digest,"
                    "related_authoritative_transaction_id,created_ns,committed_ns,status) VALUES(?,?,?,?,?,?,?,?)",
                    (
                        transaction_id, transaction_kind, replay_key, state_digest,
                        related_authoritative_transaction_id, now_ns, now_ns, "committed",
                    ),
                )
        return transaction_id


_CANDIDATE_STORE = LearningCandidateStoreOwner()


def learning_candidate_store() -> LearningCandidateStoreOwner:
    return _CANDIDATE_STORE


__all__ = ("LearningCandidateStoreOwner", "learning_candidate_store")
