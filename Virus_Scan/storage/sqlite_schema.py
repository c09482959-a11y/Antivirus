"""Exact current SQLite schemas for model truth and disposable scan cache."""
from __future__ import annotations

import hashlib
from typing import Final

from Virus_Scan.storage.contracts import (
    CACHE_DATABASE_APPLICATION_ID,
    CACHE_DATABASE_SCHEMA_VERSION,
    CANDIDATE_DATABASE_APPLICATION_ID,
    CANDIDATE_DATABASE_SCHEMA_VERSION,
    MODEL_DATABASE_APPLICATION_ID,
    MODEL_DATABASE_SCHEMA_VERSION,
)

MODEL_STATE_CORE_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS database_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_ns INTEGER NOT NULL CHECK(updated_ns >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS database_generations (
        generation_id TEXT PRIMARY KEY NOT NULL,
        schema_digest TEXT NOT NULL CHECK(length(schema_digest) = 64),
        semantic_digest TEXT NOT NULL CHECK(length(semantic_digest) = 64),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0),
        status TEXT NOT NULL CHECK(status IN ('active','retired','invalid'))
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS authoritative_transactions (
        transaction_id TEXT PRIMARY KEY NOT NULL CHECK(length(transaction_id) = 64),
        transaction_kind TEXT NOT NULL CHECK(length(transaction_kind) BETWEEN 1 AND 64),
        replay_key TEXT NOT NULL DEFAULT '' CHECK(replay_key = '' OR length(replay_key) = 64),
        state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0),
        committed_ns INTEGER NOT NULL CHECK(committed_ns >= created_ns),
        status TEXT NOT NULL CHECK(status = 'committed')
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS authoritative_transaction_domains (
        transaction_id TEXT NOT NULL REFERENCES authoritative_transactions(transaction_id)
            ON UPDATE CASCADE ON DELETE CASCADE,
        domain_kind TEXT NOT NULL CHECK(length(domain_kind) BETWEEN 1 AND 64),
        domain_identity TEXT NOT NULL CHECK(length(domain_identity) BETWEEN 1 AND 4096),
        state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
        PRIMARY KEY(transaction_id, domain_kind, domain_identity)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_corruption_events (
        event_id INTEGER PRIMARY KEY,
        event_key TEXT NOT NULL UNIQUE CHECK(length(event_key) = 16),
        engine_id TEXT NOT NULL CHECK(length(engine_id) BETWEEN 1 AND 64),
        profile_scope TEXT NOT NULL CHECK(length(profile_scope) BETWEEN 1 AND 128),
        corruption_type TEXT NOT NULL CHECK(length(corruption_type) BETWEEN 1 AND 64),
        policy TEXT NOT NULL CHECK(policy IN ('hard-fail','quarantine')),
        quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)),
        scan_continued INTEGER NOT NULL CHECK(scan_continued IN (0,1)),
        event_json TEXT NOT NULL CHECK(json_valid(event_json)),
        event_sha256 TEXT NOT NULL CHECK(length(event_sha256) = 64),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_engines (
        engine_id TEXT NOT NULL CHECK(length(engine_id) BETWEEN 1 AND 64),
        profile_scope TEXT NOT NULL CHECK(length(profile_scope) BETWEEN 1 AND 128),
        profile_schema_version INTEGER NOT NULL CHECK(profile_schema_version > 0),
        created_value REAL NOT NULL,
        updated_value REAL NOT NULL,
        generation_id TEXT NOT NULL REFERENCES database_generations(generation_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        PRIMARY KEY(engine_id, profile_scope)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extensions (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL CHECK(length(baseline_key) BETWEEN 1 AND 512),
        file_count INTEGER NOT NULL CHECK(file_count >= 0),
        section_names_json TEXT NOT NULL CHECK(json_valid(section_names_json)),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_behavior_buckets (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_tags (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_tag_evidence (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_chains (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_timeline (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_risk (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_learning_gate (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_extension_vector (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        baseline_key TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, baseline_key),
        FOREIGN KEY(engine_id, profile_scope, baseline_key)
            REFERENCES profile_extensions(engine_id, profile_scope, baseline_key)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_vector_baselines (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_temporal_baselines (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_markov_baselines (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_cluster_baselines (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_learning_rejections (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_learning_applied_keys (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        state_key TEXT NOT NULL CHECK(length(state_key) BETWEEN 1 AND 512),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope, state_key),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_contamination_state (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_decision_history_state (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        PRIMARY KEY(engine_id, profile_scope),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS profile_feature_registry_versions (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        feature_name TEXT NOT NULL CHECK(length(feature_name) BETWEEN 1 AND 128),
        schema_identity TEXT NOT NULL CHECK(length(schema_identity) BETWEEN 1 AND 256),
        PRIMARY KEY(engine_id, profile_scope, feature_name),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS learning_decisions (
        transaction_id TEXT PRIMARY KEY NOT NULL CHECK(length(transaction_id) = 64),
        replay_key TEXT NOT NULL UNIQUE CHECK(length(replay_key) = 64),
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        content_sha256 TEXT NOT NULL DEFAULT '' CHECK(content_sha256 = '' OR length(content_sha256) = 64),
        content_identity_status TEXT NOT NULL CHECK(content_identity_status IN ('verified','unavailable')),
        artifact_instance TEXT NOT NULL,
        model_context_digest TEXT NOT NULL CHECK(length(model_context_digest) = 64),
        observation_digest TEXT NOT NULL CHECK(length(observation_digest) = 64),
        decision_digest TEXT NOT NULL CHECK(length(decision_digest) = 64),
        decision_ordinal INTEGER NOT NULL CHECK(decision_ordinal >= 0),
        status TEXT NOT NULL CHECK(status IN ('pending','partial','complete','rejected','failed')),
        completed_targets INTEGER NOT NULL CHECK(completed_targets >= 0),
        failed_targets INTEGER NOT NULL CHECK(failed_targets >= 0),
        transaction_json TEXT NOT NULL CHECK(json_valid(transaction_json)),
        transaction_sha256 TEXT NOT NULL CHECK(length(transaction_sha256) = 64),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0),
        committed_ns INTEGER CHECK(committed_ns IS NULL OR committed_ns >= created_ns),
        UNIQUE(engine_id, profile_scope, content_sha256, model_context_digest, observation_digest),
        FOREIGN KEY(transaction_id) REFERENCES authoritative_transactions(transaction_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE RESTRICT
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS learning_targets (
        transaction_id TEXT NOT NULL REFERENCES learning_decisions(transaction_id)
            ON UPDATE CASCADE ON DELETE CASCADE,
        target_ordinal INTEGER NOT NULL CHECK(target_ordinal >= 0),
        target_name TEXT NOT NULL CHECK(length(target_name) BETWEEN 1 AND 64),
        status TEXT NOT NULL CHECK(status IN ('pending','in_progress','succeeded','failed')),
        attempts INTEGER NOT NULL CHECK(attempts >= 0),
        reason TEXT NOT NULL,
        output_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(output_json)),
        output_sha256 TEXT NOT NULL CHECK(length(output_sha256) = 64),
        PRIMARY KEY(transaction_id, target_name),
        UNIQUE(transaction_id, target_ordinal)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS content_artifact_occurrences (
        engine_id TEXT NOT NULL,
        profile_scope TEXT NOT NULL,
        content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
        artifact_instance TEXT NOT NULL CHECK(length(artifact_instance) BETWEEN 1 AND 4096),
        model_context_digest TEXT NOT NULL CHECK(length(model_context_digest) = 64),
        occurrence_count INTEGER NOT NULL CHECK(occurrence_count BETWEEN 1 AND 1000000000),
        first_decision_ordinal INTEGER NOT NULL CHECK(first_decision_ordinal >= 0),
        last_decision_ordinal INTEGER NOT NULL CHECK(last_decision_ordinal >= first_decision_ordinal),
        PRIMARY KEY(engine_id, profile_scope, content_sha256, artifact_instance, model_context_digest),
        FOREIGN KEY(engine_id, profile_scope) REFERENCES profile_engines(engine_id, profile_scope)
            ON UPDATE CASCADE ON DELETE CASCADE
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS runtime_model_metadata (
        key TEXT PRIMARY KEY NOT NULL CHECK(length(key) BETWEEN 1 AND 128),
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS markov_transitions (
        transition_key_digest TEXT NOT NULL CHECK(length(transition_key_digest) = 64),
        transition_key_json TEXT NOT NULL CHECK(json_valid(transition_key_json)),
        target_state TEXT NOT NULL CHECK(length(target_state) > 0),
        observation_count INTEGER NOT NULL CHECK(observation_count > 0),
        PRIMARY KEY(transition_key_digest, target_state)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS markov_tag_baselines (
        tag TEXT PRIMARY KEY NOT NULL,
        observation_count INTEGER NOT NULL CHECK(observation_count >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS markov_tag_pair_baselines (
        first_tag TEXT NOT NULL,
        second_tag TEXT NOT NULL,
        observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
        PRIMARY KEY(first_tag, second_tag),
        CHECK(first_tag <= second_tag)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS filetype_baselines (
        filetype_key TEXT NOT NULL,
        feature_key TEXT NOT NULL,
        observation_count INTEGER NOT NULL CHECK(observation_count >= 0),
        PRIMARY KEY(filetype_key, feature_key)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS temporal_nodes (
        node_identity TEXT PRIMARY KEY NOT NULL,
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS temporal_learning_keys (
        replay_key TEXT PRIMARY KEY NOT NULL CHECK(length(replay_key) = 64),
        decision_ordinal INTEGER NOT NULL CHECK(decision_ordinal >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS microclusters (
        cluster_id TEXT PRIMARY KEY NOT NULL,
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cluster_node_assignments (
        node_identity TEXT PRIMARY KEY NOT NULL,
        cluster_id TEXT NOT NULL REFERENCES microclusters(cluster_id)
            ON UPDATE CASCADE ON DELETE CASCADE,
        feature_vector_json TEXT CHECK(feature_vector_json IS NULL OR json_valid(feature_vector_json)),
        feature_vector_sha256 TEXT CHECK(feature_vector_sha256 IS NULL OR length(feature_vector_sha256) = 64),
        CHECK((feature_vector_json IS NULL) = (feature_vector_sha256 IS NULL))
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cluster_learning_keys (
        replay_key TEXT PRIMARY KEY NOT NULL CHECK(length(replay_key) = 64),
        decision_ordinal INTEGER NOT NULL CHECK(decision_ordinal >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS model_replay_keys (
        domain TEXT NOT NULL CHECK(length(domain) BETWEEN 1 AND 64),
        replay_key TEXT NOT NULL CHECK(length(replay_key) = 64),
        decision_ordinal INTEGER NOT NULL CHECK(decision_ordinal >= 0),
        PRIMARY KEY(domain, replay_key)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS model_events (
        event_id INTEGER PRIMARY KEY,
        event_ns INTEGER NOT NULL CHECK(event_ns >= 0),
        event_type TEXT NOT NULL,
        transaction_id TEXT,
        details_json TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(details_json)),
        FOREIGN KEY(transaction_id) REFERENCES learning_decisions(transaction_id)
            ON UPDATE CASCADE ON DELETE SET NULL
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_profile_corruption_engine ON profile_corruption_events(engine_id, profile_scope, event_id)",
    "CREATE INDEX IF NOT EXISTS idx_profile_extensions ON profile_extensions(engine_id, profile_scope)",
    "CREATE INDEX IF NOT EXISTS idx_learning_content_context ON learning_decisions(content_sha256, model_context_digest)",
    "CREATE INDEX IF NOT EXISTS idx_occurrence_content_context ON content_artifact_occurrences(content_sha256, model_context_digest)",
)

MODEL_GENERATION_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS model_generation_manifests (
        generation_id TEXT PRIMARY KEY NOT NULL CHECK(length(generation_id) = 64),
        manifest_schema_version TEXT NOT NULL CHECK(length(manifest_schema_version) BETWEEN 1 AND 128),
        manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
        manifest_sha256 TEXT NOT NULL UNIQUE CHECK(length(manifest_sha256) = 64),
        canonical_state_digest TEXT NOT NULL CHECK(length(canonical_state_digest) = 64),
        previous_generation_id TEXT NOT NULL DEFAULT ''
            CHECK(previous_generation_id = '' OR length(previous_generation_id) = 64),
        previous_generation_manifest_hash TEXT NOT NULL DEFAULT ''
            CHECK(previous_generation_manifest_hash = '' OR length(previous_generation_manifest_hash) = 64),
        promotion_transaction_id TEXT NOT NULL DEFAULT ''
            CHECK(promotion_transaction_id = '' OR length(promotion_transaction_id) = 64),
        application_model_version TEXT NOT NULL CHECK(length(application_model_version) BETWEEN 1 AND 256),
        feature_schema_identity TEXT NOT NULL CHECK(length(feature_schema_identity) BETWEEN 1 AND 256),
        policy_identity TEXT NOT NULL CHECK(length(policy_identity) BETWEEN 1 AND 256),
        dependency_graph_identity TEXT NOT NULL CHECK(length(dependency_graph_identity) BETWEEN 1 AND 256),
        evaluation_release_identity TEXT NOT NULL DEFAULT '' CHECK(length(evaluation_release_identity) <= 256),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0),
        CHECK((previous_generation_id = '') = (previous_generation_manifest_hash = ''))
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS active_model_generation (
        singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
        generation_id TEXT NOT NULL UNIQUE REFERENCES model_generation_manifests(generation_id)
            ON UPDATE RESTRICT ON DELETE RESTRICT,
        activated_ns INTEGER NOT NULL CHECK(activated_ns >= 0),
        promotion_transaction_id TEXT NOT NULL CHECK(length(promotion_transaction_id) = 64)
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_model_generation_created ON model_generation_manifests(created_ns, generation_id)",
    "CREATE INDEX IF NOT EXISTS idx_model_generation_previous ON model_generation_manifests(previous_generation_id)",
)

MODEL_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    MODEL_STATE_CORE_SCHEMA_STATEMENTS + MODEL_GENERATION_SCHEMA_STATEMENTS
)

CANDIDATE_STAGED_STATE_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS database_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_ns INTEGER NOT NULL CHECK(updated_ns >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS candidate_transactions (
        transaction_id TEXT PRIMARY KEY NOT NULL CHECK(length(transaction_id) = 64),
        transaction_kind TEXT NOT NULL CHECK(length(transaction_kind) BETWEEN 1 AND 64),
        replay_key TEXT NOT NULL DEFAULT '' CHECK(replay_key = '' OR length(replay_key) = 64),
        state_digest TEXT NOT NULL CHECK(length(state_digest) = 64),
        related_authoritative_transaction_id TEXT NOT NULL DEFAULT ''
            CHECK(related_authoritative_transaction_id = '' OR length(related_authoritative_transaction_id) = 64),
        created_ns INTEGER NOT NULL CHECK(created_ns >= 0),
        committed_ns INTEGER NOT NULL CHECK(committed_ns >= created_ns),
        status TEXT NOT NULL CHECK(status = 'committed')
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS staged_candidates (
        candidate_key TEXT PRIMARY KEY NOT NULL,
        content_sha256 TEXT NOT NULL CHECK(length(content_sha256) = 64),
        engine_id TEXT NOT NULL,
        extension TEXT NOT NULL,
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS staged_observations (
        observation_id TEXT PRIMARY KEY NOT NULL,
        observation_digest TEXT NOT NULL CHECK(length(observation_digest) = 64),
        replay_key TEXT NOT NULL CHECK(length(replay_key) = 64),
        decision_ordinal INTEGER NOT NULL CHECK(decision_ordinal >= 0),
        candidate_key TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','staged','promoted','rejected')),
        reason TEXT NOT NULL,
        promoted INTEGER NOT NULL CHECK(promoted IN (0,1)),
        CHECK(promoted = CASE WHEN status = 'promoted' THEN 1 ELSE 0 END)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS staged_rejections (
        reason TEXT PRIMARY KEY NOT NULL CHECK(length(reason) > 0),
        rejection_count INTEGER NOT NULL CHECK(rejection_count >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS staged_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_staged_content ON staged_candidates(content_sha256)",
    "CREATE INDEX IF NOT EXISTS idx_candidate_transaction_replay ON candidate_transactions(replay_key)",
)

CANDIDATE_CUSTODY_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS candidate_observations (
        candidate_id TEXT PRIMARY KEY NOT NULL CHECK(length(candidate_id) = 64),
        schema_version TEXT NOT NULL CHECK(length(schema_version) BETWEEN 1 AND 128),
        scan_id TEXT NOT NULL CHECK(length(scan_id) BETWEEN 1 AND 512),
        artifact_identity TEXT NOT NULL CHECK(length(artifact_identity) BETWEEN 1 AND 4096),
        artifact_sha256 TEXT NOT NULL CHECK(length(artifact_sha256) = 64),
        physical_target_identity TEXT NOT NULL CHECK(length(physical_target_identity) BETWEEN 1 AND 4096),
        member_identity TEXT NOT NULL DEFAULT '' CHECK(length(member_identity) <= 4096),
        evidence_ids_json TEXT NOT NULL CHECK(json_valid(evidence_ids_json)),
        evidence_snapshot_id TEXT NOT NULL CHECK(length(evidence_snapshot_id) BETWEEN 1 AND 512),
        authority_class TEXT NOT NULL CHECK(authority_class IN ('A','B')),
        evidence_type TEXT NOT NULL CHECK(length(evidence_type) BETWEEN 1 AND 256),
        producer_id TEXT NOT NULL CHECK(length(producer_id) BETWEEN 1 AND 256),
        producer_version TEXT NOT NULL CHECK(length(producer_version) BETWEEN 1 AND 256),
        model_id TEXT NOT NULL DEFAULT '' CHECK(length(model_id) <= 256),
        model_generation TEXT NOT NULL DEFAULT '' CHECK(length(model_generation) <= 256),
        external_source TEXT NOT NULL DEFAULT '' CHECK(length(external_source) <= 512),
        observed_at INTEGER NOT NULL CHECK(observed_at >= 0),
        normalized_value_json TEXT NOT NULL CHECK(json_valid(normalized_value_json)),
        confidence_context_json TEXT NOT NULL CHECK(json_valid(confidence_context_json)),
        source_independence_key TEXT NOT NULL CHECK(length(source_independence_key) = 64),
        replay_key TEXT NOT NULL CHECK(length(replay_key) = 64),
        semantic_domain TEXT NOT NULL CHECK(length(semantic_domain) BETWEEN 1 AND 256),
        proposed_effect TEXT NOT NULL CHECK(length(proposed_effect) BETWEEN 1 AND 256),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)),
        record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS model_candidate_quarantine (
        candidate_id TEXT PRIMARY KEY NOT NULL CHECK(length(candidate_id) = 64),
        manifest_schema_version TEXT NOT NULL CHECK(length(manifest_schema_version) BETWEEN 1 AND 128),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
        payload_size INTEGER NOT NULL CHECK(payload_size >= 0),
        payload_object_key TEXT NOT NULL CHECK(length(payload_object_key) BETWEEN 1 AND 80),
        trainer_version TEXT NOT NULL CHECK(length(trainer_version) BETWEEN 1 AND 256),
        code_source_generation TEXT NOT NULL CHECK(length(code_source_generation) BETWEEN 1 AND 256),
        feature_schema_identity TEXT NOT NULL CHECK(length(feature_schema_identity) BETWEEN 1 AND 256),
        dependency_graph_identity TEXT NOT NULL CHECK(length(dependency_graph_identity) BETWEEN 1 AND 256),
        calibration_identity TEXT NOT NULL DEFAULT '' CHECK(length(calibration_identity) <= 256),
        evaluation_release_identity TEXT NOT NULL CHECK(length(evaluation_release_identity) BETWEEN 1 AND 256),
        parent_model_generation_id TEXT NOT NULL DEFAULT ''
            CHECK(parent_model_generation_id = '' OR length(parent_model_generation_id) = 64),
        model_id TEXT NOT NULL CHECK(length(model_id) BETWEEN 1 AND 256),
        model_version TEXT NOT NULL CHECK(length(model_version) BETWEEN 1 AND 256),
        model_schema_identity TEXT NOT NULL CHECK(length(model_schema_identity) BETWEEN 1 AND 256),
        policy_identity TEXT NOT NULL CHECK(length(policy_identity) BETWEEN 1 AND 256),
        admitted_at_ns INTEGER NOT NULL CHECK(admitted_at_ns >= 0),
        manifest_json TEXT NOT NULL CHECK(json_valid(manifest_json)),
        manifest_sha256 TEXT NOT NULL CHECK(length(manifest_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS promotion_audits (
        promotion_id TEXT PRIMARY KEY NOT NULL CHECK(length(promotion_id) = 64),
        schema_version TEXT NOT NULL CHECK(length(schema_version) BETWEEN 1 AND 128),
        source_generation_id TEXT NOT NULL DEFAULT ''
            CHECK(source_generation_id = '' OR length(source_generation_id) = 64),
        proposed_target_generation_id TEXT NOT NULL CHECK(length(proposed_target_generation_id) = 64),
        accepted INTEGER NOT NULL CHECK(accepted IN (0,1)),
        created_at_ns INTEGER NOT NULL CHECK(created_at_ns >= 0),
        application_version TEXT NOT NULL CHECK(length(application_version) BETWEEN 1 AND 256),
        record_json TEXT NOT NULL CHECK(json_valid(record_json)),
        record_sha256 TEXT NOT NULL CHECK(length(record_sha256) = 64)
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_candidate_observation_replay ON candidate_observations(replay_key)",
    "CREATE INDEX IF NOT EXISTS idx_candidate_observation_independence ON candidate_observations(source_independence_key)",
    "CREATE INDEX IF NOT EXISTS idx_candidate_observation_artifact ON candidate_observations(artifact_sha256)",
    "CREATE INDEX IF NOT EXISTS idx_model_candidate_payload ON model_candidate_quarantine(payload_sha256)",
    "CREATE INDEX IF NOT EXISTS idx_promotion_audit_target ON promotion_audits(proposed_target_generation_id, created_at_ns)",
)

CANDIDATE_PROMOTION_LIFECYCLE_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS promotion_intents (
        promotion_intent_id TEXT PRIMARY KEY NOT NULL CHECK(length(promotion_intent_id) = 64),
        current_candidate_id TEXT NOT NULL REFERENCES candidate_observations(candidate_id)
            ON UPDATE CASCADE ON DELETE RESTRICT,
        candidate_ids_json TEXT NOT NULL CHECK(json_valid(candidate_ids_json)),
        source_generation_id TEXT NOT NULL CHECK(length(source_generation_id) = 64),
        authoritative_transaction_id TEXT NOT NULL UNIQUE CHECK(length(authoritative_transaction_id) = 64),
        replay_key TEXT NOT NULL UNIQUE CHECK(length(replay_key) = 64),
        semantic_domain TEXT NOT NULL CHECK(length(semantic_domain) BETWEEN 1 AND 256),
        proposed_effect TEXT NOT NULL CHECK(length(proposed_effect) BETWEEN 1 AND 256),
        required_independent_sources INTEGER NOT NULL CHECK(required_independent_sources > 0),
        status TEXT NOT NULL CHECK(status IN ('pending','finalized','aborted')),
        created_at_ns INTEGER NOT NULL CHECK(created_at_ns >= 0),
        finalized_at_ns INTEGER NOT NULL DEFAULT 0 CHECK(finalized_at_ns >= 0),
        intent_json TEXT NOT NULL CHECK(json_valid(intent_json)),
        intent_sha256 TEXT NOT NULL CHECK(length(intent_sha256) = 64)
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_candidate_observation_cohort "
    "ON candidate_observations(semantic_domain, proposed_effect, source_independence_key)",
    "CREATE INDEX IF NOT EXISTS idx_promotion_intent_status "
    "ON promotion_intents(status, created_at_ns, promotion_intent_id)",
)

CANDIDATE_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    CANDIDATE_STAGED_STATE_SCHEMA_STATEMENTS
    + CANDIDATE_CUSTODY_SCHEMA_STATEMENTS
    + CANDIDATE_PROMOTION_LIFECYCLE_SCHEMA_STATEMENTS
)


CACHE_SCHEMA_STATEMENTS: Final[tuple[str, ...]] = (
    """CREATE TABLE IF NOT EXISTS database_metadata (
        key TEXT PRIMARY KEY NOT NULL,
        value TEXT NOT NULL,
        updated_ns INTEGER NOT NULL CHECK(updated_ns >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_contents (
        content_sha256 TEXT PRIMARY KEY NOT NULL CHECK(length(content_sha256) = 64),
        content_size INTEGER NOT NULL CHECK(content_size >= 0),
        first_seen_ns INTEGER NOT NULL CHECK(first_seen_ns >= 0),
        last_seen_ns INTEGER NOT NULL CHECK(last_seen_ns >= first_seen_ns)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_aliases (
        alias_id INTEGER PRIMARY KEY,
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        canonical_path TEXT NOT NULL,
        archive_member TEXT NOT NULL DEFAULT '',
        file_name TEXT NOT NULL,
        fast_fingerprint TEXT NOT NULL DEFAULT '',
        stat_size INTEGER CHECK(stat_size IS NULL OR stat_size >= 0),
        stat_mtime_ns INTEGER CHECK(stat_mtime_ns IS NULL OR stat_mtime_ns >= 0),
        first_seen_ns INTEGER NOT NULL CHECK(first_seen_ns >= 0),
        last_seen_ns INTEGER NOT NULL CHECK(last_seen_ns >= first_seen_ns),
        UNIQUE(content_sha256, canonical_path, archive_member)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_execution_identities (
        identity_digest TEXT PRIMARY KEY NOT NULL CHECK(length(identity_digest) = 64),
        schema_version TEXT NOT NULL,
        payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
        payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_semantic_results (
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        identity_digest TEXT NOT NULL REFERENCES cache_execution_identities(identity_digest)
            ON UPDATE CASCADE ON DELETE CASCADE,
        result_schema TEXT NOT NULL,
        result_json TEXT NOT NULL CHECK(json_valid(result_json)),
        result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
        cached_ns INTEGER NOT NULL CHECK(cached_ns >= 0),
        last_access_ns INTEGER NOT NULL CHECK(last_access_ns >= cached_ns),
        access_count INTEGER NOT NULL DEFAULT 0 CHECK(access_count >= 0),
        integrity_status TEXT NOT NULL CHECK(integrity_status IN ('verified','unverified','invalid')),
        partial INTEGER NOT NULL DEFAULT 0 CHECK(partial IN (0,1)),
        truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1)),
        PRIMARY KEY(content_sha256, identity_digest)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_fast_fingerprints (
        fast_fingerprint TEXT PRIMARY KEY NOT NULL,
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        fingerprint_json TEXT NOT NULL CHECK(json_valid(fingerprint_json)),
        last_seen_ns INTEGER NOT NULL CHECK(last_seen_ns >= 0)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_parse_results (
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        parser_digest TEXT NOT NULL CHECK(length(parser_digest) = 64),
        result_json TEXT NOT NULL CHECK(json_valid(result_json)),
        result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
        status TEXT NOT NULL CHECK(status IN ('complete','unavailable','failed','partial','truncated')),
        cached_ns INTEGER NOT NULL CHECK(cached_ns >= 0),
        last_access_ns INTEGER NOT NULL CHECK(last_access_ns >= cached_ns),
        PRIMARY KEY(content_sha256, parser_digest)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_static_operations (
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        analysis_digest TEXT NOT NULL CHECK(length(analysis_digest) = 64),
        result_json TEXT NOT NULL CHECK(json_valid(result_json)),
        result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
        status TEXT NOT NULL CHECK(status IN ('complete','unavailable','failed','partial','truncated')),
        cached_ns INTEGER NOT NULL CHECK(cached_ns >= 0),
        last_access_ns INTEGER NOT NULL CHECK(last_access_ns >= cached_ns),
        PRIMARY KEY(content_sha256, analysis_digest)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_scanner_observations (
        content_sha256 TEXT NOT NULL REFERENCES cache_contents(content_sha256)
            ON UPDATE CASCADE ON DELETE CASCADE,
        scanner_digest TEXT NOT NULL CHECK(length(scanner_digest) = 64),
        observations_json TEXT NOT NULL CHECK(json_valid(observations_json)),
        observations_sha256 TEXT NOT NULL CHECK(length(observations_sha256) = 64),
        status TEXT NOT NULL CHECK(status IN ('complete','unavailable','failed','partial','truncated')),
        cached_ns INTEGER NOT NULL CHECK(cached_ns >= 0),
        last_access_ns INTEGER NOT NULL CHECK(last_access_ns >= cached_ns),
        PRIMARY KEY(content_sha256, scanner_digest)
    ) STRICT""",
    """CREATE TABLE IF NOT EXISTS cache_retention_policy (
        policy_id INTEGER PRIMARY KEY CHECK(policy_id = 1),
        max_contents INTEGER NOT NULL CHECK(max_contents > 0),
        max_aliases_per_content INTEGER NOT NULL CHECK(max_aliases_per_content > 0),
        max_results_per_content INTEGER NOT NULL CHECK(max_results_per_content > 0),
        max_total_bytes INTEGER NOT NULL CHECK(max_total_bytes > 0),
        max_age_seconds INTEGER NOT NULL CHECK(max_age_seconds > 0),
        updated_ns INTEGER NOT NULL CHECK(updated_ns >= 0)
    ) STRICT""",
    "CREATE INDEX IF NOT EXISTS idx_cache_alias_path ON cache_aliases(canonical_path, archive_member)",
    "CREATE INDEX IF NOT EXISTS idx_cache_alias_fast ON cache_aliases(fast_fingerprint)",
    "CREATE INDEX IF NOT EXISTS idx_cache_result_access ON cache_semantic_results(last_access_ns)",
)


def schema_digest(statements: tuple[str, ...]) -> str:
    canonical = "\n".join(" ".join(statement.split()) for statement in statements)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


MODEL_SCHEMA_DIGEST: Final[str] = schema_digest(MODEL_SCHEMA_STATEMENTS)
CANDIDATE_SCHEMA_DIGEST: Final[str] = schema_digest(CANDIDATE_SCHEMA_STATEMENTS)
CACHE_SCHEMA_DIGEST: Final[str] = schema_digest(CACHE_SCHEMA_STATEMENTS)

MODEL_PRAGMAS: Final[tuple[str, ...]] = (
    f"PRAGMA application_id = {MODEL_DATABASE_APPLICATION_ID}",
    f"PRAGMA user_version = {MODEL_DATABASE_SCHEMA_VERSION}",
)
CANDIDATE_PRAGMAS: Final[tuple[str, ...]] = (
    f"PRAGMA application_id = {CANDIDATE_DATABASE_APPLICATION_ID}",
    f"PRAGMA user_version = {CANDIDATE_DATABASE_SCHEMA_VERSION}",
)
CACHE_PRAGMAS: Final[tuple[str, ...]] = (
    f"PRAGMA application_id = {CACHE_DATABASE_APPLICATION_ID}",
    f"PRAGMA user_version = {CACHE_DATABASE_SCHEMA_VERSION}",
)

__all__ = (
    "CACHE_PRAGMAS",
    "CANDIDATE_PRAGMAS",
    "CANDIDATE_SCHEMA_DIGEST",
    "CANDIDATE_SCHEMA_STATEMENTS",
    "CANDIDATE_STAGED_STATE_SCHEMA_STATEMENTS",
    "CACHE_SCHEMA_DIGEST",
    "CACHE_SCHEMA_STATEMENTS",
    "MODEL_GENERATION_SCHEMA_STATEMENTS",
    "CANDIDATE_CUSTODY_SCHEMA_STATEMENTS",
    "CANDIDATE_PROMOTION_LIFECYCLE_SCHEMA_STATEMENTS",
    "MODEL_PRAGMAS",
    "MODEL_SCHEMA_DIGEST",
    "MODEL_SCHEMA_STATEMENTS",
    "MODEL_STATE_CORE_SCHEMA_STATEMENTS",
    "schema_digest",
)
