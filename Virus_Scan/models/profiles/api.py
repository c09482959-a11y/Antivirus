from Virus_Scan.runtime.profile_scoring_state import profile_scoring_state as profile_scoring_state_owner
from Virus_Scan.models.api.profile_retention_contracts import (
    prune_engine_profile_for_retention,
    prune_extension_baseline_for_retention,
    prune_staged_benign_store,
)
from Virus_Scan.runtime.init_state import get_init_value as runtime_init_value
from Virus_Scan.models.api.learning_context_contracts import learning_guard
from Virus_Scan.runtime.environment import runtime_worker_shared_persistence_writes_disabled
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.schema import (
    EngineProfileSchemaSnapshot,
    ProfileSchemaInvariantError,
    validate_engine_profile_schema,
)
from Virus_Scan.models.profiles.context import (
    contextual_profile_baseline_key,
    contextual_profile_learning_policy,
)
from Virus_Scan.models.profiles.snapshots import default_engine_profile, default_extension_baseline
from Virus_Scan.models.profiles.corruption import (
    ProfileCorruptionEvidence,
    configure_engine_profile_corruption_policy,
)
from Virus_Scan.models.profiles.quarantine import profile_corruption_events_snapshot
from Virus_Scan.models.profiles.baseline import (
    CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS,
    apply_library_behavior_baseline,
    get_extension_baseline,
    profile_behavior_bucket_validation,
)
from Virus_Scan.models.profiles.vector_anomaly import vector_baseline_anomaly
from Virus_Scan.models.profiles.common import (
    PROFILE_PUBLIC_INPUT_ERRORS,
    profile_mapping_items,
    profile_public_tags,
)
from Virus_Scan.models.profiles.learning import (
    behavior_vector_from_scan,
    canonical_behavior_flow_from_sources,
    canonical_profile_learning_flow,
    learning_verdict_is_clean,
    real_ordered_event_names,
)
from Virus_Scan.models.profiles.persistence import (
    BULK_DEFER_PROFILE_WRITES,
    DEFAULT_ENGINES,
    PROFILE_SCHEMA_VERSION,
    flush_profile_writes,
    get_scoring_profile,
    load_engine_profile,
    save_engine_profile,
)
from Virus_Scan.models.profiles.replay_learning import (
    flush_benign_candidate_store,
    get_benign_candidate_store,
    load_benign_candidate_store,
    mark_benign_candidate_store_dirty,
    save_benign_candidate_store,
)
from Virus_Scan.models.profiles.adaptive_signal import (
    adaptive_profile_signal,
    engine_extension_key,
    extension_profile_anomaly,
    infer_profile_engine,
    profile_prior_for_scoring,
)
from Virus_Scan.models.profiles.anomaly_frequency import (
    behavior_bucket_frequency_evidence,
    extension_chain_frequency_evidence,
    extension_tag_frequency_evidence,
)
from Virus_Scan.models.profiles.coordinated_validation import coordinated_model_validation_signal
from Virus_Scan.models.profiles.timeline import extension_timeline_anomaly, timeline_transitions
from Virus_Scan.models.profiles.learning_gate import (
    baseline_maturity_report,
    record_learning_rejection,
    should_learn_scan_result,
    triage_learning_block_hits,
)
from Virus_Scan.models.profiles.commit import (
    commit_promoted_learning,
    update_profile_from_scan_result,
)


profile_runtime_worker_shared_persistence_write_policy_owner = runtime_worker_shared_persistence_writes_disabled

ADAPTIVE_WEIGHT_MIN_HISTORY = int(runtime_init_value('ADAPTIVE_WEIGHT_MIN_HISTORY') or 5)
MIN_CLUSTER_SIZE = int(runtime_init_value('MIN_CLUSTER_SIZE') or 2)
BEHAVIOR_MODEL_VERSION = str(runtime_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')
PROMOTE_AFTER_CLEAN_OBS = int(runtime_init_value('PROMOTE_AFTER_CLEAN_OBS') or 3)
MAX_RISK_FOR_STAGING = float(runtime_init_value('MAX_RISK_FOR_STAGING') or 25.0)
MAX_RISK_FOR_PROMOTION = float(runtime_init_value('MAX_RISK_FOR_PROMOTION') or 20.0)
MIN_PROMOTION_SPREAD_DAYS = float(runtime_init_value('MIN_PROMOTION_SPREAD_DAYS') or 2.0)
TRIAGE_LEARNING_BLOCK_TAGS = frozenset(runtime_init_value('TRIAGE_LEARNING_BLOCK_TAGS') or ())
HIGH_RISK_BUCKETS = frozenset(runtime_init_value('HIGH_RISK_BUCKETS') or ())
QUALITY_GATE_VERSION = str(runtime_init_value('QUALITY_GATE_VERSION') or 'quality_gate_v2_canonical_chain_authority')
VECTOR_FEATURE_NAMES = PROFILE_RAW_FEATURE_NAMES

def clear_profile_scoring_snapshot() -> None:
    profile_scoring_state_owner().clear()


__all__ = ('ADAPTIVE_WEIGHT_MIN_HISTORY', 'BEHAVIOR_MODEL_VERSION', 'BULK_DEFER_PROFILE_WRITES', 'CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS', 'DEFAULT_ENGINES', 'HIGH_RISK_BUCKETS', 'MAX_RISK_FOR_PROMOTION', 'MAX_RISK_FOR_STAGING', 'MIN_CLUSTER_SIZE', 'MIN_PROMOTION_SPREAD_DAYS', 'PROFILE_PUBLIC_INPUT_ERRORS', 'PROFILE_SCHEMA_VERSION', 'PROMOTE_AFTER_CLEAN_OBS', 'QUALITY_GATE_VERSION', 'TRIAGE_LEARNING_BLOCK_TAGS', 'VECTOR_FEATURE_NAMES', 'EngineProfileSchemaSnapshot', 'ProfileCorruptionEvidence', 'ProfileSchemaInvariantError', 'adaptive_profile_signal', 'apply_library_behavior_baseline', 'baseline_maturity_report', 'behavior_bucket_frequency_evidence', 'behavior_vector_from_scan', 'canonical_behavior_flow_from_sources', 'canonical_profile_learning_flow', 'clear_profile_scoring_snapshot', 'commit_promoted_learning', 'configure_engine_profile_corruption_policy', 'contextual_profile_baseline_key', 'contextual_profile_learning_policy', 'coordinated_model_validation_signal', 'default_engine_profile', 'default_extension_baseline', 'engine_extension_key', 'extension_chain_frequency_evidence', 'extension_profile_anomaly', 'extension_tag_frequency_evidence', 'extension_timeline_anomaly', 'flush_benign_candidate_store', 'flush_profile_writes', 'get_benign_candidate_store', 'get_extension_baseline', 'get_scoring_profile', 'infer_profile_engine', 'learning_guard', 'learning_verdict_is_clean', 'load_benign_candidate_store', 'load_engine_profile', 'mark_benign_candidate_store_dirty', 'profile_behavior_bucket_validation', 'profile_corruption_events_snapshot', 'profile_prior_for_scoring', 'prune_engine_profile_for_retention', 'prune_extension_baseline_for_retention', 'prune_staged_benign_store', 'real_ordered_event_names', 'record_learning_rejection', 'save_benign_candidate_store', 'save_engine_profile', 'should_learn_scan_result', 'timeline_transitions', 'triage_learning_block_hits', 'update_profile_from_scan_result', 'validate_engine_profile_schema', 'vector_baseline_anomaly')
