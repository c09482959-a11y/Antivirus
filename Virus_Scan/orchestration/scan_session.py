"""Canonical immutable scan-session generation construction."""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

from Virus_Scan.contracts.chain_evidence import CHAIN_EVIDENCE_SCHEMA_VERSION
from Virus_Scan.contracts.retained_scan_result import RETAINED_RESULT_SCHEMA
from Virus_Scan.contracts.scan_cache_fingerprint import (
    SCAN_CACHE_RESULT_SCHEMA_VERSION,
    SCAN_CACHE_SCHEMA_VERSION,
    ScanCacheExecutionIdentity,
)
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
)
from Virus_Scan.contracts.model_context_snapshot import MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION
from Virus_Scan.contracts.model_projection_identity import MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION
from Virus_Scan.contracts.runtime_platform_identity import runtime_platform_identity
from Virus_Scan.contracts.scan_session_snapshot import (
    SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION,
    ScanSessionSnapshot,
    ScanSubsystemState,
    scan_session_generation_id,
    scan_session_generation_record,
)
from Virus_Scan.contracts.tag_taxonomy import TAG_TAXONOMY_VERSION
from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_SCHEMA_VERSION,
    YARA_SCAN_RESULT_SCHEMA_VERSION,
)
from Virus_Scan.detection.attack.implementations import attack_analytic_implementation_manifest
from Virus_Scan.detection.attack.mapping.registry import attack_technique_policy_manifest
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION
from Virus_Scan.detection.attack.yara_alignment import YARA_OBSERVATION_ALIGNMENT_DIGEST
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import (
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST,
    ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    COMPILED_CHAIN_REGISTRY_DIGEST,
    COMPILED_CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.detection.registries.context import detection_registry_snapshot
from Virus_Scan.detection.registries.tag_taxonomy_registry import TAG_TAXONOMY_DIGEST
from Virus_Scan.detection.scoring.adaptive.settings import (
    ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION,
    ADAPTIVE_WEIGHT_VERSION,
    CALIBRATED_SCORE_VERSION,
)
from Virus_Scan.models.clustering.feature_registry import (
    CLUSTER_FEATURE_REGISTRY_DIGEST,
    CLUSTER_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_SCHEMA_VERSION
from Virus_Scan.models.profiles.persistence import DEFAULT_ENGINES, resolved_profiles_dir
from Virus_Scan.scanners.api.static_program_analysis_contracts import (
    NATIVE_DECODER_SUBSYSTEM_NAME,
    native_decoder_resource_state,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
    static_program_analysis_parser_registry_digest,
    javascript_typescript_parser_resource_state,
)
from Virus_Scan.routing.scanner_execution_plan import (
    SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    scanner_execution_capability_registry_digest,
)
from Virus_Scan.routing.intrastage_execution_plan import resolve_intrastage_execution_plan
from Virus_Scan.runtime.api import (
    get_deep_scan_mode,
    mitre_dir,
    mitre_runtime_snapshot,
    runtime_worker_shared_persistence_writes_disabled,
    yara_rules_state,
)
from Virus_Scan.storage import (
    SQLiteLifecycleError,
    authoritative_model_state,
    scan_cache_repository,
    sqlite_lifecycle,
)
from Virus_Scan.storage.sqlite_schema import CACHE_SCHEMA_DIGEST, MODEL_SCHEMA_DIGEST
from Virus_Scan.yara.execution_identity import selected_yara_execution_provenance
from Virus_Scan.yara.execution_policy import selected_yara_snapshot

_SCAN_SESSION_BUILD_ERRORS = (
    ArithmeticError,
    KeyError,
    LookupError,
    OSError,
    RuntimeError,
    SQLiteLifecycleError,
    TypeError,
    UnicodeError,
    ValueError,
)


def _canonical(value: object) -> object:
    """Return exact JSON-safe builtins from owned immutable/session values."""
    if type(value) is dict or isinstance(value, MappingProxyType):
        rows: list[tuple[str, object]] = []
        for key, child in value.items():
            if type(key) is not str:
                raise TypeError("scan_session_mapping_key_invalid")
            rows.append((str.__str__(key), _canonical(child)))
        return {key: child for key, child in sorted(rows, key=lambda row: row[0])}
    if isinstance(value, Mapping):
        raise TypeError("scan_session_mapping_owner_invalid")
    if type(value) in (tuple, list):
        return [_canonical(item) for item in value]
    if type(value) in (set, frozenset):
        children = [_canonical(item) for item in value]
        return sorted(
            children,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
            ),
        )
    if type(value) in (str, int, bool) or value is None:
        return value
    if type(value) is bytes:
        return {"bytes_hex": bytes.hex(value)}
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("scan_session_nonfinite_value")
        return value
    raise TypeError("scan_session_value_invalid")


def _digest(value: object) -> str:
    payload = json.dumps(
        _canonical(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _detection_registry_digest() -> str:
    return _digest(detection_registry_snapshot().publication_items())


def _model_state_identity() -> tuple[str, str, str, str]:
    """Return state, semantic digest, DB generation, and schema digest."""
    try:
        lifecycle = sqlite_lifecycle()
        generation = lifecycle.generation("model")
        owner = authoritative_model_state()
        record = {
            "profiles": tuple(
                (engine, owner.read_profile(engine)) for engine in DEFAULT_ENGINES
            ),
            "runtime_models": owner.read_runtime_snapshot(),
        }
        return "available", _digest(record), generation.generation_id, generation.schema_digest
    except _SCAN_SESSION_BUILD_ERRORS:
        return "unavailable", "", "", ""


def _cache_database_identity() -> tuple[str, str]:
    generation = sqlite_lifecycle().generation("cache")
    return generation.generation_id, generation.schema_digest


def _configuration_digest(
    *, scan_mode: str, requested_engine: str, strict: bool, yara_enabled: bool,
    per_file_timeout_sec: float, slow_file_warn_sec: float,
) -> str:
    return _digest({
        "deep_scan_mode": get_deep_scan_mode("auto"),
        "per_file_timeout_sec": float(per_file_timeout_sec),
        "requested_engine": requested_engine,
        "scan_cache_enabled": scan_cache_repository().enabled(),
        "scan_mode": scan_mode,
        "slow_file_warn_sec": float(slow_file_warn_sec),
        "strict": strict,
        "yara_enabled": yara_enabled,
    })


def _feature_registry_digest() -> str:
    return _digest({
        "adaptive_probability": ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION,
        "attack_classifier_registry_digest": (
            ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_DIGEST
        ),
        "attack_classifier_registry_version": (
            ATTACK_INTELLIGENCE_CLASSIFIER_REGISTRY_VERSION
        ),
        "attack_intelligence_evidence": ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
        "adaptive_weight": ADAPTIVE_WEIGHT_VERSION,
        "calibrated_score": CALIBRATED_SCORE_VERSION,
        "profile_raw_features": PROFILE_RAW_FEATURE_SCHEMA_VERSION,
        "cluster_feature_schema": CLUSTER_FEATURE_SCHEMA_VERSION,
        "cluster_feature_registry_digest": CLUSTER_FEATURE_REGISTRY_DIGEST,
        "model_context_snapshot": MODEL_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
        "model_projection_identity": MODEL_PROJECTION_IDENTITY_SCHEMA_VERSION,
    })


def _output_schema_digest() -> str:
    return _digest({
        "chain_evidence": CHAIN_EVIDENCE_SCHEMA_VERSION,
        "retained_result": RETAINED_RESULT_SCHEMA,
        "scan_cache_result": SCAN_CACHE_RESULT_SCHEMA_VERSION,
        "yara_hit": YARA_HIT_SCHEMA_VERSION,
        "yara_scan_result": YARA_SCAN_RESULT_SCHEMA_VERSION,
    })


def _durability_digest() -> str:
    return _digest({
        "cache_schema_digest": CACHE_SCHEMA_DIGEST,
        "foreign_keys": True,
        "journal_mode": "wal",
        "model_schema_digest": MODEL_SCHEMA_DIGEST,
        "synchronous": "full",
        "worker_shared_persistence_writes_disabled": (
            runtime_worker_shared_persistence_writes_disabled()
        ),
    })


def build_scan_session_snapshot(
    *,
    compiled_rules: object,
    yara_enabled: bool,
    scan_mode: str,
    requested_engine: str = "auto",
    strict: bool = False,
    per_file_timeout_sec: float = 20.0,
    slow_file_warn_sec: float = 2.0,
    worker_count: int = 0,
) -> ScanSessionSnapshot:
    """Build the one immutable semantic snapshot for a scan generation."""
    if type(yara_enabled) is not bool or type(strict) is not bool:
        raise TypeError("scan_session_boolean_config_invalid")
    if type(scan_mode) is not str or scan_mode == "" or len(scan_mode) > 64:
        raise ValueError("scan_session_mode_invalid")
    if type(requested_engine) is not str or requested_engine == "" or len(requested_engine) > 64:
        raise ValueError("scan_session_requested_engine_invalid")
    if type(worker_count) is not int or worker_count < 0:
        raise ValueError("scan_session_worker_count_invalid")
    if type(per_file_timeout_sec) not in (int, float) or float(per_file_timeout_sec) < 0:
        raise ValueError("scan_session_timeout_invalid")
    if type(slow_file_warn_sec) not in (int, float) or float(slow_file_warn_sec) < 0:
        raise ValueError("scan_session_slow_warn_invalid")

    # The session generation is the first consumer of authoritative/cache DB
    # identities for direct scheduler calls. Bind both domains through the
    # existing canonical profiles-directory owner before reading generations.
    resolved_profiles_dir()

    yara = selected_yara_execution_provenance(compiled_rules)
    yara_scan_mode = get_deep_scan_mode("auto")
    if not yara_enabled:
        yara_state = "disabled"
        yara_package = "disabled"
        yara_source_path = ""
        yara_reason = ""
    elif yara.verified:
        yara_state = "verified"
        yara_package = yara.package_kind
        source = getattr(compiled_rules, "source", None)
        source_path = getattr(source, "path", "")
        yara_source_path = "" if source_path == "" else str(Path(source_path).resolve())
        yara_reason = ""
    else:
        yara_state = "unavailable"
        yara_package = "unavailable"
        yara_source_path = ""
        yara_reason = "yara_selected_rules_unavailable"

    mitre = mitre_runtime_snapshot()
    repository_digest = ""
    dataset_version = ""
    attack_reason = ""
    if not mitre.enabled:
        attack_state = "disabled"
    elif mitre.available and mitre.repository is not None:
        attack_state = "available"
        repository_digest = mitre.repository.digest
        dataset_version = mitre.repository.version.dataset_version
    else:
        attack_state = "unavailable"
        status_reason = mitre.status.get("unavailable_reason", "")
        attack_reason = status_reason if type(status_reason) is str else ""
        if attack_reason == "":
            attack_reason = "mitre_repository_unavailable"

    implementation = attack_analytic_implementation_manifest()
    policy = attack_technique_policy_manifest()
    model_state, model_digest, model_generation, model_schema_digest = _model_state_identity()
    cache_generation, cache_schema_digest = _cache_database_identity()
    configuration_digest = _configuration_digest(
        scan_mode=scan_mode,
        requested_engine=requested_engine,
        strict=strict,
        yara_enabled=yara_enabled,
        per_file_timeout_sec=float(per_file_timeout_sec),
        slow_file_warn_sec=float(slow_file_warn_sec),
    )
    detection_digest = _detection_registry_digest()
    feature_digest = _feature_registry_digest()
    output_digest = _output_schema_digest()
    concurrency_plan = resolve_intrastage_execution_plan(
        scheduler_mode=scan_mode,
        scheduler_worker_count=worker_count,
    )
    concurrency_digest = concurrency_plan.digest
    durability_digest = _durability_digest()
    scanner_registry_digest = scanner_execution_capability_registry_digest()
    platform_identity = runtime_platform_identity()
    typescript_parser = javascript_typescript_parser_resource_state()
    native_decoder = native_decoder_resource_state()
    native_decoder_state = "available" if native_decoder.available else "unavailable"
    native_decoder_digest = native_decoder.identity_digest if native_decoder.available else ""
    native_decoder_reason = "" if native_decoder.available else native_decoder.reason
    static_analysis_state = "available" if native_decoder.available else "partial"
    static_analysis_reason = "" if native_decoder.available else "native_decoder_unavailable"

    yara_source_digest = yara.source_digest if yara_state == "verified" else ""
    yara_compiled_digest = yara.compiled_cache_digest if yara_state == "verified" else ""
    yara_catalog_digest = yara.rule_catalog_digest if yara_state == "verified" else ""
    yara_identity_digest = _digest({
        "compiled_cache_digest": yara_compiled_digest,
        "package_kind": yara_package,
        "rule_catalog_digest": yara_catalog_digest,
        "source_digest": yara_source_digest,
        "state": yara_state,
    }) if yara_state == "verified" else ""
    mitre_identity_digest = _digest({
        "alignment_digest": YARA_OBSERVATION_ALIGNMENT_DIGEST,
        "dataset_version": dataset_version,
        "implementation_manifest_digest": implementation["digest"],
        "policy_digest": policy["digest"],
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
        "repository_digest": repository_digest,
        "state": attack_state,
    }) if attack_state == "available" else ""

    provisional_identity = ScanCacheExecutionIdentity(
        session_generation_id="0" * 64,
        session_state="available" if model_state == "available" else "unavailable",
        yara_state=yara_state,
        yara_package_kind=yara_package,
        yara_source_digest=yara_source_digest,
        yara_compiled_cache_digest=yara_compiled_digest,
        yara_rule_catalog_digest=yara_catalog_digest,
        attack_state=attack_state,
        attack_alignment_digest=YARA_OBSERVATION_ALIGNMENT_DIGEST,
        attack_implementation_manifest_digest=implementation["digest"],
        attack_policy_digest=policy["digest"],
        attack_policy_version=ATTACK_MAPPING_POLICY_VERSION,
        attack_repository_digest=repository_digest,
        attack_dataset_version=dataset_version,
    )
    subsystem_states = tuple(sorted((
        ScanSubsystemState("clustering", "partial", model_digest or feature_digest),
        ScanSubsystemState("graph", "partial", detection_digest),
        ScanSubsystemState(
            "markov", "available" if model_state == "available" else "unavailable",
            model_digest, "" if model_digest else "model_state_unavailable",
        ),
        ScanSubsystemState(
            "mitre", attack_state, mitre_identity_digest,
            attack_reason,
        ),
        ScanSubsystemState(
            "profiles", "available" if model_state == "available" else "unavailable",
            model_digest, "" if model_digest else "model_state_unavailable",
        ),
        ScanSubsystemState("chain_matcher", "available", COMPILED_CHAIN_REGISTRY_DIGEST),
        ScanSubsystemState("scan_cache", "available", cache_schema_digest),
        ScanSubsystemState("runtime_platform", "available", platform_identity.digest),
        ScanSubsystemState("scanner_applicability", "available", scanner_registry_digest),
        ScanSubsystemState(
            "language_parser_registry",
            "available",
            STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST,
        ),
        ScanSubsystemState(
            NATIVE_DECODER_SUBSYSTEM_NAME,
            native_decoder_state,
            native_decoder_digest,
            native_decoder_reason,
        ),
        ScanSubsystemState(
            "typescript_parser_runtime",
            "available" if typescript_parser.available else "unavailable",
            typescript_parser.resource_digest if typescript_parser.available else "",
            "" if typescript_parser.available else typescript_parser.reason,
        ),
        ScanSubsystemState(
            "static_program_analysis",
            static_analysis_state,
            STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
            static_analysis_reason,
        ),
        ScanSubsystemState(
            "temporal", "available" if model_state == "available" else "unavailable",
            model_digest, "" if model_digest else "model_state_unavailable",
        ),
        ScanSubsystemState(
            "yara",
            "available" if yara_state == "verified" else yara_state,
            yara_identity_digest,
            yara_reason,
        ),
    ), key=lambda item: item.name))
    generation_fields = {
        "attack_unavailable_reason": attack_reason,
        "cache_database_generation": cache_generation,
        "cache_database_schema_digest": cache_schema_digest,
        "cache_schema_version": SCAN_CACHE_SCHEMA_VERSION,
        "chain_registry_digest": CHAIN_REGISTRY_DIGEST,
        "chain_registry_version": CHAIN_REGISTRY_VERSION,
        "concurrency_digest": concurrency_digest,
        "concurrency_plan": concurrency_plan.to_record(),
        "configuration_digest": configuration_digest,
        "detection_registry_digest": detection_digest,
        "durability_digest": durability_digest,
        "feature_registry_digest": feature_digest,
        "feature_registry_state": "partial",
        "mitre_root": str(Path(mitre_dir()).resolve()),
        "model_database_generation": model_generation,
        "model_database_schema_digest": model_schema_digest,
        "model_state": model_state,
        "model_state_digest": model_digest,
        "output_schema_digest": output_digest,
        "parser_reason": "",
        "parser_schema_version": STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
        "parser_state": "available",
        "runtime_platform": platform_identity.to_record(),
        "scan_mode": scan_mode,
        "scanner_registry_digest": scanner_registry_digest,
        "scanner_registry_reason": "",
        "scanner_registry_state": "available",
        "schema_version": SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION,
        "static_ir_reason": "",
        "static_ir_schema_version": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
        "static_ir_state": "available",
        "subsystem_states": [item.to_record() for item in subsystem_states],
        "tag_taxonomy_digest": TAG_TAXONOMY_DIGEST,
        "tag_taxonomy_version": TAG_TAXONOMY_VERSION,
        "yara_scan_mode": yara_scan_mode,
        "yara_source_path": yara_source_path,
        "yara_unavailable_reason": yara_reason,
    }
    generation_id = scan_session_generation_id(
        scan_session_generation_record(generation_fields, provisional_identity)
    )
    cache_execution_identity = ScanCacheExecutionIdentity(
        session_generation_id=generation_id,
        session_state=provisional_identity.session_state,
        yara_state=provisional_identity.yara_state,
        yara_package_kind=provisional_identity.yara_package_kind,
        yara_source_digest=provisional_identity.yara_source_digest,
        yara_compiled_cache_digest=provisional_identity.yara_compiled_cache_digest,
        yara_rule_catalog_digest=provisional_identity.yara_rule_catalog_digest,
        attack_state=provisional_identity.attack_state,
        attack_alignment_digest=provisional_identity.attack_alignment_digest,
        attack_implementation_manifest_digest=provisional_identity.attack_implementation_manifest_digest,
        attack_policy_digest=provisional_identity.attack_policy_digest,
        attack_policy_version=provisional_identity.attack_policy_version,
        attack_repository_digest=provisional_identity.attack_repository_digest,
        attack_dataset_version=provisional_identity.attack_dataset_version,
    )
    return ScanSessionSnapshot(
        generation_id=generation_id,
        runtime_platform=platform_identity,
        scan_mode=scan_mode,
        configuration_digest=configuration_digest,
        yara_source_path=yara_source_path,
        yara_scan_mode=yara_scan_mode,
        yara_unavailable_reason=yara_reason,
        mitre_root=str(Path(mitre_dir()).resolve()),
        attack_unavailable_reason=attack_reason,
        scanner_registry_state="available",
        scanner_registry_digest=scanner_registry_digest,
        scanner_registry_reason="",
        parser_state="available",
        parser_schema_version=STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
        parser_reason="",
        static_ir_state="available",
        static_ir_schema_version=STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
        static_ir_reason="",
        tag_taxonomy_version=TAG_TAXONOMY_VERSION,
        tag_taxonomy_digest=TAG_TAXONOMY_DIGEST,
        chain_registry_version=CHAIN_REGISTRY_VERSION,
        chain_registry_digest=CHAIN_REGISTRY_DIGEST,
        detection_registry_digest=detection_digest,
        model_state=model_state,
        model_state_digest=model_digest,
        model_database_generation=model_generation,
        model_database_schema_digest=model_schema_digest,
        feature_registry_state="partial",
        feature_registry_digest=feature_digest,
        cache_database_generation=cache_generation,
        cache_database_schema_digest=cache_schema_digest,
        cache_schema_version=SCAN_CACHE_SCHEMA_VERSION,
        output_schema_digest=output_digest,
        concurrency_plan=concurrency_plan,
        concurrency_digest=concurrency_digest,
        durability_digest=durability_digest,
        subsystem_states=subsystem_states,
        cache_execution_identity=cache_execution_identity,
    )


def validate_scan_session_runtime(snapshot: object) -> ScanSessionSnapshot:
    """Validate process-local YARA/MITRE resources against one parent snapshot."""
    if type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("scan_session_snapshot_required")
    identity = snapshot.cache_execution_identity
    local_platform = runtime_platform_identity()
    if snapshot.runtime_platform != local_platform:
        raise RuntimeError("scan_session_worker_runtime_platform_mismatch")
    platform_subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == "runtime_platform"),
        None,
    )
    if (
        platform_subsystem is None
        or platform_subsystem.state != "available"
        or platform_subsystem.identity_digest != local_platform.digest
        or platform_subsystem.reason != ""
    ):
        raise RuntimeError("scan_session_worker_runtime_platform_subsystem_mismatch")
    if identity.yara_state == "verified":
        local_yara = selected_yara_execution_provenance(
            selected_yara_snapshot(yara_rules_state(), scan_mode=snapshot.yara_scan_mode)
        )
        if not local_yara.verified or (
            local_yara.package_kind != identity.yara_package_kind
            or local_yara.source_digest != identity.yara_source_digest
            or local_yara.compiled_cache_digest != identity.yara_compiled_cache_digest
            or local_yara.rule_catalog_digest != identity.yara_rule_catalog_digest
        ):
            raise RuntimeError("scan_session_worker_yara_identity_mismatch")
    local_mitre = mitre_runtime_snapshot()
    if identity.attack_state == "available":
        repository = local_mitre.repository
        if (
            not local_mitre.enabled
            or not local_mitre.available
            or repository is None
            or repository.digest != identity.attack_repository_digest
            or repository.version.dataset_version != identity.attack_dataset_version
        ):
            raise RuntimeError("scan_session_worker_attack_identity_mismatch")
    if snapshot.tag_taxonomy_digest != TAG_TAXONOMY_DIGEST:
        raise RuntimeError("scan_session_worker_tag_taxonomy_mismatch")
    if snapshot.chain_registry_digest != CHAIN_REGISTRY_DIGEST:
        raise RuntimeError("scan_session_worker_chain_registry_mismatch")
    chain_matcher_subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == "chain_matcher"),
        None,
    )
    if chain_matcher_subsystem is None:
        raise RuntimeError("scan_session_worker_chain_matcher_subsystem_missing")
    if (
        chain_matcher_subsystem.state != "available"
        or chain_matcher_subsystem.identity_digest != COMPILED_CHAIN_REGISTRY_DIGEST
        or chain_matcher_subsystem.reason != ""
    ):
        raise RuntimeError("scan_session_worker_chain_matcher_subsystem_mismatch")
    if COMPILED_CHAIN_REGISTRY_VERSION == "":
        raise RuntimeError("scan_session_worker_chain_matcher_version_missing")
    if snapshot.scanner_registry_state != "available":
        raise RuntimeError("scan_session_worker_scanner_registry_unavailable")
    if snapshot.scanner_registry_digest != scanner_execution_capability_registry_digest():
        raise RuntimeError("scan_session_worker_scanner_registry_mismatch")
    if snapshot.scanner_registry_reason != "":
        raise RuntimeError("scan_session_worker_scanner_registry_reason_invalid")
    if SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION == "":
        raise RuntimeError("scan_session_worker_scanner_registry_version_missing")
    if snapshot.parser_state != "available":
        raise RuntimeError("scan_session_worker_parser_registry_unavailable")
    if snapshot.parser_schema_version != STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION:
        raise RuntimeError("scan_session_worker_parser_registry_version_mismatch")
    if snapshot.parser_reason != "":
        raise RuntimeError("scan_session_worker_parser_registry_reason_invalid")
    parser_subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == "language_parser_registry"),
        None,
    )
    if parser_subsystem is None:
        raise RuntimeError("scan_session_worker_parser_registry_subsystem_missing")
    if (
        parser_subsystem.state != "available"
        or parser_subsystem.identity_digest != static_program_analysis_parser_registry_digest()
        or parser_subsystem.reason != ""
    ):
        raise RuntimeError("scan_session_worker_parser_registry_subsystem_mismatch")
    if snapshot.static_ir_state != "available":
        raise RuntimeError("scan_session_worker_static_ir_unavailable")
    if snapshot.static_ir_schema_version != STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION:
        raise RuntimeError("scan_session_worker_static_ir_version_mismatch")
    if snapshot.static_ir_reason != "":
        raise RuntimeError("scan_session_worker_static_ir_reason_invalid")
    typescript_subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == "typescript_parser_runtime"),
        None,
    )
    if typescript_subsystem is None:
        raise RuntimeError("scan_session_worker_typescript_parser_subsystem_missing")
    local_typescript_parser = javascript_typescript_parser_resource_state()
    expected_typescript_state = "available" if local_typescript_parser.available else "unavailable"
    expected_typescript_digest = (
        local_typescript_parser.resource_digest if local_typescript_parser.available else ""
    )
    expected_typescript_reason = "" if local_typescript_parser.available else local_typescript_parser.reason
    if (
        typescript_subsystem.state != expected_typescript_state
        or typescript_subsystem.identity_digest != expected_typescript_digest
        or typescript_subsystem.reason != expected_typescript_reason
    ):
        raise RuntimeError("scan_session_worker_typescript_parser_subsystem_mismatch")
    native_subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == NATIVE_DECODER_SUBSYSTEM_NAME),
        None,
    )
    if native_subsystem is None:
        raise RuntimeError("scan_session_worker_native_decoder_subsystem_missing")
    local_native_decoder = native_decoder_resource_state()
    expected_native_state = "available" if local_native_decoder.available else "unavailable"
    expected_native_digest = (
        local_native_decoder.identity_digest if local_native_decoder.available else ""
    )
    expected_native_reason = "" if local_native_decoder.available else local_native_decoder.reason
    if (
        native_subsystem.state != expected_native_state
        or native_subsystem.identity_digest != expected_native_digest
        or native_subsystem.reason != expected_native_reason
    ):
        raise RuntimeError("scan_session_worker_native_decoder_subsystem_mismatch")
    subsystem = next(
        (item for item in snapshot.subsystem_states if item.name == "static_program_analysis"),
        None,
    )
    if subsystem is None:
        raise RuntimeError("scan_session_worker_static_analysis_subsystem_missing")
    expected_static_state = "available" if local_native_decoder.available else "partial"
    expected_static_reason = "" if local_native_decoder.available else "native_decoder_unavailable"
    if (
        subsystem.state != expected_static_state
        or subsystem.identity_digest != STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST
        or subsystem.reason != expected_static_reason
    ):
        raise RuntimeError("scan_session_worker_static_analysis_subsystem_mismatch")
    return snapshot


__all__ = ("build_scan_session_snapshot", "validate_scan_session_runtime")
