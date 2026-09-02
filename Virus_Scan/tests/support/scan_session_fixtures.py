"""Exact immutable scan-session fixtures for scheduler and detection tests."""
from __future__ import annotations

from Virus_Scan.contracts.scan_cache_fingerprint import ScanCacheExecutionIdentity
from Virus_Scan.contracts.intrastage_execution import IntrastageExecutionPlan
from Virus_Scan.contracts.runtime_platform_identity import RuntimePlatformIdentity, runtime_platform_identity
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
)
from Virus_Scan.contracts.scan_session_snapshot import (
    SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION,
    ScanSessionSnapshot,
    ScanSubsystemState,
    scan_session_generation_id,
    scan_session_generation_record,
)
from Virus_Scan.detection.chains.execution.compiled_registry import COMPILED_CHAIN_REGISTRY_DIGEST
from Virus_Scan.detection.registries.chain_registry import CHAIN_REGISTRY_DIGEST
from Virus_Scan.detection.registries.chain_registry_defaults import CHAIN_REGISTRY_VERSION
from Virus_Scan.detection.registries.tag_taxonomy_registry import TAG_TAXONOMY_DIGEST
from Virus_Scan.routing.scanner_execution_plan import scanner_execution_capability_registry_digest
from Virus_Scan.scanners.static_program_analysis.javascript_typescript_frontend import (
    javascript_typescript_parser_resource_state,
)
from Virus_Scan.scanners.static_program_analysis import (
    NATIVE_DECODER_SUBSYSTEM_NAME,
    native_decoder_resource_state,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_DIGEST,
    STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
)
from Virus_Scan.tests.support.scan_cache_fixtures import disabled_scan_cache_identity


def _identity_with_session(
    identity: ScanCacheExecutionIdentity, generation_id: str,
) -> ScanCacheExecutionIdentity:
    return ScanCacheExecutionIdentity(
        session_generation_id=generation_id,
        session_state=identity.session_state,
        yara_state=identity.yara_state,
        yara_package_kind=identity.yara_package_kind,
        yara_source_digest=identity.yara_source_digest,
        yara_compiled_cache_digest=identity.yara_compiled_cache_digest,
        yara_rule_catalog_digest=identity.yara_rule_catalog_digest,
        attack_state=identity.attack_state,
        attack_alignment_digest=identity.attack_alignment_digest,
        attack_implementation_manifest_digest=identity.attack_implementation_manifest_digest,
        attack_policy_digest=identity.attack_policy_digest,
        attack_policy_version=identity.attack_policy_version,
        attack_repository_digest=identity.attack_repository_digest,
        attack_dataset_version=identity.attack_dataset_version,
    )


def scan_session_snapshot_fixture(
    *,
    scan_mode: str = "serial",
    generation_seed: str = "d",
    runtime_platform_override: RuntimePlatformIdentity | None = None,
) -> ScanSessionSnapshot:
    if generation_seed not in "abcdef0123456789":
        raise ValueError("scan_session_fixture_seed_invalid")
    provisional_identity = disabled_scan_cache_identity(session_seed="0")
    concurrency_plan = IntrastageExecutionPlan(
        scheduler_mode=scan_mode,
        scheduler_worker_count=1,
        stage_parallel_enabled=True,
        intrastage_enabled=True,
        default_backend="thread",
        intrastage_workers=2,
        serial_task_threshold=2,
        max_pending_tasks=8,
        max_process_task_bytes=256 * 1024,
    )
    scanner_digest = scanner_execution_capability_registry_digest()
    native_decoder = native_decoder_resource_state()
    typescript_parser = javascript_typescript_parser_resource_state()
    native_decoder_state = "available" if native_decoder.available else "unavailable"
    native_decoder_digest = native_decoder.identity_digest if native_decoder.available else ""
    native_decoder_reason = "" if native_decoder.available else native_decoder.reason
    if runtime_platform_override is not None and type(runtime_platform_override) is not RuntimePlatformIdentity:
        raise TypeError("scan_session_fixture_runtime_platform_invalid")
    platform_identity = runtime_platform_identity() if runtime_platform_override is None else runtime_platform_override
    static_analysis_state = "available" if native_decoder.available else "partial"
    static_analysis_reason = "" if native_decoder.available else "native_decoder_unavailable"
    subsystem_states = tuple(sorted((
        ScanSubsystemState("chain_matcher", "available", COMPILED_CHAIN_REGISTRY_DIGEST),
        ScanSubsystemState("profiles", "available", "5" * 64),
        ScanSubsystemState("scan_cache", "available", "a" * 64),
        ScanSubsystemState("runtime_platform", "available", platform_identity.digest),
        ScanSubsystemState("scanner_applicability", "available", scanner_digest),
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
        ScanSubsystemState("yara", "disabled", ""),
    ), key=lambda item: item.name))
    fields = {
        "attack_unavailable_reason": "",
        "cache_database_generation": "9" * 64,
        "cache_database_schema_digest": "a" * 64,
        "cache_schema_version": 3,
        "chain_registry_digest": CHAIN_REGISTRY_DIGEST,
        "chain_registry_version": CHAIN_REGISTRY_VERSION,
        "concurrency_digest": concurrency_plan.digest,
        "concurrency_plan": concurrency_plan.to_record(),
        "configuration_digest": generation_seed * 64,
        "detection_registry_digest": "4" * 64,
        "durability_digest": "e" * 64,
        "feature_registry_digest": "8" * 64,
        "feature_registry_state": "partial",
        "mitre_root": "/tmp/mitre",
        "model_database_generation": "6" * 64,
        "model_database_schema_digest": "7" * 64,
        "model_state": "available",
        "model_state_digest": "5" * 64,
        "output_schema_digest": "b" * 64,
        "parser_reason": "",
        "parser_schema_version": STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
        "parser_state": "available",
        "runtime_platform": platform_identity.to_record(),
        "scan_mode": scan_mode,
        "scanner_registry_digest": scanner_digest,
        "scanner_registry_reason": "",
        "scanner_registry_state": "available",
        "schema_version": SCAN_SESSION_SNAPSHOT_SCHEMA_VERSION,
        "static_ir_reason": "",
        "static_ir_schema_version": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
        "static_ir_state": "available",
        "subsystem_states": [item.to_record() for item in subsystem_states],
        "tag_taxonomy_digest": TAG_TAXONOMY_DIGEST,
        "tag_taxonomy_version": "tag_taxonomy_v1",
        "yara_scan_mode": "auto",
        "yara_source_path": "",
        "yara_unavailable_reason": "",
    }
    generation = scan_session_generation_id(
        scan_session_generation_record(fields, provisional_identity)
    )
    identity = _identity_with_session(provisional_identity, generation)
    return ScanSessionSnapshot(
        generation_id=generation,
        runtime_platform=platform_identity,
        scan_mode=scan_mode,
        configuration_digest=fields["configuration_digest"],
        yara_source_path="",
        yara_scan_mode="auto",
        yara_unavailable_reason="",
        mitre_root="/tmp/mitre",
        attack_unavailable_reason="",
        scanner_registry_state="available",
        scanner_registry_digest=scanner_digest,
        scanner_registry_reason="",
        parser_state="available",
        parser_schema_version=STATIC_PROGRAM_ANALYSIS_PARSER_REGISTRY_VERSION,
        parser_reason="",
        static_ir_state="available",
        static_ir_schema_version=STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
        static_ir_reason="",
        tag_taxonomy_version="tag_taxonomy_v1",
        tag_taxonomy_digest=TAG_TAXONOMY_DIGEST,
        chain_registry_version=CHAIN_REGISTRY_VERSION,
        chain_registry_digest=CHAIN_REGISTRY_DIGEST,
        detection_registry_digest="4" * 64,
        model_state="available",
        model_state_digest="5" * 64,
        model_database_generation="6" * 64,
        model_database_schema_digest="7" * 64,
        feature_registry_state="partial",
        feature_registry_digest="8" * 64,
        cache_database_generation="9" * 64,
        cache_database_schema_digest="a" * 64,
        cache_schema_version=3,
        output_schema_digest="b" * 64,
        concurrency_plan=concurrency_plan,
        concurrency_digest=concurrency_plan.digest,
        durability_digest="e" * 64,
        subsystem_states=subsystem_states,
        cache_execution_identity=identity,
    )


__all__ = ("scan_session_snapshot_fixture",)
