"""Public deterministic 10,000-sample forensic stress-corpus API.

This public module exposes immutable manifest-planning contracts only. It does
not create live malware, execute samples, publish JSON, or perform
scanner/detection work. File-type coverage is derived from the scanner public
filetype-policy contract through the bounded corpus builder.
"""
from __future__ import annotations

from Virus_Scan.stress.corpus_builder import (
    all_stress_file_type_contracts,
    coverage_summary,
    engine_file_type_contracts,
    json_persistence_contract,
    synthesize_10000_stress_plan,
)
from Virus_Scan.stress.corpus_materializer import (
    malicious_manifest_to_json,
    materialize_malicious_corpus,
    write_malicious_oracle_manifest,
)
from Virus_Scan.stress.malicious_corpus import (
    build_malicious_oracle_manifest,
    inert_malicious_sample_bytes,
    malicious_oracle_case,
)
from Virus_Scan.stress.profile_verifier import verify_no_malicious_profile_learning
from Virus_Scan.stress.run_verifier import verify_malicious_scan_artifacts
from Virus_Scan.stress.corpus_policy import (
    ARCHIVE_DEPTH_MATRIX,
    ARCHIVE_FILE_TYPE_EXTENSIONS,
    BENIGN_SYNTHETIC_SAMPLES,
    CROSS_PATH_RESULT_ARTIFACTS,
    DEEP_SCAN_CONFIGURATION,
    DEEP_SCAN_RESULT_ARTIFACTS,
    ENGINE_ANCHOR_FILENAMES,
    FAST_PATH_CONFIGURATION,
    FAST_PATH_RESULT_ARTIFACTS,
    GENERIC_STRESS_FILE_TYPES,
    INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS,
    INERT_MALICIOUS_EXTENSIONS,
    INERT_MALICIOUS_FAMILIES,
    INERT_MALICIOUS_ORACLE_SCHEMA_VERSION,
    INERT_MALICIOUS_STRESS_SAMPLES,
    OFFICE_FILE_TYPE_EXTENSIONS,
    PE_FILE_TYPE_EXTENSIONS,
    PIPELINE_PERSISTENCE_COUNTERS,
    PIPELINE_ZERO_LOSS_REQUIREMENTS,
    QUEUE_DEPTH_MATRIX,
    RESTART_POINT_MATRIX,
    SCAN_ORDER_MATRIX,
    SCRIPT_FILE_TYPE_EXTENSIONS,
    TIMEOUT_PRESSURE_MATRIX,
    TOTAL_SYNTHETIC_SAMPLES,
    WORKER_MATRIX,
)
from Virus_Scan.stress.corpus_types import (
    EngineFileTypeContract,
    JsonPersistenceContract,
    MaliciousCorpusManifest,
    MaliciousOracleCase,
    MaterializedMaliciousCorpus,
    MaterializedMaliciousSample,
    StressVerificationIssue,
    StressVerificationReport,
    SyntheticCorpusPlan,
    SyntheticStressCase,
)

__all__ = (
    "ARCHIVE_DEPTH_MATRIX",
    "ARCHIVE_FILE_TYPE_EXTENSIONS",
    "BENIGN_SYNTHETIC_SAMPLES",
    "CROSS_PATH_RESULT_ARTIFACTS",
    "DEEP_SCAN_CONFIGURATION",
    "DEEP_SCAN_RESULT_ARTIFACTS",
    "ENGINE_ANCHOR_FILENAMES",
    "FAST_PATH_CONFIGURATION",
    "FAST_PATH_RESULT_ARTIFACTS",
    "GENERIC_STRESS_FILE_TYPES",
    "INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS",
    "INERT_MALICIOUS_EXTENSIONS",
    "INERT_MALICIOUS_FAMILIES",
    "INERT_MALICIOUS_ORACLE_SCHEMA_VERSION",
    "INERT_MALICIOUS_STRESS_SAMPLES",
    "OFFICE_FILE_TYPE_EXTENSIONS",
    "PE_FILE_TYPE_EXTENSIONS",
    "PIPELINE_PERSISTENCE_COUNTERS",
    "PIPELINE_ZERO_LOSS_REQUIREMENTS",
    "QUEUE_DEPTH_MATRIX",
    "RESTART_POINT_MATRIX",
    "SCAN_ORDER_MATRIX",
    "SCRIPT_FILE_TYPE_EXTENSIONS",
    "TIMEOUT_PRESSURE_MATRIX",
    "TOTAL_SYNTHETIC_SAMPLES",
    "WORKER_MATRIX",
    "EngineFileTypeContract",
    "JsonPersistenceContract",
    "MaliciousCorpusManifest",
    "MaliciousOracleCase",
    "MaterializedMaliciousCorpus",
    "MaterializedMaliciousSample",
    "SyntheticCorpusPlan",
    "SyntheticStressCase",
    "StressVerificationIssue",
    "StressVerificationReport",
    "all_stress_file_type_contracts",
    "build_malicious_oracle_manifest",
    "coverage_summary",
    "engine_file_type_contracts",
    "inert_malicious_sample_bytes",
    "json_persistence_contract",
    "malicious_manifest_to_json",
    "malicious_oracle_case",
    "materialize_malicious_corpus",
    "synthesize_10000_stress_plan",
    "verify_malicious_scan_artifacts",
    "verify_no_malicious_profile_learning",
    "write_malicious_oracle_manifest",
)
