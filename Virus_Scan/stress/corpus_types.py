"""Immutable stress planning, oracle, and verification contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class EngineFileTypeContract:
    engine: str
    bucket: str
    extension: str
    execution_capability: str


@dataclass(frozen=True, slots=True)
class SyntheticStressCase:
    index: int
    sample_id: str
    classification: str
    family: str
    engine: str
    file_type: str
    extension: str
    relative_path: str
    expected_fast_path: bool
    expected_deep_scan: bool
    worker_matrix: tuple[object, ...]
    queue_depth_matrix: tuple[object, ...]
    restart_point_matrix: tuple[str, ...]
    timeout_pressure_matrix: tuple[str, ...]
    archive_depth_matrix: tuple[int, ...]
    scan_order_matrix: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class JsonPersistenceContract:
    fast_path_artifacts: tuple[str, ...]
    deep_scan_artifacts: tuple[str, ...]
    cross_path_artifacts: tuple[str, ...]
    persistence_counters: tuple[str, ...]
    zero_loss_requirements: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class SyntheticCorpusPlan:
    total_samples: int
    benign_samples: int
    malicious_samples: int
    engine_file_types: tuple[EngineFileTypeContract, ...]
    cases: tuple[SyntheticStressCase, ...]
    fast_path_configuration: Mapping[str, object]
    deep_scan_configuration: Mapping[str, object]
    json_persistence_contract: JsonPersistenceContract


@dataclass(frozen=True, slots=True)
class MaliciousOracleCase:
    index: int
    sample_id: str
    family: str
    template_id: str
    extension: str
    relative_path: str
    size_bytes: int
    sha256: str
    expected_classifications: tuple[str, ...]
    minimum_score: float
    maximum_score: float
    required_tags: tuple[str, ...]
    forbidden_tags: tuple[str, ...]
    oracle_level: str
    expected_terminal_status: str
    expected_profile_learning: str


@dataclass(frozen=True, slots=True)
class MaliciousCorpusManifest:
    schema_version: str
    run_id: str
    total_samples: int
    cases: tuple[MaliciousOracleCase, ...]


@dataclass(frozen=True, slots=True)
class MaterializedMaliciousSample:
    sample_id: str
    relative_path: str
    absolute_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class MaterializedMaliciousCorpus:
    root: str
    manifest_path: str
    samples: tuple[MaterializedMaliciousSample, ...]


@dataclass(frozen=True, slots=True)
class StressVerificationIssue:
    artifact: str
    sample_id: str
    reason: str
    detail: str


@dataclass(frozen=True, slots=True)
class StressVerificationReport:
    ok: bool
    checked: int
    issues: tuple[StressVerificationIssue, ...]


__all__ = (
    "EngineFileTypeContract",
    "JsonPersistenceContract",
    "MaliciousCorpusManifest",
    "MaliciousOracleCase",
    "MaterializedMaliciousCorpus",
    "MaterializedMaliciousSample",
    "StressVerificationIssue",
    "StressVerificationReport",
    "SyntheticCorpusPlan",
    "SyntheticStressCase",
)
