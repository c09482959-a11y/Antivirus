"""Deterministic stress-corpus planning logic."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field, no_hook_mapping_items, no_hook_text
from Virus_Scan.scanners.api.filetype_policy_contracts import ENGINE_SPECIFIC_FILETYPE_BUCKETS
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
    MALICIOUS_SYNTHETIC_SAMPLES,
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
    SyntheticCorpusPlan,
    SyntheticStressCase,
)


def _stress_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_stress_text",
        unsupported_reason="unsafe_stress_text_rejected",
    )
    return text if not reason else default


def _stress_mapping_get(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate_key, value in items:
        if type(candidate_key) is str and str.__eq__(candidate_key, key):
            return value
    return default


def _stress_text_sequence(value: object) -> tuple[str, ...]:
    if type(value) is tuple:
        items = value
    elif type(value) in (list, set, frozenset):
        items = tuple(value)
    else:
        return ()
    out: list[str] = []
    for item in items:
        text = _stress_text(item).lstrip(".")
        if text:
            out.append(text)
    return tuple(out)


def _sorted_mapping_text_items(mapping: object) -> tuple[tuple[str, object], ...]:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return ()
    normalized: list[tuple[str, object]] = []
    for key, value in items:
        key_text = _stress_text(key)
        if key_text:
            normalized.append((key_text, value))
    return tuple(sorted(normalized, key=lambda item: item[0]))


def _contract_field(contract: object, name: str) -> str:
    field_value = no_hook_exact_owner_field(contract, EngineFileTypeContract, name)
    if field_value is None:
        return ""
    return _stress_text(field_value)


def engine_file_type_contracts() -> tuple[EngineFileTypeContract, ...]:
    contracts: list[EngineFileTypeContract] = []
    for engine in sorted(ENGINE_SPECIFIC_FILETYPE_BUCKETS):
        buckets = ENGINE_SPECIFIC_FILETYPE_BUCKETS[engine]
        for bucket in sorted(buckets):
            policy = buckets[bucket]
            execution_capability = _stress_text(_stress_mapping_get(policy, "execution_capability", "unknown"), "unknown")
            extensions = tuple(sorted(_stress_text_sequence(_stress_mapping_get(policy, "extensions", ()))))
            for extension in extensions:
                normalized = extension if extension.startswith(".") else str.__add__(".", extension)
                contracts.append(EngineFileTypeContract(engine, bucket, normalized, execution_capability))
    return tuple(contracts)


def _generic_contracts() -> tuple[EngineFileTypeContract, ...]:
    values: list[EngineFileTypeContract] = [
        *(EngineFileTypeContract("generic", "pe_malware", ext, "native") for ext in PE_FILE_TYPE_EXTENSIONS),
        *(EngineFileTypeContract("generic", "script", ext, "script") for ext in SCRIPT_FILE_TYPE_EXTENSIONS),
        *(EngineFileTypeContract("generic", "office_malware", ext, "document") for ext in OFFICE_FILE_TYPE_EXTENSIONS),
        *(EngineFileTypeContract("generic", "archive", ext, "container") for ext in ARCHIVE_FILE_TYPE_EXTENSIONS),
    ]
    values.extend(
        EngineFileTypeContract("generic", family, str.__add__(".", family), "data")
        for family in (
            "renamed_payload",
            "corrupted_file",
            "large_file",
            "tiny_file",
            "timeout_trigger",
            "replay_recovery",
        )
    )
    return tuple(values)


def _anchor_contracts() -> tuple[EngineFileTypeContract, ...]:
    values: list[EngineFileTypeContract] = []
    for engine in sorted(ENGINE_ANCHOR_FILENAMES):
        for anchor in ENGINE_ANCHOR_FILENAMES[engine]:
            extension = _path_suffix(anchor)
            anchor_key = anchor.replace("/", "__").replace(".", "_") or "extensionless_anchor"
            values.append(EngineFileTypeContract(engine, str.__add__("engine_anchor__", anchor_key), extension, "anchor"))
    return tuple(values)


def all_stress_file_type_contracts() -> tuple[EngineFileTypeContract, ...]:
    return engine_file_type_contracts() + _anchor_contracts() + _generic_contracts()


def _relative_path(contract: EngineFileTypeContract, index: int) -> str:
    engine = _contract_field(contract, "engine")
    bucket = _contract_field(contract, "bucket")
    extension = _contract_field(contract, "extension")
    anchors = ENGINE_ANCHOR_FILENAMES.get(engine)
    if anchors:
        anchor = anchors[index % len(anchors)]
        if _path_suffix(anchor) == extension:
            return anchor
        return "/".join((engine, bucket, "".join(("sample_", format(index, "05d"), extension))))
    if engine == "generic":
        return "/".join(("generic", bucket, "".join(("sample_", format(index, "05d"), extension))))
    return "/".join((engine, bucket, "".join(("sample_", format(index, "05d"), extension))))


def _path_suffix(path: str) -> str:
    if path.endswith("global-metadata.dat"):
        return ".global-metadata.dat"
    if path.endswith("metadata.dat"):
        return ".metadata.dat"
    marker = path.rfind(".")
    return "" if marker < 0 else path[marker:]


def json_persistence_contract() -> JsonPersistenceContract:
    return JsonPersistenceContract(
        fast_path_artifacts=FAST_PATH_RESULT_ARTIFACTS,
        deep_scan_artifacts=DEEP_SCAN_RESULT_ARTIFACTS,
        cross_path_artifacts=CROSS_PATH_RESULT_ARTIFACTS,
        persistence_counters=PIPELINE_PERSISTENCE_COUNTERS,
        zero_loss_requirements=PIPELINE_ZERO_LOSS_REQUIREMENTS,
    )


def synthesize_10000_stress_plan() -> SyntheticCorpusPlan:
    contracts = all_stress_file_type_contracts()
    if not contracts:
        raise RuntimeError("no stress file type contracts available")
    cases: list[SyntheticStressCase] = []
    for index in range(TOTAL_SYNTHETIC_SAMPLES):
        classification = "benign" if index < BENIGN_SYNTHETIC_SAMPLES else "malicious"
        contract = contracts[index % len(contracts)]
        family = contract.bucket if contract.engine != "generic" else GENERIC_STRESS_FILE_TYPES[index % len(GENERIC_STRESS_FILE_TYPES)]
        cases.append(
            SyntheticStressCase(
                index=index,
                sample_id="-".join(("synthetic", classification, format(index, "05d"))),
                classification=classification,
                family=family,
                engine=contract.engine,
                file_type=contract.bucket,
                extension=contract.extension,
                relative_path=_relative_path(contract, index),
                expected_fast_path=True,
                expected_deep_scan=True,
                worker_matrix=WORKER_MATRIX,
                queue_depth_matrix=QUEUE_DEPTH_MATRIX,
                restart_point_matrix=RESTART_POINT_MATRIX,
                timeout_pressure_matrix=TIMEOUT_PRESSURE_MATRIX,
                archive_depth_matrix=ARCHIVE_DEPTH_MATRIX,
                scan_order_matrix=SCAN_ORDER_MATRIX,
            )
        )
    return SyntheticCorpusPlan(
        total_samples=TOTAL_SYNTHETIC_SAMPLES,
        benign_samples=BENIGN_SYNTHETIC_SAMPLES,
        malicious_samples=MALICIOUS_SYNTHETIC_SAMPLES,
        engine_file_types=contracts,
        cases=tuple(cases),
        fast_path_configuration=FAST_PATH_CONFIGURATION,
        deep_scan_configuration=DEEP_SCAN_CONFIGURATION,
        json_persistence_contract=json_persistence_contract(),
    )


def coverage_summary(plan: SyntheticCorpusPlan) -> Mapping[str, object]:
    engines = tuple(sorted({case.engine for case in plan.cases}))
    extensions = tuple(sorted({case.extension for case in plan.cases}))
    file_types = tuple(sorted({case.file_type for case in plan.cases}))
    return MappingProxyType({
        "total_samples": plan.total_samples,
        "benign_samples": plan.benign_samples,
        "malicious_samples": plan.malicious_samples,
        "engines": engines,
        "extensions": extensions,
        "file_types": file_types,
        "worker_matrix": WORKER_MATRIX,
        "queue_depth_matrix": QUEUE_DEPTH_MATRIX,
        "restart_point_matrix": RESTART_POINT_MATRIX,
        "timeout_pressure_matrix": TIMEOUT_PRESSURE_MATRIX,
        "archive_depth_matrix": ARCHIVE_DEPTH_MATRIX,
        "scan_order_matrix": SCAN_ORDER_MATRIX,
        "fast_path_configuration": _sorted_mapping_text_items(plan.fast_path_configuration),
        "deep_scan_configuration": _sorted_mapping_text_items(plan.deep_scan_configuration),
        "fast_path_artifacts": plan.json_persistence_contract.fast_path_artifacts,
        "deep_scan_artifacts": plan.json_persistence_contract.deep_scan_artifacts,
        "cross_path_artifacts": plan.json_persistence_contract.cross_path_artifacts,
        "persistence_counters": plan.json_persistence_contract.persistence_counters,
        "zero_loss_requirements": _sorted_mapping_text_items(plan.json_persistence_contract.zero_loss_requirements),
    })


__all__ = (
    "all_stress_file_type_contracts",
    "coverage_summary",
    "engine_file_type_contracts",
    "json_persistence_contract",
    "synthesize_10000_stress_plan",
)
