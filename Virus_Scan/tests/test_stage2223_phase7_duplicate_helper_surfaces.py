from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_duplicate_key
from Virus_Scan.models.api.text_boundary import public_first_unavailable_reason, public_unavailable_contract_mapping
from Virus_Scan.models.contracts.text_boundaries import (
    model_contract_json_safe_scalar,
    model_contract_safe_text,
    model_contract_text_field,
    model_contract_unavailable_record,
)
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.scanners.config.error_contracts import ScannerConfigFailure
from Virus_Scan.scanners.config.loader_results import (
    ArchivePolicyLoadResult,
    BinaryPolicyLoadResult,
    EnginePolicyLoadResult,
    FiletypePolicyLoadResult,
    PayloadPolicyLoadResult,
    PicklePolicyLoadResult,
    RawChunkPolicyLoadResult,
    ScannerLimitsPolicyLoadResult,
    TextPolicyLoadResult,
)
from Virus_Scan.scheduler.evidence_pairs import scheduler_evidence_pairs
from Virus_Scan.utils.probability import safe_probability_score


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.touched = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves hook execution
        self.touched += 1
        raise AssertionError("caller-owned duplicate-key text hook was invoked")


_LOCAL_DUPLICATE_HELPERS = {
    "Virus_Scan/contracts/worker_record.py": ("_worker_duplicate_key",),
    "Virus_Scan/contracts/telemetry.py": ("_telemetry_duplicate_key",),
    "Virus_Scan/contracts/scan_evidence_cache_publication.py": ("_scan_cache_duplicate_key",),
    "Virus_Scan/runtime/immutable_core.py": ("_runtime_duplicate_key",),
    "Virus_Scan/runtime/init_state.py": ("_init_duplicate_key",),
    "Virus_Scan/runtime/determinism.py": ("_determinism_duplicate_key",),
    "Virus_Scan/runtime/profile_scoring_state.py": ("_profile_duplicate_key",),
    "Virus_Scan/detection/profiles/baseline_snapshot.py": ("profile_snapshot_duplicate_key",),
    "Virus_Scan/detection/registries/immutability.py": ("registry_duplicate_key",),
    "Virus_Scan/detection/scoring/adaptive/public_inputs.py": ("adaptive_public_duplicate_key",),
    "Virus_Scan/models/api/graph_contracts.py": (
        "_duplicate_graph_key",
        "_unreadable_graph_mapping_key",
    ),
}

_LOCAL_DUPLICATE_CANONICAL_MARKERS = {
    "Virus_Scan/models/api/graph_contracts.py": "public_duplicate_mapping_key_label",
}

_LOCAL_UNAVAILABLE_MAPPING_HELPERS = {
    "Virus_Scan/models/api/clustering_contracts.py": ("_public_cluster_unavailable_mapping",),
    "Virus_Scan/models/api/graph_contracts.py": ("_public_graph_unavailable_mapping",),
    "Virus_Scan/models/api/profile_contracts.py": ("_public_profile_unavailable_mapping",),
    "Virus_Scan/models/api/profile_learning_contracts.py": ("_public_profile_learning_unavailable_mapping",),
    "Virus_Scan/models/api/profile_retention_contracts.py": ("_public_retention_unavailable_mapping",),
}

_PUBLIC_ADAPTERS = {
    "Virus_Scan/models/api/text_boundary.py": ("public_duplicate_mapping_key_label",),
    "Virus_Scan/publication/json_finalization/projection_text.py": ("final_json_duplicate_key_text",),
    "Virus_Scan/publication/model_evidence_projection/safe_mapping_primitives.py": ("model_evidence_duplicate_key",),
}

_MODEL_CONTRACT_DUPLICATE_HELPERS = {
    "Virus_Scan/models/contracts/model_evidence.py": (
        "_safe_str",
        "_safe_text_field",
        "_unavailable_record",
        "_json_safe_model_evidence_scalar",
    ),
    "Virus_Scan/models/contracts/model_feature_bundle.py": (
        "_safe_str",
        "_safe_text_field",
        "_unavailable_record",
        "_json_safe_model_feature_scalar",
    ),
    "Virus_Scan/models/contracts/model_failure.py": (
        "_safe_str",
        "_safe_text_field",
        "_unavailable_failure_detail_record",
        "_json_safe_failure_scalar",
    ),
    "Virus_Scan/models/contracts/model_snapshot.py": (
        "_safe_str",
        "_text_value",
        "_json_safe_contract_scalar",
    ),
    "Virus_Scan/models/contracts/probability_record.py": ("_safe_str",),
}

_MODEL_CONTRACT_CANONICAL_MARKERS = {
    "Virus_Scan/models/contracts/model_evidence.py": (
        "model_contract_safe_text",
        "model_contract_text_field",
        "model_contract_unavailable_record",
        "model_contract_json_safe_scalar",
    ),
    "Virus_Scan/models/contracts/model_feature_bundle.py": (
        "model_contract_safe_text",
        "model_contract_text_field",
        "model_contract_unavailable_record",
        "model_contract_json_safe_scalar",
    ),
    "Virus_Scan/models/contracts/model_failure.py": (
        "model_contract_safe_text",
        "model_contract_text_field",
        "model_contract_unavailable_record",
        "model_contract_json_safe_scalar",
    ),
    "Virus_Scan/models/contracts/model_snapshot.py": (
        "model_contract_safe_text",
        "model_contract_text_field",
        "model_contract_json_safe_scalar",
    ),
    "Virus_Scan/models/contracts/probability_record.py": ("model_contract_safe_text",),
}

_SCANNER_POLICY_LOAD_RESULT_CLASSES = (
    PayloadPolicyLoadResult,
    PicklePolicyLoadResult,
    RawChunkPolicyLoadResult,
    TextPolicyLoadResult,
    FiletypePolicyLoadResult,
    EnginePolicyLoadResult,
    BinaryPolicyLoadResult,
    ArchivePolicyLoadResult,
    ScannerLimitsPolicyLoadResult,
)

_SCHEDULER_EVIDENCE_PAIR_HELPER_FILES = (
    "Virus_Scan/scheduler/orchestration/inmemory_parent_result_evidence.py",
    "Virus_Scan/scheduler/queue/integrity_evidence.py",
    "Virus_Scan/scheduler/queue/raw_queue_cleanup_evidence.py",
    "Virus_Scan/scheduler/queue/raw_queue_failed_diagnostics_evidence.py",
    "Virus_Scan/scheduler/queue/terminal_accounting_support_evidence.py",
    "Virus_Scan/scheduler/workers/inmemory_file_scan_support_evidence.py",
    "Virus_Scan/scheduler/workers/inmemory_spawn_evidence.py",
    "Virus_Scan/scheduler/workers/retire_tokens_evidence.py",
)

_PROBABILITY_SCORE_HELPER_FILES = {
    "Virus_Scan/contracts/behavior_rarity.py": "_behavior_rarity_clamp",
    "Virus_Scan/models/temporal/anomaly.py": "_temporal_owned_score",
    "Virus_Scan/models/temporal/overlay.py": "_temporal_overlay_clamp",
    "Virus_Scan/models/temporal/state_projection.py": "_temporal_projection_clamp",
    "Virus_Scan/models/temporal/validation_support.py": "_temporal_validation_support_clamp",
}

_GRAPH_EXCEPTION_MESSAGE_FILES = (
    "Virus_Scan/models/graph/attention.py",
    "Virus_Scan/models/graph/cluster_projection.py",
    "Virus_Scan/models/graph/links.py",
    "Virus_Scan/models/graph/method_graph.py",
    "Virus_Scan/models/graph/risk.py",
    "Virus_Scan/models/graph/scan.py",
)

_MODEL_API_FIRST_REASON_HELPERS = {
    "Virus_Scan/models/api/clustering_contracts.py": "_first_cluster_reason",
    "Virus_Scan/models/api/graph_contracts.py": "_first_graph_reason",
    "Virus_Scan/models/api/profile_learning_contracts.py": "_first_profile_learning_reason",
    "Virus_Scan/models/api/temporal_contracts.py": "_first_temporal_reason",
}


def _source(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_stage2223_duplicate_key_policy_has_no_hook_canonical_owner() -> None:
    hostile = HostileText("unsafe")

    assert no_hook_duplicate_key("key", 3) == "key#3"
    assert no_hook_duplicate_key(hostile, 3, rejection="duplicate_text_rejected") == "duplicate_text_rejected"
    assert hostile.touched == 0


def test_stage2223_unavailable_mapping_policy_has_no_hook_canonical_owner() -> None:
    hostile_reason = HostileText("unsafe_reason")
    hostile_evidence_type = HostileText("unsafe_evidence_type")

    unavailable = public_unavailable_contract_mapping("missing", evidence_type="graph_public_contract_value_unavailable")
    assert unavailable == {
        "ready": False,
        "degraded": True,
        "unavailable_reason": "missing",
        "evidence_type": "graph_public_contract_value_unavailable",
        "final_json_must_record": True,
        "replay_record_required": True,
    }
    try:
        unavailable["ready"] = True  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover - mutability would be a policy regression
        raise AssertionError("public unavailable mapping must be immutable")

    fallback = public_unavailable_contract_mapping(hostile_reason, evidence_type=hostile_evidence_type)
    assert fallback["unavailable_reason"] == "public_contract_value_unavailable"
    assert fallback["evidence_type"] == "public_contract_value_unavailable"
    assert hostile_reason.touched == 0
    assert hostile_evidence_type.touched == 0


def test_stage2223_model_contract_primitive_policy_has_no_hook_canonical_owner() -> None:
    hostile = HostileText("unsafe")

    assert model_contract_safe_text(hostile) == "unsafe"
    assert model_contract_text_field(hostile, field_name="model_name", default="fallback") == ("unsafe", "")
    assert model_contract_json_safe_scalar(hostile) is True
    unavailable = model_contract_unavailable_record(hostile, hostile)
    assert unavailable["unavailable_reason"] == "unsafe"
    assert unavailable["value_type"] == "HostileText"
    try:
        unavailable["value"] = "changed"  # type: ignore[index]
    except TypeError:
        pass
    else:  # pragma: no cover - mutability would be a policy regression
        raise AssertionError("model-contract unavailable record must be immutable")
    assert hostile.touched == 0


def test_stage2223_local_duplicate_key_helpers_stay_merged() -> None:
    for path, helpers in _LOCAL_DUPLICATE_HELPERS.items():
        source = _source(path)
        assert _LOCAL_DUPLICATE_CANONICAL_MARKERS.get(path, "no_hook_duplicate_key") in source
        for helper in helpers:
            assert "def " + helper not in source
        assert ' + "#" + int.__str__(' not in source
        assert ' + str.__str__("#") + int.__str__(' not in source


def test_stage2223_local_unavailable_mapping_helpers_stay_merged() -> None:
    for path, helpers in _LOCAL_UNAVAILABLE_MAPPING_HELPERS.items():
        source = _source(path)
        assert "public_unavailable_contract_mapping" in source
        for helper in helpers:
            assert "def " + helper not in source


def test_stage2223_public_duplicate_key_adapters_delegate_to_canonical_owner() -> None:
    for path, adapter_names in _PUBLIC_ADAPTERS.items():
        source = _source(path)
        assert "no_hook_duplicate_key" in source
        for adapter_name in adapter_names:
            assert "def " + adapter_name in source


def test_stage2223_model_contract_duplicate_helper_surfaces_stay_merged() -> None:
    for path, helpers in _MODEL_CONTRACT_DUPLICATE_HELPERS.items():
        source = _source(path)
        for marker in _MODEL_CONTRACT_CANONICAL_MARKERS[path]:
            assert marker in source
        for helper in helpers:
            assert "def " + helper not in source


def test_stage2223_scanner_policy_load_result_properties_have_single_owner() -> None:
    source = _source("Virus_Scan/scanners/config/loader_results.py")
    assert source.count("def ok") == 1
    assert source.count("def failure_evidence") == 1
    assert "class ScannerPolicyLoadResultMixin" in source
    failure = ScannerConfigFailure(
        "payload_policy",
        "unit",
        "invalid",
        ({"error_category": "scanner_config_validation_failure"},),
    )

    for result_cls in _SCANNER_POLICY_LOAD_RESULT_CLASSES:
        ok_result = result_cls(snapshot=object())
        assert ok_result.ok is True
        assert ok_result.failure_evidence == ()
        failed_result = result_cls(snapshot=None, failure=failure)
        assert failed_result.ok is False
        assert failed_result.failure_evidence == failure.failure_evidence


def test_stage2223_scheduler_evidence_pair_helper_has_single_owner() -> None:
    assert scheduler_evidence_pairs(("decision", "unit"), ("accepted", True)) == (
        ("decision", "unit"),
        ("accepted", True),
    )
    for path in _SCHEDULER_EVIDENCE_PAIR_HELPER_FILES:
        source = _source(path)
        assert "scheduler_evidence_pairs" in source
        assert "def _evidence_pairs" not in source
        assert "=_evidence_pairs(" not in source
        assert "JsonEvidencePairs = tuple" not in source


def test_stage2223_probability_score_clamp_policy_has_single_owner() -> None:
    assert safe_probability_score(True) == 0.0
    assert safe_probability_score(False) == 0.0
    assert safe_probability_score(1.5) == 1.0
    assert safe_probability_score(-0.25) == 0.0
    assert safe_probability_score("0.8") == 0.0
    for path, helper in _PROBABILITY_SCORE_HELPER_FILES.items():
        source = _source(path)
        assert "safe_probability_score" in source
        assert "def " + helper not in source


def test_stage2223_graph_exception_message_helper_has_single_owner() -> None:
    assert graph_exception_message("prefix:", RuntimeError("boom")) == "prefix:RuntimeError"
    for path in _GRAPH_EXCEPTION_MESSAGE_FILES:
        source = _source(path)
        assert "graph_exception_message" in source
        assert "def _graph_exception_message" not in source
        assert "_graph_exception_message(" not in source


def test_stage2223_model_api_first_reason_policy_has_single_owner() -> None:
    assert public_first_unavailable_reason(None, "first", "second") == "first"
    assert public_first_unavailable_reason(None, None) is None
    for path, helper in _MODEL_API_FIRST_REASON_HELPERS.items():
        source = _source(path)
        assert "public_first_unavailable_reason" in source
        assert "def " + helper not in source
        assert helper + "(" not in source
    adaptive_source = _source("Virus_Scan/models/api/adaptive_signals.py")
    assert "def first_adaptive_reason" in adaptive_source
    assert "public_first_unavailable_reason(*reasons)" in adaptive_source
