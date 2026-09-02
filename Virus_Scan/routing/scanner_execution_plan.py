"""Canonical declarative scanner capability registry and per-artifact execution plan."""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.artifact_read_snapshot import ArtifactReadSnapshot, require_artifact_read_snapshot
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items, no_hook_text
from Virus_Scan.contracts.runtime_platform_identity import (
    runtime_platform_target_key,
    supported_runtime_target_keys,
)
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.contracts.static_program_analysis import STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST
from Virus_Scan.scanners.api.static_program_analysis_contracts import (
    STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID,
    StaticProgramAnalysisFrontend,
)
from Virus_Scan.utils.stages import (
    FONT_ASSET_EXTENSIONS,
    MEDIA_ASSET_EXTENSIONS,
    UNITY_CONTAINER_ASSET_EXTENSIONS,
)

SCANNER_EXECUTION_PLAN_SCHEMA_VERSION = "scanner_execution_plan_v2"
SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION = "scanner_execution_capability_registry_v2"

_PLAN_STATUSES = frozenset({"selected", "conditional", "not_applicable", "disabled", "unavailable"})
_EXECUTION_STATUSES = frozenset({
    "pending",
    "not_applicable",
    "disabled",
    "unavailable",
    "failed",
    "partial",
    "truncated",
    "complete_no_observation",
    "complete_with_observation",
})
_COST_CLASSES = frozenset({"low", "medium", "high"})
_CONCURRENCY_CLASSES = frozenset({"inline", "intrastage", "external_session"})
_MODALITIES = frozenset({"static_control_flow", "static_string", "static_structure", "verified_rule_match"})


def _owned_text(value: object, reason: str) -> str:
    text, unavailable = no_hook_text(
        value,
        missing_reason=reason,
        unsupported_reason=reason,
    )
    if unavailable or not text:
        raise ValueError(reason)
    return text


def _owned_text_tuple(value: object, reason: str) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for item in no_hook_sequence_items(value):
        text = _owned_text(item, reason)
        if text not in seen:
            seen.add(text)
            out.append(text)
    return tuple(out)


def _identity_text(identity: object, key: str) -> str:
    items = no_hook_mapping_items(identity)
    if items is None:
        return ""
    for candidate, value in items:
        if type(candidate) is str and candidate == key:
            text, reason = no_hook_text(
                value,
                missing_reason="scanner_identity_value_missing",
                unsupported_reason="scanner_identity_value_rejected",
            )
            return "" if reason else text.strip().lower()
    return ""


@dataclass(frozen=True, slots=True)
class ScannerExecutionCapability:
    """One immutable production scanner-family declaration."""

    scanner_id: str
    accepted_stages: tuple[str, ...]
    accepted_extensions: tuple[str, ...] = ()
    accepted_magic_types: tuple[str, ...] = ()
    accepted_actual_categories: tuple[str, ...] = ()
    excluded_extensions: tuple[str, ...] = ()
    excluded_magic_types: tuple[str, ...] = ()
    required_views: tuple[str, ...] = ()
    cost_class: str = "medium"
    concurrency_class: str = "inline"
    modality: str = "static_structure"
    supported_runtime_targets: tuple[str, ...] = ()
    maximum_size_bytes: int = 0
    maximum_nesting_depth: int = 0
    required_predecessors: tuple[str, ...] = ()
    expected_observation_families: tuple[str, ...] = ()
    deterministic: bool = True
    cacheable: bool = True
    cache_dependencies: tuple[str, ...] = ()
    allowed_outcomes: tuple[str, ...] = (
        "unavailable",
        "failed",
        "partial",
        "truncated",
        "complete_no_observation",
        "complete_with_observation",
    )
    conditional: bool = False

    def __post_init__(self) -> None:
        scanner_id = _owned_text(self.scanner_id, "scanner_id_invalid")
        stages = _owned_text_tuple(self.accepted_stages, "scanner_stage_invalid")
        if not stages:
            raise ValueError("scanner_stage_missing")
        cost = _owned_text(self.cost_class, "scanner_cost_invalid")
        concurrency = _owned_text(self.concurrency_class, "scanner_concurrency_invalid")
        modality = _owned_text(self.modality, "scanner_modality_invalid")
        if cost not in _COST_CLASSES:
            raise ValueError("scanner_cost_invalid")
        if concurrency not in _CONCURRENCY_CLASSES:
            raise ValueError("scanner_concurrency_invalid")
        if modality not in _MODALITIES:
            raise ValueError("scanner_modality_invalid")
        if type(self.maximum_size_bytes) is not int or type(self.maximum_size_bytes) is bool or self.maximum_size_bytes < 0:
            raise ValueError("scanner_maximum_size_invalid")
        if type(self.maximum_nesting_depth) is not int or type(self.maximum_nesting_depth) is bool or self.maximum_nesting_depth < 0:
            raise ValueError("scanner_maximum_nesting_invalid")
        if type(self.deterministic) is not bool or type(self.cacheable) is not bool or type(self.conditional) is not bool:
            raise TypeError("scanner_boolean_contract_invalid")
        values = {
            "scanner_id": scanner_id,
            "accepted_stages": stages,
            "accepted_extensions": _owned_text_tuple(self.accepted_extensions, "scanner_extension_invalid"),
            "accepted_magic_types": _owned_text_tuple(self.accepted_magic_types, "scanner_magic_invalid"),
            "accepted_actual_categories": _owned_text_tuple(self.accepted_actual_categories, "scanner_category_invalid"),
            "excluded_extensions": _owned_text_tuple(self.excluded_extensions, "scanner_excluded_extension_invalid"),
            "excluded_magic_types": _owned_text_tuple(self.excluded_magic_types, "scanner_excluded_magic_invalid"),
            "required_views": _owned_text_tuple(self.required_views, "scanner_view_invalid"),
            "cost_class": cost,
            "concurrency_class": concurrency,
            "modality": modality,
            "supported_runtime_targets": _owned_text_tuple(
                self.supported_runtime_targets, "scanner_runtime_target_invalid",
            ),
            "required_predecessors": _owned_text_tuple(self.required_predecessors, "scanner_predecessor_invalid"),
            "expected_observation_families": _owned_text_tuple(self.expected_observation_families, "scanner_observation_family_invalid"),
            "cache_dependencies": _owned_text_tuple(self.cache_dependencies, "scanner_cache_dependency_invalid"),
            "allowed_outcomes": _owned_text_tuple(self.allowed_outcomes, "scanner_allowed_outcome_invalid"),
        }
        if (
            not values["required_views"]
            or not values["expected_observation_families"]
            or not values["cache_dependencies"]
            or not values["allowed_outcomes"]
            or not values["supported_runtime_targets"]
        ):
            raise ValueError("scanner_execution_capability_contract_incomplete")
        declared_targets = frozenset(supported_runtime_target_keys())
        if any(item not in declared_targets for item in values["supported_runtime_targets"]):
            raise ValueError("scanner_runtime_target_invalid")
        if any(item not in _EXECUTION_STATUSES or item == "pending" for item in values["allowed_outcomes"]):
            raise ValueError("scanner_allowed_outcome_invalid")
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def to_record(self) -> dict[str, object]:
        return {
            "accepted_actual_categories": list(self.accepted_actual_categories),
            "allowed_outcomes": list(self.allowed_outcomes),
            "accepted_extensions": list(self.accepted_extensions),
            "accepted_magic_types": list(self.accepted_magic_types),
            "accepted_stages": list(self.accepted_stages),
            "cache_dependencies": list(self.cache_dependencies),
            "cacheable": self.cacheable,
            "concurrency_class": self.concurrency_class,
            "conditional": self.conditional,
            "cost_class": self.cost_class,
            "deterministic": self.deterministic,
            "excluded_extensions": list(self.excluded_extensions),
            "excluded_magic_types": list(self.excluded_magic_types),
            "expected_observation_families": list(self.expected_observation_families),
            "maximum_nesting_depth": self.maximum_nesting_depth,
            "maximum_size_bytes": self.maximum_size_bytes,
            "modality": self.modality,
            "supported_runtime_targets": list(self.supported_runtime_targets),
            "required_predecessors": list(self.required_predecessors),
            "required_views": list(self.required_views),
            "scanner_id": self.scanner_id,
        }


@dataclass(frozen=True, slots=True)
class ScannerPlanDecision:
    scanner_id: str
    plan_status: str
    plan_reason: str
    outcome_status: str
    outcome_reason: str = ""

    def __post_init__(self) -> None:
        scanner_id = _owned_text(self.scanner_id, "scanner_decision_id_invalid")
        plan_status = _owned_text(self.plan_status, "scanner_plan_status_invalid")
        outcome_status = _owned_text(self.outcome_status, "scanner_outcome_status_invalid")
        if plan_status not in _PLAN_STATUSES:
            raise ValueError("scanner_plan_status_invalid")
        if outcome_status not in _EXECUTION_STATUSES:
            raise ValueError("scanner_outcome_status_invalid")
        plan_reason = _owned_text(self.plan_reason, "scanner_plan_reason_invalid")
        outcome_reason = self.outcome_reason if type(self.outcome_reason) is str else ""
        object.__setattr__(self, "scanner_id", scanner_id)
        object.__setattr__(self, "plan_status", plan_status)
        object.__setattr__(self, "plan_reason", plan_reason)
        object.__setattr__(self, "outcome_status", outcome_status)
        object.__setattr__(self, "outcome_reason", outcome_reason)

    def to_record(self) -> dict[str, object]:
        return {
            "outcome_reason": self.outcome_reason,
            "outcome_status": self.outcome_status,
            "plan_reason": self.plan_reason,
            "plan_status": self.plan_status,
            "scanner_id": self.scanner_id,
        }


@dataclass(frozen=True, slots=True)
class ScannerExecutionPlan:
    session_generation_id: str
    runtime_target_key: str
    extension: str
    effective_stage: str
    magic_type: str
    actual_category: str
    content_sha256: str
    artifact_size: int
    archive_depth: int
    registry_digest: str
    decisions: tuple[ScannerPlanDecision, ...]
    schema_version: str = SCANNER_EXECUTION_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self.session_generation_id) is not str or len(self.session_generation_id) != 64:
            raise ValueError("scanner_plan_session_generation_invalid")
        if type(self.runtime_target_key) is not str or not self.runtime_target_key:
            raise ValueError("scanner_plan_runtime_target_invalid")
        if type(self.extension) is not str or type(self.effective_stage) is not str:
            raise TypeError("scanner_plan_identity_invalid")
        if type(self.magic_type) is not str or type(self.actual_category) is not str:
            raise TypeError("scanner_plan_identity_invalid")
        if type(self.content_sha256) is not str:
            raise TypeError("scanner_plan_content_identity_invalid")
        if type(self.artifact_size) is not int or type(self.artifact_size) is bool or self.artifact_size < 0:
            raise ValueError("scanner_plan_size_invalid")
        if type(self.archive_depth) is not int or type(self.archive_depth) is bool or self.archive_depth < 0:
            raise ValueError("scanner_plan_archive_depth_invalid")
        if type(self.registry_digest) is not str or len(self.registry_digest) != 64:
            raise ValueError("scanner_plan_registry_digest_invalid")
        if self.schema_version != SCANNER_EXECUTION_PLAN_SCHEMA_VERSION:
            raise ValueError("scanner_plan_schema_invalid")
        if type(self.decisions) is not tuple or any(type(item) is not ScannerPlanDecision for item in self.decisions):
            raise TypeError("scanner_plan_decisions_invalid")
        ids = tuple(item.scanner_id for item in self.decisions)
        if len(ids) != len(set(ids)) or set(ids) != set(SCANNER_EXECUTION_CAPABILITY_REGISTRY):
            raise ValueError("scanner_plan_registry_coverage_invalid")

    def decision(self, scanner_id: str) -> ScannerPlanDecision:
        for item in self.decisions:
            if item.scanner_id == scanner_id:
                return item
        raise KeyError(scanner_id)

    def allows(self, scanner_id: str) -> bool:
        return self.decision(scanner_id).plan_status in {"selected", "conditional"}

    def with_outcome(self, scanner_id: str, status: str, reason: str = "") -> "ScannerExecutionPlan":
        if status not in _EXECUTION_STATUSES or status == "pending":
            raise ValueError("scanner_outcome_status_invalid")
        capability = SCANNER_EXECUTION_CAPABILITY_REGISTRY.get(scanner_id)
        if capability is None:
            raise KeyError(scanner_id)
        if status not in {"not_applicable", "disabled"} and status not in capability.allowed_outcomes:
            raise ValueError("scanner_outcome_not_allowed")
        updated: list[ScannerPlanDecision] = []
        found = False
        for item in self.decisions:
            if item.scanner_id == scanner_id:
                found = True
                if item.plan_status in {"not_applicable", "disabled", "unavailable"} and status != item.plan_status:
                    raise ValueError("scanner_outcome_conflicts_with_plan")
                updated.append(replace(item, outcome_status=status, outcome_reason=reason))
            else:
                updated.append(item)
        if not found:
            raise KeyError(scanner_id)
        return replace(self, decisions=tuple(updated))

    def pending_scanner_ids(self) -> tuple[str, ...]:
        return tuple(item.scanner_id for item in self.decisions if item.outcome_status == "pending")

    def with_pending_outcomes(self, status: str, reason: str) -> "ScannerExecutionPlan":
        plan = self
        for scanner_id in self.pending_scanner_ids():
            plan = plan.with_outcome(scanner_id, status, reason)
        return plan

    def to_record(self) -> dict[str, object]:
        return {
            "actual_category": self.actual_category,
            "archive_depth": self.archive_depth,
            "artifact_size": self.artifact_size,
            "content_sha256": self.content_sha256,
            "decisions": [item.to_record() for item in self.decisions],
            "effective_stage": self.effective_stage,
            "extension": self.extension,
            "magic_type": self.magic_type,
            "registry_digest": self.registry_digest,
            "runtime_target_key": self.runtime_target_key,
            "schema_version": self.schema_version,
            "session_generation_id": self.session_generation_id,
        }


def _capability(
    scanner_id: str,
    stages: tuple[str, ...],
    *,
    extensions: tuple[str, ...] = (),
    magic_types: tuple[str, ...] = (),
    categories: tuple[str, ...] = (),
    excluded_extensions: tuple[str, ...] = (),
    excluded_magic_types: tuple[str, ...] = (),
    views: tuple[str, ...],
    cost: str,
    concurrency: str,
    modality: str,
    observations: tuple[str, ...],
    dependencies: tuple[str, ...],
    predecessors: tuple[str, ...] = (),
    max_depth: int = 0,
    max_size: int = 0,
    conditional: bool = False,
) -> ScannerExecutionCapability:
    return ScannerExecutionCapability(
        scanner_id=scanner_id,
        accepted_stages=stages,
        accepted_extensions=extensions,
        accepted_magic_types=magic_types,
        accepted_actual_categories=categories,
        excluded_extensions=excluded_extensions,
        excluded_magic_types=excluded_magic_types,
        required_views=views,
        cost_class=cost,
        concurrency_class=concurrency,
        modality=modality,
        supported_runtime_targets=supported_runtime_target_keys(),
        maximum_size_bytes=max_size,
        maximum_nesting_depth=max_depth,
        required_predecessors=predecessors,
        expected_observation_families=observations,
        cache_dependencies=dependencies,
        conditional=conditional,
    )


_STATIC_FRONTEND_EXECUTION_POLICY = (
    ("dotnet_il_static_analysis", ("binary",), "high", ("elf", "macho")),
    ("native_elf_x86_64_static_analysis", ("binary",), "high", ()),
    ("javascript_typescript_static_analysis", ("runtime",), "high", ()),
    ("powershell_static_analysis", ("runtime",), "medium", ()),
    ("batch_cmd_static_analysis", ("runtime",), "low", ()),
    ("shell_static_analysis", ("runtime",), "low", ()),
    ("python_renpy_static_analysis", ("runtime",), "medium", ()),
)


def _static_frontend_capability(
    scanner_id: str, stages: tuple[str, ...], cost: str, excluded_magic_types: tuple[str, ...],
) -> ScannerExecutionCapability:
    frontend = STATIC_PROGRAM_ANALYSIS_FRONTEND_BY_SCANNER_ID[scanner_id]
    if type(frontend) is not StaticProgramAnalysisFrontend:
        raise TypeError("static_frontend_execution_owner_invalid")
    return _capability(
        scanner_id,
        stages,
        extensions=frontend.extensions,
        magic_types=frontend.magic_types,
        excluded_magic_types=excluded_magic_types,
        views=("artifact_read_snapshot",),
        cost=cost,
        concurrency="inline",
        modality="static_control_flow",
        observations=("static_operation", "static_flow"),
        dependencies=(
            "content_sha256",
            "static_frontend:" + frontend.frontend_digest,
            "static_ir:" + STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
        ),
        max_size=frontend.maximum_source_bytes,
    )


_CAPABILITIES = (
    _capability("pickle_embedded_payload", ("*",), extensions=(".pkl", ".pickle", ".save", ".sav", ".rpyc", ".rpyb", ".rpa"), views=("artifact_prefix_2097152",), cost="low", concurrency="inline", modality="static_structure", observations=("pickle_opcode", "pickle_callable_reference"), dependencies=("content_sha256", "pickle_scanner_schema")),
    _capability("csharp_graph", ("cs", "asset", "runtime"), extensions=(".cs",), views=("path_parser",), cost="medium", concurrency="inline", modality="static_structure", observations=("csharp_graph",), dependencies=("content_sha256", "graph_schema")),
    _capability("archive_graph", ("archive",), views=("archive_path_parser",), cost="medium", concurrency="inline", modality="static_structure", observations=("archive_member_graph",), dependencies=("content_sha256", "archive_graph_schema"), max_depth=8),
    _capability("rpa_archive", ("archive",), extensions=(".rpa",), magic_types=("renpy_rpa",), views=("archive_path_parser",), cost="high", concurrency="inline", modality="static_structure", observations=("rpa_archive",), dependencies=("content_sha256", "rpa_scanner_schema"), max_depth=8),
    _capability("generic_archive", ("archive",), excluded_extensions=(".rpa",), excluded_magic_types=("renpy_rpa",), views=("archive_path_parser",), cost="high", concurrency="inline", modality="static_structure", observations=("archive_findings",), dependencies=("content_sha256", "archive_scanner_schema", "archive_limits"), max_depth=8),
    _capability("media_asset", ("asset",), extensions=tuple(sorted(MEDIA_ASSET_EXTENSIONS)), categories=("media",), views=("bounded_asset_sample", "format_parser"), cost="low", concurrency="inline", modality="static_structure", observations=("media_asset",), dependencies=("content_sha256", "asset_scanner_schema")),
    _capability("unity_asset", ("asset",), extensions=tuple(sorted(UNITY_CONTAINER_ASSET_EXTENSIONS)), categories=("unity_asset",), views=("bounded_asset_sample", "format_parser"), cost="medium", concurrency="inline", modality="static_structure", observations=("unity_asset",), dependencies=("content_sha256", "unity_scanner_schema")),
    _capability("font_asset", ("asset",), extensions=tuple(sorted(FONT_ASSET_EXTENSIONS)), categories=("font",), views=("bounded_asset_sample", "font_parser"), cost="low", concurrency="inline", modality="static_structure", observations=("font_asset",), dependencies=("content_sha256", "font_scanner_schema")),
    _capability("asset_string", ("asset",), views=("artifact_prefix_1000000", "latin1_text"), cost="medium", concurrency="inline", modality="static_string", observations=("string_context",), dependencies=("content_sha256", "string_scanner_schema"), predecessors=("media_asset", "unity_asset", "font_asset"), conditional=True),
    _capability("binary_static", ("binary",), views=("artifact_read_snapshot",), cost="high", concurrency="intrastage", modality="static_structure", observations=("binary_static",), dependencies=("content_sha256", "binary_scanner_schema")),
    _capability("binary_embedded_pickle", ("binary",), views=("artifact_read_snapshot",), cost="medium", concurrency="intrastage", modality="static_structure", observations=("embedded_pickle",), dependencies=("content_sha256", "pickle_scanner_schema")),
    _capability("image_static", ("image",), views=("artifact_read_snapshot", "image_parser"), cost="medium", concurrency="inline", modality="static_structure", observations=("image_structure", "image_stego"), dependencies=("content_sha256", "image_scanner_schema")),
    _capability("image_string", ("image",), views=("artifact_prefix_512000", "latin1_text"), cost="medium", concurrency="inline", modality="static_string", observations=("string_context",), dependencies=("content_sha256", "string_scanner_schema"), predecessors=("image_static",), conditional=True),
    *(
        _static_frontend_capability(scanner_id, stages, cost, excluded_magic_types)
        for scanner_id, stages, cost, excluded_magic_types in _STATIC_FRONTEND_EXECUTION_POLICY
    ),
    _capability("runtime_context", ("runtime",), views=("artifact_prefix_1500000", "latin1_text"), cost="medium", concurrency="intrastage", modality="static_string", observations=("runtime_context",), dependencies=("content_sha256", "runtime_context_schema")),
    _capability("runtime_decoded", ("runtime",), views=("artifact_prefix_1500000", "latin1_text"), cost="medium", concurrency="intrastage", modality="static_string", observations=("runtime_decoded",), dependencies=("content_sha256", "runtime_decoded_schema")),
    _capability("other_string", ("other", "unknown"), views=("artifact_prefix_750000", "latin1_text"), cost="medium", concurrency="inline", modality="static_string", observations=("string_context",), dependencies=("content_sha256", "string_scanner_schema")),
)

SCANNER_EXECUTION_CAPABILITY_REGISTRY: Mapping[str, ScannerExecutionCapability] = MappingProxyType({item.scanner_id: item for item in _CAPABILITIES})


def scanner_execution_capability_registry_digest() -> str:
    payload = {
        "capabilities": [SCANNER_EXECUTION_CAPABILITY_REGISTRY[key].to_record() for key in sorted(SCANNER_EXECUTION_CAPABILITY_REGISTRY)],
        "schema_version": SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def scanner_execution_capability_registry_record() -> dict[str, object]:
    return {
        "capabilities": [SCANNER_EXECUTION_CAPABILITY_REGISTRY[key].to_record() for key in sorted(SCANNER_EXECUTION_CAPABILITY_REGISTRY)],
        "registry_digest": scanner_execution_capability_registry_digest(),
        "schema_version": SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION,
    }


def _matches(capability: ScannerExecutionCapability, *, extension: str, stage: str, magic_type: str, category: str) -> tuple[bool, str]:
    if "*" not in capability.accepted_stages and stage not in capability.accepted_stages:
        return False, "effective_stage_not_applicable"
    if extension in capability.excluded_extensions or magic_type in capability.excluded_magic_types:
        return False, "identity_explicitly_excluded"
    selectors_present = bool(capability.accepted_extensions or capability.accepted_magic_types or capability.accepted_actual_categories)
    selector_match = (
        extension in capability.accepted_extensions
        or magic_type in capability.accepted_magic_types
        or category in capability.accepted_actual_categories
    )
    if selectors_present and not selector_match:
        return False, "extension_magic_category_not_applicable"
    return True, "conditional_after_predecessor" if capability.conditional else "selected_by_capability"


def build_scanner_execution_plan(
    *,
    scan_session_snapshot: object,
    artifact_read_snapshot: object,
    extension: object,
    effective_stage: object,
    identity: object,
    archive_depth: object,
    disabled_scanners: object = (),
    unavailable_scanners: object = (),
) -> ScannerExecutionPlan:
    """Build one exact immutable scanner plan after file identity resolution."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("scanner_plan_scan_session_snapshot_required")
    session = scan_session_snapshot
    registry_digest = scanner_execution_capability_registry_digest()
    if session.scanner_registry_state != "available":
        raise RuntimeError("scanner_plan_session_scanner_registry_unavailable")
    if session.scanner_registry_digest != registry_digest:
        raise RuntimeError("scanner_plan_session_scanner_registry_mismatch")
    if session.scanner_registry_reason != "":
        raise RuntimeError("scanner_plan_session_scanner_registry_reason_invalid")
    if type(archive_depth) is not int or type(archive_depth) is bool or archive_depth < 0:
        raise ValueError("scanner_plan_archive_depth_invalid")
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot)
    extension_text = extension if type(extension) is str else ""
    stage_text = effective_stage if type(effective_stage) is str else "unknown"
    extension_text = extension_text.strip().lower()
    stage_text = stage_text.strip().lower() or "unknown"
    magic_type = _identity_text(identity, "magic_type")
    category = _identity_text(identity, "actual_category")
    runtime_target = runtime_platform_target_key(session.runtime_platform)
    disabled = frozenset(_owned_text_tuple(disabled_scanners, "disabled_scanner_invalid"))
    unavailable = frozenset(_owned_text_tuple(unavailable_scanners, "unavailable_scanner_invalid"))
    unknown = (disabled | unavailable) - set(SCANNER_EXECUTION_CAPABILITY_REGISTRY)
    if unknown:
        raise ValueError("scanner_plan_unknown_scanner")
    decisions: list[ScannerPlanDecision] = []
    for scanner_id, capability in SCANNER_EXECUTION_CAPABILITY_REGISTRY.items():
        applies, reason = _matches(
            capability,
            extension=extension_text,
            stage=stage_text,
            magic_type=magic_type,
            category=category,
        )
        if not applies:
            decisions.append(ScannerPlanDecision(
                scanner_id, "not_applicable", reason, "not_applicable", reason,
            ))
            continue
        unavailable_reason = ""
        if runtime_target not in capability.supported_runtime_targets:
            unavailable_reason = "runtime_target_unsupported"
        elif capability.maximum_size_bytes and snapshot.size > capability.maximum_size_bytes:
            unavailable_reason = "artifact_size_limit_exceeded"
        elif capability.maximum_nesting_depth and archive_depth > capability.maximum_nesting_depth:
            unavailable_reason = "archive_nesting_limit_exceeded"
        elif scanner_id in unavailable:
            unavailable_reason = "scanner_unavailable_by_session"
        elif not snapshot.complete:
            unavailable_reason = "artifact_read_unavailable"
        if scanner_id in disabled:
            decisions.append(ScannerPlanDecision(
                scanner_id, "disabled", "scanner_disabled_by_session", "disabled",
                "scanner_disabled_by_session",
            ))
        elif unavailable_reason:
            decisions.append(ScannerPlanDecision(
                scanner_id, "unavailable", unavailable_reason, "unavailable", unavailable_reason,
            ))
        else:
            status = "conditional" if capability.conditional else "selected"
            decisions.append(ScannerPlanDecision(scanner_id, status, reason, "pending"))
    return ScannerExecutionPlan(
        session_generation_id=session.generation_id,
        runtime_target_key=runtime_target,
        extension=extension_text,
        effective_stage=stage_text,
        magic_type=magic_type,
        actual_category=category,
        content_sha256=snapshot.content_sha256,
        artifact_size=snapshot.size,
        archive_depth=archive_depth,
        registry_digest=registry_digest,
        decisions=tuple(decisions),
    )


def scanner_result_status(tags: object, error: object = None) -> str:
    """Classify one raw scanner result without inferring semantic authority."""
    if error is not None:
        return "failed"
    texts: list[str] = []
    for item in no_hook_sequence_items(tags):
        text, reason = no_hook_text(
            item,
            missing_reason="scanner_result_tag_missing",
            unsupported_reason="scanner_result_tag_rejected",
        )
        if not reason and text:
            texts.append(text.lower())
    if any("unavailable" in text for text in texts):
        return "unavailable"
    if any("truncated" in text for text in texts):
        return "truncated"
    if any("partial" in text for text in texts):
        return "partial"
    return "complete_with_observation" if texts else "complete_no_observation"


__all__ = (
    "SCANNER_EXECUTION_CAPABILITY_REGISTRY",
    "SCANNER_EXECUTION_CAPABILITY_REGISTRY_SCHEMA_VERSION",
    "SCANNER_EXECUTION_PLAN_SCHEMA_VERSION",
    "ScannerExecutionCapability",
    "ScannerExecutionPlan",
    "ScannerPlanDecision",
    "build_scanner_execution_plan",
    "scanner_execution_capability_registry_digest",
    "scanner_execution_capability_registry_record",
    "scanner_result_status",
)
