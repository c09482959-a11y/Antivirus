"""Canonical immutable language-neutral static-program-analysis contracts.

These contracts describe only facts parsed from an artifact.  They do not carry
ATT&CK technique identifiers, calibrated probabilities, runtime process/host
identity, or claims that an operation executed or succeeded.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from math import isfinite
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)

STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION = "static_program_analysis_v3"
STATIC_OPERATION_SCHEMA_VERSION = "static_operation_v3"
STATIC_FLOW_EDGE_SCHEMA_VERSION = "static_flow_edge_v4"
STATIC_OBSERVATION_REFERENCE_SCHEMA_VERSION = "static_observation_reference_v3"
STATIC_OPERATION_PROJECTION_VERSION = "static_operation_projection_v4"

STATIC_ANALYSIS_STATUSES = frozenset({"complete", "partial", "truncated", "unavailable", "failed"})
STATIC_REACHABILITY_STATES = frozenset({
    "entrypoint_reachable",
    "locally_reachable",
    "conditionally_reachable",
    "unreachable",
    "unresolved",
})
STATIC_CONTROL_FLOW_PROVENANCE = frozenset({
    "static_control_flow",
    "syntactic_order",
    "unavailable",
})
STATIC_RESOLUTION_STATES = frozenset({"resolved", "partial", "unresolved", "unavailable"})
STATIC_INTEGRITY_STATES = frozenset({"verified", "partial", "unavailable"})
STATIC_DATA_FLOW_EDGE_KINDS = frozenset({
    "assignment",
    "argument",
    "return",
    "attribute",
    "index",
    "phi",
    "alias",
    "source_to_sink",
})
STATIC_CONTROL_FLOW_EDGE_KINDS = frozenset({
    "call_direct",
    "call_indirect",
    "branch_conditional",
    "branch_unconditional",
    "branch_indirect",
    "fallthrough",
    "control_return",
    "trap",
})
STATIC_FLOW_EDGE_KINDS = frozenset({
    *STATIC_DATA_FLOW_EDGE_KINDS,
    *STATIC_CONTROL_FLOW_EDGE_KINDS,
})
_CONTROL_EDGE_TARGET_REQUIRED = frozenset({
    "call_direct",
    "branch_conditional",
    "branch_unconditional",
    "fallthrough",
})
_CONTROL_EDGE_TARGET_FORBIDDEN = frozenset({
    "call_indirect",
    "branch_indirect",
    "control_return",
    "trap",
})
STATIC_OPERATION_KINDS = frozenset({
    "resource_reference",
    "file_open",
    "file_read",
    "file_write",
    "database_open",
    "database_query",
    "registry_access",
    "config_access",
    "process_open",
    "process_launch",
    "memory_allocate",
    "memory_read",
    "memory_write",
    "memory_protect",
    "thread_execute",
    "apc_execute",
    "context_execute",
    "decrypt",
    "decode",
    "decompress",
    "serialize",
    "archive",
    "network_connect",
    "network_download",
    "network_upload",
    "network_send",
    "credential_store_discovery",
    "credential_store_query",
    "security_configuration_modify",
    "security_control_disable",
    "security_process_terminate",
    "security_service_stop",
    "native_instruction_boundary",
    "native_call",
    "native_branch",
    "native_return",
    "native_trap",
    "native_syscall",
})
STATIC_NON_OBSERVATION_OPERATION_KINDS = frozenset({"native_instruction_boundary"})

# One exact vocabulary owns all bounded static-analysis limitation reasons.
# Frontends may emit only these stable semantic states; exception text and
# parser-specific diagnostics belong in unavailable/failure detail instead.
STATIC_LIMITATION_CODES = frozenset({
    "ambiguous_function_resolution",
    "ambiguous_import_alias",
    "ambiguous_input_flow",
    "ambiguous_source_flow",
    "argument_unresolved",
    "ast_depth_limit_exceeded",
    "ast_node_limit_exceeded",
    "basic_block_limit_exceeded",
    "branch_target_limit_exceeded",
    "call_signature_incompatible",
    "command_limit_exceeded",
    "control_flow_source_operation_unavailable",
    "control_flow_target_inside_instruction",
    "control_flow_target_operation_unavailable",
    "control_flow_target_outside_executable_section",
    "control_flow_unresolved",
    "decoded_byte_limit_exceeded",
    "decoder_api_error",
    "decoder_detail_error",
    "duplicate_function_name",
    "elapsed_time_limit_exceeded",
    "evaluation_stack_underflow",
    "exception_sections_not_interpreted",
    "flow_edge_limit_exceeded",
    "function_limit_exceeded",
    "indirect_branch_target_unresolved",
    "indirect_call_target_unresolved",
    "instruction_limit_exceeded",
    "inter_basic_block_value_flow_not_interpreted",
    "label_limit_exceeded",
    "operation_limit_exceeded",
    "overlapping_instruction_candidate",
    "parser_timeout",
    "powershell_nesting_limit_exceeded",
    "powershell_statement_limit_exceeded",
    "powershell_token_limit_exceeded",
    "sequential_decode_left_executable_section",
    "source_size_limit_exceeded",
    "target_argument_unresolved",
    "target_unresolved",
    "truncated_instruction",
    "typescript_parser_bridge_output_limit_exceeded",
    "undecodable_instruction",
    "unresolved_construct_limit_exceeded",
    "unresolved_input_or_target",
    "unresolved_network_target",
    "unresolved_path",
    "unresolved_target",
})

# Exact API/command observations are additional factual projections of the same
# owned StaticOperation.  They never replace the generic operation-kind tag and
# therefore cannot manufacture a second physical evidence root.
STATIC_OPERATION_EXACT_CALL_TAGS = MappingProxyType({
    "createremotethread": "static_create_remote_thread_operation",
    "minidumpwritedump": "static_minidump_write_dump_operation",
    "openprocess": "static_open_process_operation",
    "virtualallocex": "static_virtual_alloc_ex_operation",
    "virtualprotectex": "static_virtual_protect_ex_operation",
    "writeprocessmemory": "static_write_process_memory_operation",
})
STATIC_OPERATION_EXACT_TAG_IDS = frozenset({
    *STATIC_OPERATION_EXACT_CALL_TAGS.values(),
    "static_encoded_powershell_launch_operation",
})

_MAX_TEXT = 4096
_MAX_SMALL_TEXT = 256
_MAX_ITEMS = 4096
_MAX_ARGUMENT_ITEMS = 128
_MAX_JSON_DEPTH = 8
_MAX_JSON_INTEGER_BITS = 256
_HEX = frozenset("0123456789abcdef")


def _text(value: object, reason: str, *, maximum: int = _MAX_TEXT, allow_blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if len(text) > maximum or (not allow_blank and text == ""):
        raise ValueError(reason)
    return text


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool:
        raise TypeError(reason)
    if value < 0 or value > 2**63 - 1:
        raise ValueError(reason)
    return value


def _optional_nonnegative_int(value: object, reason: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, reason)


def _hex_digest(value: object, reason: str, *, allow_blank: bool = False) -> str:
    text = _text(value, reason, maximum=64, allow_blank=allow_blank).lower()
    if allow_blank and text == "":
        return ""
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def static_artifact_identity(content_sha256: object) -> str:
    """Return the path-independent canonical static-IR artifact identity."""
    return "content_sha256:" + _hex_digest(
        content_sha256, "static_artifact_content_sha256_invalid"
    )


def _identity(value: object, prefix: str, reason: str, *, allow_blank: bool = False) -> str:
    text = _text(value, reason, maximum=256, allow_blank=allow_blank)
    if allow_blank and text == "":
        return ""
    if not text.startswith(prefix) or len(text) <= len(prefix):
        raise ValueError(reason)
    return text


def _text_tuple(
    value: object,
    reason: str,
    *,
    maximum_items: int = _MAX_ITEMS,
    maximum_text: int = _MAX_TEXT,
    identity_prefix: str = "",
) -> tuple[str, ...]:
    if type(value) not in (tuple, list):
        raise TypeError(reason)
    if len(value) > maximum_items:
        raise ValueError(reason)
    output: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = (
            _identity(item, identity_prefix, reason)
            if identity_prefix
            else _text(item, reason, maximum=maximum_text)
        )
        if text not in seen:
            seen.add(text)
            output.append(text)
    return tuple(output)


def _limitation_tuple(
    value: object,
    reason: str,
    *,
    maximum_items: int = 64,
) -> tuple[str, ...]:
    values = _text_tuple(
        value,
        reason,
        maximum_items=maximum_items,
        maximum_text=128,
    )
    if any(item not in STATIC_LIMITATION_CODES for item in values):
        raise ValueError(reason)
    return tuple(sorted(values))


def _freeze_json(value: object, *, depth: int = 0) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("static_analysis_json_depth_exceeded")
    if value is None or type(value) in (str, bool):
        if type(value) is str and len(value) > _MAX_TEXT:
            raise ValueError("static_analysis_json_text_exceeded")
        return value
    if type(value) is int:
        if int.bit_length(value) > _MAX_JSON_INTEGER_BITS:
            raise ValueError("static_analysis_json_integer_exceeded")
        return value
    if type(value) is float:
        if not isfinite(value):
            raise ValueError("static_analysis_json_nonfinite")
        return value
    if type(value) in (tuple, list):
        if len(value) > _MAX_ARGUMENT_ITEMS:
            raise ValueError("static_analysis_json_items_exceeded")
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    if type(value) is dict:
        if len(value) > _MAX_ARGUMENT_ITEMS:
            raise ValueError("static_analysis_json_items_exceeded")
        output: dict[str, object] = {}
        for key, item in dict.items(value):
            key_text = _text(key, "static_analysis_json_key_invalid", maximum=_MAX_SMALL_TEXT)
            if key_text in output:
                raise ValueError("static_analysis_json_key_duplicate")
            output[key_text] = _freeze_json(item, depth=depth + 1)
        return MappingProxyType(dict(sorted(output.items())))
    raise TypeError("static_analysis_json_value_invalid")


def _materialize_json(value: object) -> object:
    if type(value) is MappingProxyType:
        return {key: _materialize_json(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_materialize_json(item) for item in value]
    return value


def _canonical_digest(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(raw).hexdigest()


def _prefixed_digest(prefix: str, value: object) -> str:
    return prefix + _canonical_digest(value)[:40]


STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST = _canonical_digest({
    "analysis": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "control_flow_provenance": sorted(STATIC_CONTROL_FLOW_PROVENANCE),
    "flow_edge": STATIC_FLOW_EDGE_SCHEMA_VERSION,
    "control_flow_edge_kinds": sorted(STATIC_CONTROL_FLOW_EDGE_KINDS),
    "data_flow_edge_kinds": sorted(STATIC_DATA_FLOW_EDGE_KINDS),
    "flow_edge_kinds": sorted(STATIC_FLOW_EDGE_KINDS),
    "integrity_states": sorted(STATIC_INTEGRITY_STATES),
    "limitation_codes": sorted(STATIC_LIMITATION_CODES),
    "limits": {
        "argument_items": _MAX_ARGUMENT_ITEMS,
        "items": _MAX_ITEMS,
        "json_depth": _MAX_JSON_DEPTH,
        "json_integer_bits": _MAX_JSON_INTEGER_BITS,
        "small_text": _MAX_SMALL_TEXT,
        "text": _MAX_TEXT,
    },
    "observation_reference": STATIC_OBSERVATION_REFERENCE_SCHEMA_VERSION,
    "operation": STATIC_OPERATION_SCHEMA_VERSION,
    "operation_exact_call_tags": dict(STATIC_OPERATION_EXACT_CALL_TAGS),
    "operation_exact_tag_ids": sorted(STATIC_OPERATION_EXACT_TAG_IDS),
    "operation_kinds": sorted(STATIC_OPERATION_KINDS),
    "operation_projection": STATIC_OPERATION_PROJECTION_VERSION,
    "reachability_states": sorted(STATIC_REACHABILITY_STATES),
    "resolution_states": sorted(STATIC_RESOLUTION_STATES),
    "statuses": sorted(STATIC_ANALYSIS_STATUSES),
})


@dataclass(frozen=True, slots=True, order=True)
class StaticSourceLocation:
    """Bounded source-code location owned by the static-analysis domain."""

    locator: str
    archive_member: str = ""
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    end_column: int | None = None

    def __post_init__(self) -> None:
        if type(self) is not StaticSourceLocation:
            raise TypeError("static_source_location_owner_invalid")
        locator = _text(self.locator, "static_source_locator_invalid")
        archive_member = _text(
            self.archive_member,
            "static_source_archive_member_invalid",
            allow_blank=True,
        )
        values = {
            "line": _optional_nonnegative_int(self.line, "static_source_line_invalid"),
            "column": _optional_nonnegative_int(self.column, "static_source_column_invalid"),
            "end_line": _optional_nonnegative_int(self.end_line, "static_source_end_line_invalid"),
            "end_column": _optional_nonnegative_int(self.end_column, "static_source_end_column_invalid"),
        }
        if values["line"] is not None and values["line"] == 0:
            raise ValueError("static_source_line_invalid")
        if values["end_line"] is not None and values["end_line"] == 0:
            raise ValueError("static_source_end_line_invalid")
        if values["column"] is not None and values["line"] is None:
            raise ValueError("static_source_column_without_line")
        if values["end_line"] is not None and values["line"] is None:
            raise ValueError("static_source_end_without_start")
        if values["end_column"] is not None and values["end_line"] is None:
            raise ValueError("static_source_end_column_without_line")
        if (
            values["line"] is not None
            and values["end_line"] is not None
            and values["end_line"] < values["line"]
        ):
            raise ValueError("static_source_range_invalid")
        if (
            values["line"] is not None
            and values["end_line"] == values["line"]
            and values["column"] is not None
            and values["end_column"] is not None
            and values["end_column"] < values["column"]
        ):
            raise ValueError("static_source_column_range_invalid")
        object.__setattr__(self, "locator", locator)
        object.__setattr__(self, "archive_member", archive_member)
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def to_record(self) -> dict[str, object]:
        return {
            "archive_member": self.archive_member,
            "column": self.column,
            "end_column": self.end_column,
            "end_line": self.end_line,
            "line": self.line,
            "locator": self.locator,
        }

    @classmethod
    def from_record(cls, value: object) -> "StaticSourceLocation":
        if type(value) is not dict:
            raise TypeError("static_source_location_record_invalid")
        expected = {"archive_member", "column", "end_column", "end_line", "line", "locator"}
        if set(value) != expected:
            raise ValueError("static_source_location_fields_invalid")
        return cls(
            locator=dict.get(value, "locator"),
            archive_member=dict.get(value, "archive_member"),
            line=dict.get(value, "line"),
            column=dict.get(value, "column"),
            end_line=dict.get(value, "end_line"),
            end_column=dict.get(value, "end_column"),
        )


@dataclass(frozen=True, slots=True)
class StaticOperation:
    """One atomic operation parsed from source or a static program representation."""

    operation_id: str
    language: str
    operation_kind: str
    source_location: StaticSourceLocation
    enclosing_function_id: str
    basic_block_id: str
    control_flow_ordinal: int
    control_flow_provenance: str
    reachability_state: str
    platform: str
    actor_program_entity: str
    target_resource_identity: str = ""
    input_value_ids: tuple[str, ...] = ()
    output_value_ids: tuple[str, ...] = ()
    flow_identity: str = ""
    resolved_arguments: Mapping[str, object] = field(default_factory=dict)
    resolution_state: str = "unavailable"
    limitations: tuple[str, ...] = ()
    integrity_status: str = "unavailable"
    schema_version: str = STATIC_OPERATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticOperation:
            raise TypeError("static_operation_owner_invalid")
        language = _text(self.language, "static_operation_language_invalid", maximum=64).lower()
        kind = _text(self.operation_kind, "static_operation_kind_invalid", maximum=64)
        if kind not in STATIC_OPERATION_KINDS:
            raise ValueError("static_operation_kind_invalid")
        if type(self.source_location) is not StaticSourceLocation:
            raise TypeError("static_operation_source_location_invalid")
        function = _identity(self.enclosing_function_id, "fn_", "static_operation_function_identity_invalid")
        block = _identity(self.basic_block_id, "bb_", "static_operation_block_identity_invalid")
        ordinal = _nonnegative_int(self.control_flow_ordinal, "static_operation_ordinal_invalid")
        provenance = _text(self.control_flow_provenance, "static_operation_control_flow_provenance_invalid", maximum=64)
        if provenance not in STATIC_CONTROL_FLOW_PROVENANCE:
            raise ValueError("static_operation_control_flow_provenance_invalid")
        reachability = _text(self.reachability_state, "static_operation_reachability_invalid", maximum=64)
        if reachability not in STATIC_REACHABILITY_STATES:
            raise ValueError("static_operation_reachability_invalid")
        platform = _text(self.platform, "static_operation_platform_invalid", maximum=128, allow_blank=True)
        actor = _identity(self.actor_program_entity, "spe_", "static_operation_actor_identity_invalid")
        target = _identity(
            self.target_resource_identity,
            "res_",
            "static_operation_resource_identity_invalid",
            allow_blank=True,
        )
        inputs = _text_tuple(
            self.input_value_ids,
            "static_operation_input_identity_invalid",
            maximum_items=_MAX_ARGUMENT_ITEMS,
            identity_prefix="val_",
        )
        outputs = _text_tuple(
            self.output_value_ids,
            "static_operation_output_identity_invalid",
            maximum_items=_MAX_ARGUMENT_ITEMS,
            identity_prefix="val_",
        )
        flow = _identity(self.flow_identity, "flow_", "static_operation_flow_identity_invalid", allow_blank=True)
        resolution = _text(self.resolution_state, "static_operation_resolution_invalid", maximum=64)
        if resolution not in STATIC_RESOLUTION_STATES:
            raise ValueError("static_operation_resolution_invalid")
        limitations = _limitation_tuple(
            self.limitations,
            "static_operation_limitation_invalid",
        )
        integrity = _text(self.integrity_status, "static_operation_integrity_invalid", maximum=64)
        if integrity not in STATIC_INTEGRITY_STATES:
            raise ValueError("static_operation_integrity_invalid")
        schema = _text(self.schema_version, "static_operation_schema_invalid", maximum=128)
        if schema != STATIC_OPERATION_SCHEMA_VERSION:
            raise ValueError("static_operation_schema_invalid")
        arguments = _freeze_json(self.resolved_arguments)
        if type(arguments) is not MappingProxyType:
            raise TypeError("static_operation_arguments_mapping_invalid")
        identity_record = {
            "actor_program_entity": actor,
            "basic_block_id": block,
            "control_flow_ordinal": ordinal,
            "control_flow_provenance": provenance,
            "enclosing_function_id": function,
            "flow_identity": flow,
            "input_value_ids": list(inputs),
            "language": language,
            "operation_kind": kind,
            "output_value_ids": list(outputs),
            "platform": platform,
            "reachability_state": reachability,
            "resolution_state": resolution,
            "resolved_arguments": _materialize_json(arguments),
            "source_location": self.source_location.to_record(),
            "target_resource_identity": target,
        }
        computed = _prefixed_digest("sop_", identity_record)
        operation_id = _identity(self.operation_id, "sop_", "static_operation_id_invalid", allow_blank=True) or computed
        if operation_id != computed:
            raise ValueError("static_operation_id_invalid")
        object.__setattr__(self, "operation_id", operation_id)
        object.__setattr__(self, "language", language)
        object.__setattr__(self, "operation_kind", kind)
        object.__setattr__(self, "enclosing_function_id", function)
        object.__setattr__(self, "basic_block_id", block)
        object.__setattr__(self, "control_flow_ordinal", ordinal)
        object.__setattr__(self, "control_flow_provenance", provenance)
        object.__setattr__(self, "reachability_state", reachability)
        object.__setattr__(self, "platform", platform)
        object.__setattr__(self, "actor_program_entity", actor)
        object.__setattr__(self, "target_resource_identity", target)
        object.__setattr__(self, "input_value_ids", inputs)
        object.__setattr__(self, "output_value_ids", outputs)
        object.__setattr__(self, "flow_identity", flow)
        object.__setattr__(self, "resolved_arguments", arguments)
        object.__setattr__(self, "resolution_state", resolution)
        object.__setattr__(self, "limitations", limitations)
        object.__setattr__(self, "integrity_status", integrity)
        object.__setattr__(self, "schema_version", schema)

    @classmethod
    def create(cls, **fields: object) -> "StaticOperation":
        return cls(operation_id="", **fields)  # type: ignore[arg-type]

    def to_record(self) -> dict[str, object]:
        return {
            "actor_program_entity": self.actor_program_entity,
            "basic_block_id": self.basic_block_id,
            "control_flow_ordinal": self.control_flow_ordinal,
            "control_flow_provenance": self.control_flow_provenance,
            "enclosing_function_id": self.enclosing_function_id,
            "flow_identity": self.flow_identity,
            "input_value_ids": list(self.input_value_ids),
            "integrity_status": self.integrity_status,
            "language": self.language,
            "limitations": list(self.limitations),
            "operation_id": self.operation_id,
            "operation_kind": self.operation_kind,
            "output_value_ids": list(self.output_value_ids),
            "platform": self.platform,
            "reachability_state": self.reachability_state,
            "resolution_state": self.resolution_state,
            "resolved_arguments": _materialize_json(self.resolved_arguments),
            "schema_version": self.schema_version,
            "source_location": self.source_location.to_record(),
            "target_resource_identity": self.target_resource_identity,
        }

    @classmethod
    def from_record(cls, value: object) -> "StaticOperation":
        if type(value) is not dict:
            raise TypeError("static_operation_record_invalid")
        expected = {
            "actor_program_entity", "basic_block_id", "control_flow_ordinal",
            "control_flow_provenance", "enclosing_function_id", "flow_identity",
            "input_value_ids", "integrity_status", "language", "limitations",
            "operation_id", "operation_kind", "output_value_ids", "platform",
            "reachability_state", "resolution_state", "resolved_arguments",
            "schema_version", "source_location", "target_resource_identity",
        }
        if set(value) != expected:
            raise ValueError("static_operation_record_fields_invalid")
        return cls(
            operation_id=dict.get(value, "operation_id"),
            language=dict.get(value, "language"),
            operation_kind=dict.get(value, "operation_kind"),
            source_location=StaticSourceLocation.from_record(dict.get(value, "source_location")),
            enclosing_function_id=dict.get(value, "enclosing_function_id"),
            basic_block_id=dict.get(value, "basic_block_id"),
            control_flow_ordinal=dict.get(value, "control_flow_ordinal"),
            control_flow_provenance=dict.get(value, "control_flow_provenance"),
            reachability_state=dict.get(value, "reachability_state"),
            platform=dict.get(value, "platform"),
            actor_program_entity=dict.get(value, "actor_program_entity"),
            target_resource_identity=dict.get(value, "target_resource_identity"),
            input_value_ids=dict.get(value, "input_value_ids"),
            output_value_ids=dict.get(value, "output_value_ids"),
            flow_identity=dict.get(value, "flow_identity"),
            resolved_arguments=dict.get(value, "resolved_arguments"),
            resolution_state=dict.get(value, "resolution_state"),
            limitations=dict.get(value, "limitations"),
            integrity_status=dict.get(value, "integrity_status"),
            schema_version=dict.get(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StaticFlowEdge:
    """One bounded value-flow relation between canonical static operations."""

    edge_id: str
    flow_identity: str
    edge_kind: str
    source_value_id: str
    target_value_id: str
    source_operation_id: str = ""
    target_operation_id: str = ""
    resolution_state: str = "unavailable"
    limitations: tuple[str, ...] = ()
    integrity_status: str = "unavailable"
    schema_version: str = STATIC_FLOW_EDGE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticFlowEdge:
            raise TypeError("static_flow_edge_owner_invalid")
        kind = _text(self.edge_kind, "static_flow_edge_kind_invalid", maximum=64)
        if kind not in STATIC_FLOW_EDGE_KINDS:
            raise ValueError("static_flow_edge_kind_invalid")
        control_edge = kind in STATIC_CONTROL_FLOW_EDGE_KINDS
        flow = _identity(
            self.flow_identity,
            "flow_",
            "static_flow_identity_invalid",
            allow_blank=control_edge,
        )
        source_value = _identity(
            self.source_value_id,
            "val_",
            "static_flow_source_value_invalid",
            allow_blank=control_edge,
        )
        target_value = _identity(
            self.target_value_id,
            "val_",
            "static_flow_target_value_invalid",
            allow_blank=control_edge,
        )
        source_operation = _identity(
            self.source_operation_id,
            "sop_",
            "static_flow_source_operation_invalid",
            allow_blank=not control_edge,
        )
        target_operation = _identity(
            self.target_operation_id,
            "sop_",
            "static_flow_target_operation_invalid",
            allow_blank=True,
        )
        if control_edge:
            if flow or source_value or target_value:
                raise ValueError("static_control_flow_value_identity_present")
            if kind in _CONTROL_EDGE_TARGET_REQUIRED and not target_operation:
                raise ValueError("static_control_flow_target_missing")
            if kind in _CONTROL_EDGE_TARGET_FORBIDDEN and target_operation:
                raise ValueError("static_control_flow_target_present")
        elif not flow or not source_value or not target_value:
            raise ValueError("static_data_flow_identity_missing")
        resolution = _text(self.resolution_state, "static_flow_resolution_invalid", maximum=64)
        if resolution not in STATIC_RESOLUTION_STATES:
            raise ValueError("static_flow_resolution_invalid")
        limitations = _limitation_tuple(
            self.limitations,
            "static_flow_limitation_invalid",
        )
        integrity = _text(self.integrity_status, "static_flow_integrity_invalid", maximum=64)
        if integrity not in STATIC_INTEGRITY_STATES:
            raise ValueError("static_flow_integrity_invalid")
        schema = _text(self.schema_version, "static_flow_schema_invalid", maximum=128)
        if schema != STATIC_FLOW_EDGE_SCHEMA_VERSION:
            raise ValueError("static_flow_schema_invalid")
        identity_record = {
            "edge_kind": kind,
            "flow_identity": flow,
            "source_operation_id": source_operation,
            "source_value_id": source_value,
            "target_operation_id": target_operation,
            "target_value_id": target_value,
        }
        computed = _prefixed_digest("sfe_", identity_record)
        edge_id = _identity(self.edge_id, "sfe_", "static_flow_edge_id_invalid", allow_blank=True) or computed
        if edge_id != computed:
            raise ValueError("static_flow_edge_id_invalid")
        for name, value in (
            ("edge_id", edge_id),
            ("flow_identity", flow),
            ("edge_kind", kind),
            ("source_value_id", source_value),
            ("target_value_id", target_value),
            ("source_operation_id", source_operation),
            ("target_operation_id", target_operation),
            ("resolution_state", resolution),
            ("limitations", limitations),
            ("integrity_status", integrity),
            ("schema_version", schema),
        ):
            object.__setattr__(self, name, value)

    @classmethod
    def create(cls, **fields: object) -> "StaticFlowEdge":
        return cls(edge_id="", **fields)  # type: ignore[arg-type]

    def to_record(self) -> dict[str, object]:
        return {
            "edge_id": self.edge_id,
            "edge_kind": self.edge_kind,
            "flow_identity": self.flow_identity,
            "integrity_status": self.integrity_status,
            "limitations": list(self.limitations),
            "resolution_state": self.resolution_state,
            "schema_version": self.schema_version,
            "source_operation_id": self.source_operation_id,
            "source_value_id": self.source_value_id,
            "target_operation_id": self.target_operation_id,
            "target_value_id": self.target_value_id,
        }

    @classmethod
    def from_record(cls, value: object) -> "StaticFlowEdge":
        if type(value) is not dict:
            raise TypeError("static_flow_edge_record_invalid")
        expected = {
            "edge_id", "edge_kind", "flow_identity", "integrity_status",
            "limitations", "resolution_state", "schema_version",
            "source_operation_id", "source_value_id", "target_operation_id",
            "target_value_id",
        }
        if set(value) != expected:
            raise ValueError("static_flow_edge_record_fields_invalid")
        return cls(
            edge_id=dict.get(value, "edge_id"),
            flow_identity=dict.get(value, "flow_identity"),
            edge_kind=dict.get(value, "edge_kind"),
            source_value_id=dict.get(value, "source_value_id"),
            target_value_id=dict.get(value, "target_value_id"),
            source_operation_id=dict.get(value, "source_operation_id"),
            target_operation_id=dict.get(value, "target_operation_id"),
            resolution_state=dict.get(value, "resolution_state"),
            limitations=dict.get(value, "limitations"),
            integrity_status=dict.get(value, "integrity_status"),
            schema_version=dict.get(value, "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class StaticObservationReference:
    """Immutable reference from a DetectionObservation to one static operation."""

    analysis_semantic_digest: str
    operation_id: str
    actor_program_entity: str
    enclosing_function_id: str
    basic_block_id: str
    target_resource_identity: str = ""
    flow_identity: str = ""
    schema_version: str = STATIC_OBSERVATION_REFERENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticObservationReference:
            raise TypeError("static_observation_reference_owner_invalid")
        values = {
            "analysis_semantic_digest": _hex_digest(
                self.analysis_semantic_digest,
                "static_observation_analysis_digest_invalid",
            ),
            "operation_id": _identity(self.operation_id, "sop_", "static_observation_operation_id_invalid"),
            "actor_program_entity": _identity(
                self.actor_program_entity,
                "spe_",
                "static_observation_actor_identity_invalid",
            ),
            "enclosing_function_id": _identity(
                self.enclosing_function_id,
                "fn_",
                "static_observation_function_identity_invalid",
            ),
            "basic_block_id": _identity(
                self.basic_block_id,
                "bb_",
                "static_observation_block_identity_invalid",
            ),
            "target_resource_identity": _identity(
                self.target_resource_identity,
                "res_",
                "static_observation_resource_identity_invalid",
                allow_blank=True,
            ),
            "flow_identity": _identity(
                self.flow_identity,
                "flow_",
                "static_observation_flow_identity_invalid",
                allow_blank=True,
            ),
            "schema_version": _text(
                self.schema_version,
                "static_observation_reference_schema_invalid",
                maximum=128,
            ),
        }
        if values["schema_version"] != STATIC_OBSERVATION_REFERENCE_SCHEMA_VERSION:
            raise ValueError("static_observation_reference_schema_invalid")
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def to_record(self) -> dict[str, object]:
        return {
            "actor_program_entity": self.actor_program_entity,
            "analysis_semantic_digest": self.analysis_semantic_digest,
            "basic_block_id": self.basic_block_id,
            "enclosing_function_id": self.enclosing_function_id,
            "flow_identity": self.flow_identity,
            "operation_id": self.operation_id,
            "schema_version": self.schema_version,
            "target_resource_identity": self.target_resource_identity,
        }

    @classmethod
    def from_record(cls, value: object) -> "StaticObservationReference":
        if type(value) is not dict:
            raise TypeError("static_observation_reference_record_invalid")
        expected = {
            "actor_program_entity", "analysis_semantic_digest", "basic_block_id",
            "enclosing_function_id", "flow_identity", "operation_id",
            "schema_version", "target_resource_identity",
        }
        if set(value) != expected:
            raise ValueError("static_observation_reference_fields_invalid")
        return cls(**value)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class StaticProgramAnalysis:
    """One deterministic bounded static-analysis result for exact content."""

    content_sha256: str
    content_size: int
    artifact_identity: str
    language: str
    language_version: str
    parser_status: str
    parser_schema_version: str
    parser_digest: str
    operations: tuple[StaticOperation, ...] = ()
    flow_edges: tuple[StaticFlowEdge, ...] = ()
    entrypoint_function_ids: tuple[str, ...] = ()
    unresolved_constructs: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    integrity_status: str = "unavailable"
    unavailable_reason: str = ""
    semantic_digest: str = ""
    schema_version: str = STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StaticProgramAnalysis:
            raise TypeError("static_program_analysis_owner_invalid")
        content_sha = _hex_digest(self.content_sha256, "static_analysis_content_sha256_invalid")
        content_size = _nonnegative_int(self.content_size, "static_analysis_content_size_invalid")
        artifact = _text(self.artifact_identity, "static_analysis_artifact_identity_invalid")
        expected_artifact = static_artifact_identity(content_sha)
        if artifact != expected_artifact:
            raise ValueError("static_analysis_artifact_identity_invalid")
        language = _text(self.language, "static_analysis_language_invalid", maximum=64).lower()
        language_version = _text(
            self.language_version,
            "static_analysis_language_version_invalid",
            maximum=128,
            allow_blank=True,
        )
        status = _text(self.parser_status, "static_analysis_status_invalid", maximum=64)
        if status not in STATIC_ANALYSIS_STATUSES:
            raise ValueError("static_analysis_status_invalid")
        parser_schema = _text(
            self.parser_schema_version,
            "static_analysis_parser_schema_invalid",
            maximum=128,
            allow_blank=status in {"unavailable", "failed"},
        )
        parser_digest = _hex_digest(
            self.parser_digest,
            "static_analysis_parser_digest_invalid",
            allow_blank=status in {"unavailable", "failed"},
        )
        if type(self.operations) is not tuple or len(self.operations) > _MAX_ITEMS:
            raise TypeError("static_analysis_operations_invalid")
        if any(type(item) is not StaticOperation for item in self.operations):
            raise TypeError("static_analysis_operation_owner_invalid")
        operations = tuple(sorted(self.operations, key=lambda item: item.operation_id))
        if len({item.operation_id for item in operations}) != len(operations):
            raise ValueError("static_analysis_operation_duplicate")
        if any(item.language != language for item in operations):
            raise ValueError("static_analysis_operation_language_mismatch")
        if any(item.source_location.locator != artifact for item in operations):
            raise ValueError("static_analysis_operation_source_locator_mismatch")
        if type(self.flow_edges) is not tuple or len(self.flow_edges) > _MAX_ITEMS:
            raise TypeError("static_analysis_flow_edges_invalid")
        if any(type(item) is not StaticFlowEdge for item in self.flow_edges):
            raise TypeError("static_analysis_flow_edge_owner_invalid")
        flow_edges = tuple(sorted(self.flow_edges, key=lambda item: item.edge_id))
        if len({item.edge_id for item in flow_edges}) != len(flow_edges):
            raise ValueError("static_analysis_flow_edge_duplicate")
        operation_ids = {item.operation_id for item in operations}
        for edge in flow_edges:
            if edge.source_operation_id and edge.source_operation_id not in operation_ids:
                raise ValueError("static_analysis_flow_source_operation_missing")
            if edge.target_operation_id and edge.target_operation_id not in operation_ids:
                raise ValueError("static_analysis_flow_target_operation_missing")
        entrypoints = tuple(sorted(_text_tuple(
            self.entrypoint_function_ids,
            "static_analysis_entrypoint_identity_invalid",
            maximum_items=_MAX_ITEMS,
            identity_prefix="fn_",
        )))
        unresolved = tuple(sorted(_text_tuple(
            self.unresolved_constructs,
            "static_analysis_unresolved_construct_invalid",
            maximum_items=256,
            maximum_text=512,
        )))
        limitations = _limitation_tuple(
            self.limitations,
            "static_analysis_limitation_invalid",
            maximum_items=256,
        )
        integrity = _text(self.integrity_status, "static_analysis_integrity_invalid", maximum=64)
        if integrity not in STATIC_INTEGRITY_STATES:
            raise ValueError("static_analysis_integrity_invalid")
        unavailable = _text(
            self.unavailable_reason,
            "static_analysis_unavailable_reason_invalid",
            maximum=512,
            allow_blank=True,
        )
        if status in {"unavailable", "failed"}:
            if operations or flow_edges or unavailable == "":
                raise ValueError("static_analysis_unavailable_contract_invalid")
            integrity = "unavailable"
        elif unavailable:
            raise ValueError("static_analysis_available_reason_invalid")
        if status == "complete" and integrity != "verified":
            raise ValueError("static_analysis_complete_integrity_invalid")
        schema = _text(self.schema_version, "static_analysis_schema_invalid", maximum=128)
        if schema != STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION:
            raise ValueError("static_analysis_schema_invalid")
        semantic_record = {
            "artifact_identity": artifact,
            "content_sha256": content_sha,
            "content_size": content_size,
            "entrypoint_function_ids": list(entrypoints),
            "flow_edges": [item.to_record() for item in flow_edges],
            "integrity_status": integrity,
            "language": language,
            "language_version": language_version,
            "limitations": list(limitations),
            "operations": [item.to_record() for item in operations],
            "parser_digest": parser_digest,
            "parser_schema_version": parser_schema,
            "parser_status": status,
            "schema_version": schema,
            "unavailable_reason": unavailable,
            "unresolved_constructs": list(unresolved),
        }
        computed = _canonical_digest(semantic_record)
        semantic_digest = _hex_digest(
            self.semantic_digest,
            "static_analysis_semantic_digest_invalid",
            allow_blank=True,
        ) or computed
        if semantic_digest != computed:
            raise ValueError("static_analysis_semantic_digest_invalid")
        for name, value in (
            ("content_sha256", content_sha),
            ("content_size", content_size),
            ("artifact_identity", artifact),
            ("language", language),
            ("language_version", language_version),
            ("parser_status", status),
            ("parser_schema_version", parser_schema),
            ("parser_digest", parser_digest),
            ("operations", operations),
            ("flow_edges", flow_edges),
            ("entrypoint_function_ids", entrypoints),
            ("unresolved_constructs", unresolved),
            ("limitations", limitations),
            ("integrity_status", integrity),
            ("unavailable_reason", unavailable),
            ("semantic_digest", semantic_digest),
            ("schema_version", schema),
        ):
            object.__setattr__(self, name, value)

    def operation(self, operation_id: object) -> StaticOperation:
        identity = _identity(operation_id, "sop_", "static_analysis_operation_lookup_invalid")
        for operation in self.operations:
            if operation.operation_id == identity:
                return operation
        raise KeyError(identity)

    def to_record(self) -> dict[str, object]:
        return {
            "artifact_identity": self.artifact_identity,
            "content_sha256": self.content_sha256,
            "content_size": self.content_size,
            "entrypoint_function_ids": list(self.entrypoint_function_ids),
            "flow_edges": [item.to_record() for item in self.flow_edges],
            "integrity_status": self.integrity_status,
            "language": self.language,
            "language_version": self.language_version,
            "limitations": list(self.limitations),
            "operations": [item.to_record() for item in self.operations],
            "parser_digest": self.parser_digest,
            "parser_schema_version": self.parser_schema_version,
            "parser_status": self.parser_status,
            "schema_version": self.schema_version,
            "semantic_digest": self.semantic_digest,
            "unavailable_reason": self.unavailable_reason,
            "unresolved_constructs": list(self.unresolved_constructs),
        }

    @classmethod
    def from_record(cls, value: object) -> "StaticProgramAnalysis":
        if type(value) is not dict:
            raise TypeError("static_program_analysis_record_invalid")
        expected = {
            "artifact_identity", "content_sha256", "content_size",
            "entrypoint_function_ids", "flow_edges", "integrity_status",
            "language", "language_version", "limitations", "operations",
            "parser_digest", "parser_schema_version", "parser_status",
            "schema_version", "semantic_digest", "unavailable_reason",
            "unresolved_constructs",
        }
        if set(value) != expected:
            raise ValueError("static_program_analysis_record_fields_invalid")
        operations_value = dict.get(value, "operations")
        edges_value = dict.get(value, "flow_edges")
        if type(operations_value) is not list or type(edges_value) is not list:
            raise TypeError("static_program_analysis_sequence_invalid")
        return cls(
            content_sha256=dict.get(value, "content_sha256"),
            content_size=dict.get(value, "content_size"),
            artifact_identity=dict.get(value, "artifact_identity"),
            language=dict.get(value, "language"),
            language_version=dict.get(value, "language_version"),
            parser_status=dict.get(value, "parser_status"),
            parser_schema_version=dict.get(value, "parser_schema_version"),
            parser_digest=dict.get(value, "parser_digest"),
            operations=tuple(StaticOperation.from_record(item) for item in operations_value),
            flow_edges=tuple(StaticFlowEdge.from_record(item) for item in edges_value),
            entrypoint_function_ids=dict.get(value, "entrypoint_function_ids"),
            unresolved_constructs=dict.get(value, "unresolved_constructs"),
            limitations=dict.get(value, "limitations"),
            integrity_status=dict.get(value, "integrity_status"),
            unavailable_reason=dict.get(value, "unavailable_reason"),
            semantic_digest=dict.get(value, "semantic_digest"),
            schema_version=dict.get(value, "schema_version"),
        )


def static_observation_reference_from_detection(
    observation: object,
) -> StaticObservationReference:
    """Validate the immutable static relation carried by one detection observation.

    This is the sole bridge from generic DetectionObservation evidence back to
    static program-entity/flow identities.  A partial or forged nested mapping
    cannot become Tag/Chain correlation authority.
    """
    if type(observation) is not DetectionObservation:
        raise TypeError("static_observation_detection_owner_invalid")
    if observation.modality not in {"static_control_flow", "static_structure"}:
        raise ValueError("static_observation_detection_modality_invalid")
    raw = observation.evidence.get("static_observation_reference")
    if type(raw) is not MappingProxyType:
        raise TypeError("static_observation_reference_evidence_invalid")
    materialized = _materialize_json(raw)
    reference = StaticObservationReference.from_record(materialized)
    if observation.actor_identity != reference.actor_program_entity:
        raise ValueError("static_observation_actor_projection_mismatch")
    if observation.target_identity != reference.target_resource_identity:
        raise ValueError("static_observation_target_projection_mismatch")
    if observation.source_location.location_type != "static_operation":
        raise ValueError("static_observation_source_projection_mismatch")
    if observation.source_location.event_id != reference.operation_id:
        raise ValueError("static_observation_operation_projection_mismatch")
    if observation.process_identity or observation.host_identity or observation.connection_identity:
        raise ValueError("static_observation_runtime_identity_present")
    if observation.evidence.get("claim_scope") != "static_operation":
        raise ValueError("static_observation_claim_scope_invalid")
    if observation.evidence.get("execution_observed") is not False:
        raise ValueError("static_observation_execution_claim_invalid")
    return reference


def static_operation_observation_tag(operation_kind: object) -> str:
    kind = _text(operation_kind, "static_operation_tag_kind_invalid", maximum=64)
    if kind not in STATIC_OPERATION_KINDS:
        raise ValueError("static_operation_tag_kind_invalid")
    return "static_" + kind + "_operation"


def static_operation_observation_tags(operation: object) -> tuple[str, ...]:
    """Return deterministic atomic tags for one owned static operation."""
    if type(operation) is not StaticOperation:
        raise TypeError("static_operation_projection_operation_invalid")
    if operation.operation_kind in STATIC_NON_OBSERVATION_OPERATION_KINDS:
        return ()
    tags = [static_operation_observation_tag(operation.operation_kind)]
    call = operation.resolved_arguments.get("call")
    if type(call) is str:
        base = str.__str__(call).lower().split(".")[-1]
        exact = STATIC_OPERATION_EXACT_CALL_TAGS.get(base)
        if exact is not None:
            tags.append(exact)
        if operation.operation_kind == "process_launch":
            command_parts = []
            for key in sorted(operation.resolved_arguments):
                if key == "call":
                    continue
                value = operation.resolved_arguments[key]
                if type(value) is str:
                    command_parts.append(str.__str__(value).lower())
                elif type(value) in (tuple, list):
                    command_parts.extend(
                        (
                            str.__str__(item).lower()
                            if type(item) is str
                            else int.__str__(item)
                            if type(item) is int and type(item) is not bool
                            else "true" if item is True else "false"
                        )
                        for item in value
                        if type(item) in (str, int, bool)
                    )
            command = " ".join(command_parts)
            if (
                ("powershell" in command or "pwsh" in command)
                and any(token in command for token in ("-enc", "-encodedcommand", "-encoded"))
            ):
                tags.append("static_encoded_powershell_launch_operation")
    return tuple(dict.fromkeys(tags))


def project_static_operation_observations(
    analysis: object,
    operation: object,
    *,
    producer_id: object = "static_program_analysis",
    stage_id: object = "static_operation_projection",
) -> tuple[DetectionObservation, ...]:
    """Project one exact static operation to its atomic physical observations."""
    if type(analysis) is not StaticProgramAnalysis:
        raise TypeError("static_operation_projection_analysis_invalid")
    if type(operation) is not StaticOperation:
        raise TypeError("static_operation_projection_operation_invalid")
    if analysis.operation(operation.operation_id) is not operation:
        raise ValueError("static_operation_projection_owner_mismatch")
    producer = _text(producer_id, "static_operation_projection_producer_invalid", maximum=256)
    stage = _text(stage_id, "static_operation_projection_stage_invalid", maximum=256)
    reference = StaticObservationReference(
        analysis_semantic_digest=analysis.semantic_digest,
        operation_id=operation.operation_id,
        actor_program_entity=operation.actor_program_entity,
        enclosing_function_id=operation.enclosing_function_id,
        basic_block_id=operation.basic_block_id,
        target_resource_identity=operation.target_resource_identity,
        flow_identity=operation.flow_identity,
    )
    modality = (
        "static_control_flow"
        if operation.control_flow_provenance == "static_control_flow"
        else "static_structure"
    )
    if operation.integrity_status == "unavailable":
        directness = "unavailable"
    elif operation.reachability_state in {"entrypoint_reachable", "conditionally_reachable"}:
        directness = "direct"
    else:
        directness = "context"
    if operation.integrity_status == "verified" and operation.resolution_state == "resolved":
        confidence = 1.0
    elif operation.integrity_status == "partial":
        confidence = 0.5
    elif operation.integrity_status == "verified":
        confidence = 0.75
    else:
        confidence = 0.0
    if directness == "context":
        confidence = min(confidence, 0.5)
    source = ObservationSourceLocation(
        location_type="static_operation",
        locator=operation.source_location.locator,
        archive_member=operation.source_location.archive_member,
        event_id=operation.operation_id,
    )
    evidence = {
        "claim_scope": "static_operation",
        "execution_observed": False,
        "limitations": list(operation.limitations),
        "operation_kind": operation.operation_kind,
        "reachability_state": operation.reachability_state,
        "resolution_state": operation.resolution_state,
        "static_observation_reference": reference.to_record(),
        "static_source_location": operation.source_location.to_record(),
    }
    return tuple(
        DetectionObservation.create(
            tag=tag_text,
            producer_id=producer,
            stage_id=stage,
            modality=modality,
            platform=operation.platform,
            actor_identity=operation.actor_program_entity,
            target_identity=operation.target_resource_identity,
            artifact_identity=analysis.artifact_identity,
            process_identity="",
            host_identity="",
            connection_identity="",
            source_location=source,
            ordinal=operation.control_flow_ordinal,
            timestamp=None,
            timing_provenance=operation.control_flow_provenance,
            integrity_status={"verified": "verified", "partial": "partial", "unavailable": "unavailable"}[operation.integrity_status],
            directness=directness,
            confidence=confidence,
            evidence=evidence,
            unavailable_reason=(
                "static_operation_integrity_unavailable"
                if operation.integrity_status == "unavailable"
                else ""
            ),
        )
        for tag_text in static_operation_observation_tags(operation)
    )


__all__ = (
    "STATIC_ANALYSIS_STATUSES",
    "STATIC_CONTROL_FLOW_PROVENANCE",
    "STATIC_CONTROL_FLOW_EDGE_KINDS",
    "STATIC_DATA_FLOW_EDGE_KINDS",
    "STATIC_FLOW_EDGE_KINDS",
    "STATIC_FLOW_EDGE_SCHEMA_VERSION",
    "STATIC_INTEGRITY_STATES",
    "STATIC_LIMITATION_CODES",
    "STATIC_OBSERVATION_REFERENCE_SCHEMA_VERSION",
    "STATIC_OPERATION_EXACT_CALL_TAGS",
    "STATIC_OPERATION_EXACT_TAG_IDS",
    "STATIC_NON_OBSERVATION_OPERATION_KINDS",
    "STATIC_OPERATION_KINDS",
    "STATIC_OPERATION_PROJECTION_VERSION",
    "STATIC_OPERATION_SCHEMA_VERSION",
    "STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST",
    "STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION",
    "STATIC_REACHABILITY_STATES",
    "STATIC_RESOLUTION_STATES",
    "StaticFlowEdge",
    "StaticObservationReference",
    "StaticOperation",
    "StaticProgramAnalysis",
    "StaticSourceLocation",
    "project_static_operation_observations",
    "static_artifact_identity",
    "static_observation_reference_from_detection",
    "static_operation_observation_tag",
    "static_operation_observation_tags",
)
