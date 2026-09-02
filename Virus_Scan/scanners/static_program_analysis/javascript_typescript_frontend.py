"""Bounded canonical JavaScript/TypeScript static-program-analysis frontend.

A pinned, packaged TypeScript compiler resource performs syntax parsing in a
bounded Node subprocess. The target source is parsed only: it is never executed,
resolved, imported, transpiled, or allowed network/profile access. This Python
owner validates the parser response and constructs the language-neutral static
operation and flow contracts used by every downstream consumer.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import cache
import hashlib
import json
import os
from pathlib import Path
import subprocess

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.artifact_read_snapshot import (
    ArtifactReadSnapshot,
    require_artifact_read_snapshot,
)
from Virus_Scan.contracts.static_program_analysis import (
    static_artifact_identity,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
    StaticSourceLocation,
)
from Virus_Scan.runtime.api import path_contains_filesystem_alias
from Virus_Scan.scanners.static_program_analysis.typescript_parser_runtime import (
    TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
    packaged_typescript_node_runtime_state,
)
from Virus_Scan.storage import scan_cache_repository

JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION = "javascript_typescript_static_frontend_v3"
JAVASCRIPT_TYPESCRIPT_BRIDGE_SCHEMA_VERSION = "javascript_typescript_ast_bridge_v2"
JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES = 1_500_000
JAVASCRIPT_TYPESCRIPT_MAX_AST_NODES = 50_000
JAVASCRIPT_TYPESCRIPT_MAX_AST_DEPTH = 128
JAVASCRIPT_TYPESCRIPT_MAX_OPERATIONS = 4_096
JAVASCRIPT_TYPESCRIPT_MAX_FLOW_EDGES = 4_096
JAVASCRIPT_TYPESCRIPT_MAX_FUNCTIONS = 2_048
JAVASCRIPT_TYPESCRIPT_MAX_UNRESOLVED = 256
JAVASCRIPT_TYPESCRIPT_MAX_TEXT = 4_096
JAVASCRIPT_TYPESCRIPT_MAX_BRIDGE_OUTPUT_BYTES = 12_000_000
JAVASCRIPT_TYPESCRIPT_PARSER_TIMEOUT_SECONDS = 8.0
JAVASCRIPT_TYPESCRIPT_NODE_HEAP_MIB = 256
TYPESCRIPT_PARSER_VERSION = "5.8.3"
TYPESCRIPT_RESOURCE_SHA256 = "dd17428736a07e1db1a138d8a14295ddb2699ba780ee15038acdd2c6da5373a0"
TYPESCRIPT_BRIDGE_SHA256 = "d8fc37f6f04d0b96acda80151cd7f93fddae83b3bd5717b255d258d403627f00"
TYPESCRIPT_LICENSE_SHA256 = "a7d00bfd54525bc694b6e32f64c7ebcf5e6b7ae3657be5cc12767bce74654a47"
TYPESCRIPT_THIRD_PARTY_NOTICE_SHA256 = "1af3c68039c57e539422da82a4faada506ce6d0ea6f90e0b699d02dbcdb7a90c"
TYPESCRIPT_PACKAGE_SHA256 = "ebb0ce176c85ac13ce82f5be7e6f15114732ba0f064ccc893fd9051426d35d3a"

_JAVASCRIPT_EXTENSIONS = frozenset((".cjs", ".js", ".jsx", ".mjs"))
_TYPESCRIPT_EXTENSIONS = frozenset((".cts", ".mts", ".ts", ".tsx"))
_ALL_EXTENSIONS = frozenset((*_JAVASCRIPT_EXTENSIONS, *_TYPESCRIPT_EXTENSIONS))
_HEX = frozenset("0123456789abcdef")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    return hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _identity(prefix: str, *parts: object) -> str:
    return prefix + _canonical_digest([str(part) for part in parts])[:40]


def _language_for_extension(extension: str) -> str:
    return "typescript" if extension in _TYPESCRIPT_EXTENSIONS else "javascript"


@dataclass(frozen=True, slots=True)
class TypeScriptParserResourceState:
    available: bool
    reason: str
    node_executable: str
    node_version: str
    node_platform: str
    node_architecture: str
    node_abi: str
    node_sha256: str
    node_size: int
    runtime_manifest_path: str
    runtime_manifest_sha256: str
    runtime_identity_digest: str
    parser_path: str
    bridge_path: str
    resource_digest: str


@dataclass(frozen=True, slots=True)
class JavaScriptTypeScriptAnalysisResult:
    analysis: StaticProgramAnalysis
    cache_source: str


def _resource_state(
    *,
    available: bool,
    reason: str,
    parser_path: Path,
    bridge_path: Path,
    resource_digest: str = "",
    node_executable: str = "",
    node_version: str = "",
    node_platform: str = "",
    node_architecture: str = "",
    node_abi: str = "",
    node_sha256: str = "",
    node_size: int = 0,
    runtime_manifest_path: str = "",
    runtime_manifest_sha256: str = TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
    runtime_identity_digest: str = "",
) -> TypeScriptParserResourceState:
    return TypeScriptParserResourceState(
        available=available,
        reason=reason[:512],
        node_executable=node_executable,
        node_version=node_version,
        node_platform=node_platform,
        node_architecture=node_architecture,
        node_abi=node_abi,
        node_sha256=node_sha256,
        node_size=node_size,
        runtime_manifest_path=runtime_manifest_path,
        runtime_manifest_sha256=runtime_manifest_sha256,
        runtime_identity_digest=runtime_identity_digest,
        parser_path=str(parser_path),
        bridge_path=str(bridge_path),
        resource_digest=resource_digest,
    )


@cache
def _build_parser_resource_state() -> TypeScriptParserResourceState:
    module_root = Path(__file__).resolve().parent
    resource_root = module_root / "typescript_parser_resource"
    parser_path = resource_root / "typescript.js"
    license_path = resource_root / "LICENSE.txt"
    notice_path = resource_root / "ThirdPartyNoticeText.txt"
    package_path = resource_root / "package.json"
    bridge_path = module_root / "typescript_parser_bridge.js"
    expected = (
        (parser_path, TYPESCRIPT_RESOURCE_SHA256),
        (bridge_path, TYPESCRIPT_BRIDGE_SHA256),
        (license_path, TYPESCRIPT_LICENSE_SHA256),
        (notice_path, TYPESCRIPT_THIRD_PARTY_NOTICE_SHA256),
        (package_path, TYPESCRIPT_PACKAGE_SHA256),
    )
    for path, digest in expected:
        if not path.is_file():
            return _resource_state(
                available=False,
                reason="typescript_parser_resource_missing:" + path.name,
                parser_path=parser_path,
                bridge_path=bridge_path,
            )
        if path_contains_filesystem_alias(path) or _file_digest(path) != digest:
            return _resource_state(
                available=False,
                reason="typescript_parser_resource_integrity_failed:" + path.name,
                parser_path=parser_path,
                bridge_path=bridge_path,
            )
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _resource_state(
            available=False,
            reason="typescript_parser_package_metadata_invalid",
            parser_path=parser_path,
            bridge_path=bridge_path,
        )
    if type(package) is not dict or package.get("version") != TYPESCRIPT_PARSER_VERSION:
        return _resource_state(
            available=False,
            reason="typescript_parser_version_invalid",
            parser_path=parser_path,
            bridge_path=bridge_path,
        )
    runtime = packaged_typescript_node_runtime_state(resource_root)
    runtime_fields = {
        "node_executable": runtime.executable_path,
        "node_version": runtime.node_version,
        "node_platform": runtime.target_platform,
        "node_architecture": runtime.target_architecture,
        "node_abi": runtime.target_abi,
        "node_sha256": runtime.executable_sha256,
        "node_size": runtime.executable_size,
        "runtime_manifest_path": runtime.manifest_path,
        "runtime_manifest_sha256": runtime.manifest_sha256,
        "runtime_identity_digest": runtime.runtime_identity_digest,
    }
    if not runtime.available:
        return _resource_state(
            available=False,
            reason=runtime.reason,
            parser_path=parser_path,
            bridge_path=bridge_path,
            **runtime_fields,
        )
    resource_digest = _canonical_digest({
        "bridge": TYPESCRIPT_BRIDGE_SHA256,
        "license": TYPESCRIPT_LICENSE_SHA256,
        "node_runtime_identity": runtime.runtime_identity_digest,
        "node_runtime_manifest": runtime.manifest_sha256,
        "package": TYPESCRIPT_PACKAGE_SHA256,
        "third_party_notice": TYPESCRIPT_THIRD_PARTY_NOTICE_SHA256,
        "typescript": TYPESCRIPT_RESOURCE_SHA256,
        "version": TYPESCRIPT_PARSER_VERSION,
    })
    return _resource_state(
        available=True,
        reason="",
        parser_path=parser_path,
        bridge_path=bridge_path,
        resource_digest=resource_digest,
        **runtime_fields,
    )


JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST = _canonical_digest({
    "bridge_schema": JAVASCRIPT_TYPESCRIPT_BRIDGE_SCHEMA_VERSION,
    "frontend_schema": JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
    "ir_schema": STATIC_PROGRAM_ANALYSIS_SCHEMA_VERSION,
    "ir_schema_digest": STATIC_PROGRAM_ANALYSIS_SCHEMA_DIGEST,
    "limits": {
        "ast_depth": JAVASCRIPT_TYPESCRIPT_MAX_AST_DEPTH,
        "ast_nodes": JAVASCRIPT_TYPESCRIPT_MAX_AST_NODES,
        "bridge_output_bytes": JAVASCRIPT_TYPESCRIPT_MAX_BRIDGE_OUTPUT_BYTES,
        "node_heap_mib": JAVASCRIPT_TYPESCRIPT_NODE_HEAP_MIB,
        "parser_timeout_seconds": JAVASCRIPT_TYPESCRIPT_PARSER_TIMEOUT_SECONDS,
        "flow_edges": JAVASCRIPT_TYPESCRIPT_MAX_FLOW_EDGES,
        "functions": JAVASCRIPT_TYPESCRIPT_MAX_FUNCTIONS,
        "operations": JAVASCRIPT_TYPESCRIPT_MAX_OPERATIONS,
        "source_bytes": JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES,
        "unresolved": JAVASCRIPT_TYPESCRIPT_MAX_UNRESOLVED,
    },
    "parser_resource_digest": _canonical_digest({
        "bridge": TYPESCRIPT_BRIDGE_SHA256,
        "license": TYPESCRIPT_LICENSE_SHA256,
        "node_runtime_manifest": TYPESCRIPT_NODE_RUNTIME_MANIFEST_SHA256,
        "package": TYPESCRIPT_PACKAGE_SHA256,
        "third_party_notice": TYPESCRIPT_THIRD_PARTY_NOTICE_SHA256,
        "typescript": TYPESCRIPT_RESOURCE_SHA256,
        "version": TYPESCRIPT_PARSER_VERSION,
    }),
})


def javascript_typescript_parser_resource_state() -> TypeScriptParserResourceState:
    return _build_parser_resource_state()



def javascript_typescript_analysis_dependency_digest(extension: object) -> str:
    if type(extension) is not str:
        raise TypeError("javascript_typescript_extension_invalid")
    normalized = str.__str__(extension).lower()
    if normalized not in _ALL_EXTENSIONS:
        raise ValueError("javascript_typescript_extension_not_applicable")
    return _canonical_digest({
        "extension": normalized,
        "frontend_digest": JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
    })


def _decode_source(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "strict")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", "strict")
    if b"\x00" in raw:
        raise UnicodeDecodeError(
            "utf-8",
            raw,
            0,
            min(1, len(raw)),
            "javascript_typescript_encoding_bom_required",
        )
    return raw.decode("utf-8", "strict")


def _unavailable(
    snapshot: ArtifactReadSnapshot,
    reason: str,
    *,
    status: str = "unavailable",
) -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language=_language_for_extension(snapshot.extension.lower()),
        language_version="",
        parser_status=status,
        parser_schema_version="",
        parser_digest="",
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(),
        integrity_status="unavailable",
        unavailable_reason=reason[:512],
    )


def _truncated(snapshot: ArtifactReadSnapshot, limitation: str) -> StaticProgramAnalysis:
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language=_language_for_extension(snapshot.extension.lower()),
        language_version="typescript_" + TYPESCRIPT_PARSER_VERSION,
        parser_status="truncated",
        parser_schema_version=JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
        parser_digest=JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
        operations=(),
        flow_edges=(),
        entrypoint_function_ids=(),
        unresolved_constructs=(),
        limitations=(limitation[:512],),
        integrity_status="partial",
    )


def _bridge_environment(node_executable: str) -> dict[str, str]:
    environment: dict[str, str] = {}
    for key in ("SYSTEMROOT", "WINDIR", "TMP", "TEMP"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment["PATH"] = str(Path(node_executable).resolve().parent)
    environment["LANG"] = "C"
    environment["LC_ALL"] = "C"
    environment["TZ"] = "UTC"
    environment["NODE_NO_WARNINGS"] = "1"
    return environment


def _run_parser_bridge(source: str, extension: str, file_name: str) -> dict[str, object]:
    state = javascript_typescript_parser_resource_state()
    if not state.available:
        raise FileNotFoundError(state.reason)
    request = {
        "extension": extension,
        "file_name": file_name[:512],
        "max_depth": JAVASCRIPT_TYPESCRIPT_MAX_AST_DEPTH,
        "max_edges": JAVASCRIPT_TYPESCRIPT_MAX_FLOW_EDGES,
        "max_functions": JAVASCRIPT_TYPESCRIPT_MAX_FUNCTIONS,
        "max_nodes": JAVASCRIPT_TYPESCRIPT_MAX_AST_NODES,
        "max_operations": JAVASCRIPT_TYPESCRIPT_MAX_OPERATIONS,
        "max_text": JAVASCRIPT_TYPESCRIPT_MAX_TEXT,
        "max_unresolved": JAVASCRIPT_TYPESCRIPT_MAX_UNRESOLVED,
        "source": source,
    }
    encoded = json.dumps(
        request,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", "strict")
    completed = subprocess.run(  # noqa: S603
        (
            state.node_executable,
            "--max-old-space-size=" + str(JAVASCRIPT_TYPESCRIPT_NODE_HEAP_MIB),
            state.bridge_path,
        ),
        input=encoded,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=JAVASCRIPT_TYPESCRIPT_PARSER_TIMEOUT_SECONDS,
        cwd=str(Path(state.bridge_path).parent),
        env=_bridge_environment(state.node_executable),
    )
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", "replace")[:384]
        raise RuntimeError("typescript_parser_bridge_failed:" + reason)
    if len(completed.stdout) > JAVASCRIPT_TYPESCRIPT_MAX_BRIDGE_OUTPUT_BYTES:
        raise OverflowError("typescript_parser_bridge_output_limit_exceeded")
    try:
        value = json.loads(completed.stdout.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("typescript_parser_bridge_output_invalid") from exc
    if type(value) is not dict:
        raise TypeError("typescript_parser_bridge_output_invalid")
    return value


def _exact_fields(value: object, fields: frozenset[str], reason: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ValueError(reason)
    return value


def _owned_text(value: object, reason: str, *, maximum: int = 4096, blank: bool = False) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value)
    if len(text) > maximum or (not blank and not text):
        raise ValueError(reason)
    return text



def _owned_optional_index(value: object, maximum: int, reason: str) -> int | None:
    if value is None:
        return None
    result = exact_bounded_nonnegative_int(value, reason, maximum=maximum)
    if result >= maximum:
        raise ValueError(reason)
    return result


def _owned_text_sequence(
    value: object,
    reason: str,
    *,
    maximum_items: int,
    maximum_text: int = 512,
    prefix: str = "",
) -> tuple[str, ...]:
    if type(value) is not list or len(value) > maximum_items:
        raise TypeError(reason)
    output: list[str] = []
    for item in value:
        text = _owned_text(item, reason, maximum=maximum_text)
        if prefix and (not text.startswith(prefix) or len(text) <= len(prefix)):
            raise ValueError(reason)
        output.append(text)
    return tuple(output)


def _validate_json_value(value: object, *, depth: int = 0) -> object:
    if depth > 8:
        raise ValueError("typescript_bridge_json_depth_exceeded")
    if value is None or type(value) in (str, int, bool):
        if type(value) is str and len(value) > JAVASCRIPT_TYPESCRIPT_MAX_TEXT:
            raise ValueError("typescript_bridge_json_text_exceeded")
        return value
    if type(value) is float:
        if not (value == value and abs(value) != float("inf")):
            raise ValueError("typescript_bridge_json_nonfinite")
        return value
    if type(value) is list:
        if len(value) > 128:
            raise ValueError("typescript_bridge_json_items_exceeded")
        return [_validate_json_value(item, depth=depth + 1) for item in value]
    if type(value) is dict:
        if len(value) > 128:
            raise ValueError("typescript_bridge_json_items_exceeded")
        output: dict[str, object] = {}
        for key, item in dict.items(value):
            text = _owned_text(key, "typescript_bridge_json_key_invalid", maximum=256)
            if text in output:
                raise ValueError("typescript_bridge_json_key_duplicate")
            output[text] = _validate_json_value(item, depth=depth + 1)
        return output
    raise TypeError("typescript_bridge_json_value_invalid")


def _analysis_from_bridge(
    snapshot: ArtifactReadSnapshot,
    response: dict[str, object],
) -> StaticProgramAnalysis:
    root = _exact_fields(
        response,
        frozenset((
            "entrypoint_function_keys",
            "flow_edges",
            "language",
            "limitations",
            "node_count",
            "operations",
            "parse_diagnostics",
            "parser_status",
            "schema_version",
            "typescript_version",
            "unresolved_constructs",
        )),
        "typescript_bridge_fields_invalid",
    )
    if root["schema_version"] != JAVASCRIPT_TYPESCRIPT_BRIDGE_SCHEMA_VERSION:
        raise ValueError("typescript_bridge_schema_invalid")
    if root["typescript_version"] != TYPESCRIPT_PARSER_VERSION:
        raise ValueError("typescript_bridge_version_invalid")
    language = _owned_text(root["language"], "typescript_bridge_language_invalid", maximum=64)
    expected_language = _language_for_extension(snapshot.extension.lower())
    if language != expected_language:
        raise ValueError("typescript_bridge_language_mismatch")
    status = _owned_text(root["parser_status"], "typescript_bridge_status_invalid", maximum=32)
    if status not in {"complete", "truncated", "failed"}:
        raise ValueError("typescript_bridge_status_invalid")
    exact_bounded_nonnegative_int(root["node_count"], "typescript_bridge_node_count_invalid", maximum=JAVASCRIPT_TYPESCRIPT_MAX_AST_NODES * 4)
    diagnostics = root["parse_diagnostics"]
    if type(diagnostics) is not list or len(diagnostics) > 64:
        raise TypeError("typescript_bridge_diagnostics_invalid")
    if status == "failed":
        if root["operations"] or root["flow_edges"]:
            raise ValueError("typescript_bridge_failed_payload_invalid")
        return _unavailable(snapshot, "parser_failed:typescript_syntax_error", status="failed")
    operation_records = root["operations"]
    edge_records = root["flow_edges"]
    if type(operation_records) is not list or len(operation_records) > JAVASCRIPT_TYPESCRIPT_MAX_OPERATIONS:
        raise TypeError("typescript_bridge_operations_invalid")
    if type(edge_records) is not list or len(edge_records) > JAVASCRIPT_TYPESCRIPT_MAX_FLOW_EDGES:
        raise TypeError("typescript_bridge_edges_invalid")
    operation_fields = frozenset((
        "block_key",
        "control_flow_ordinal",
        "flow_identity",
        "function_key",
        "input_value_ids",
        "integrity_status",
        "limitations",
        "operation_kind",
        "output_value_ids",
        "platform",
        "reachability_state",
        "resolution_state",
        "resolved_arguments",
        "source_location",
        "target_resource",
    ))
    location_fields = frozenset(("column", "end_column", "end_line", "line"))
    drafts: list[tuple[dict[str, object], StaticOperation]] = []
    function_keys: set[str] = set()
    for record in operation_records:
        draft = _exact_fields(record, operation_fields, "typescript_bridge_operation_fields_invalid")
        location = _exact_fields(draft["source_location"], location_fields, "typescript_bridge_location_invalid")
        function_key = _owned_text(draft["function_key"], "typescript_bridge_function_invalid", maximum=256)
        block_key = _owned_text(draft["block_key"], "typescript_bridge_block_invalid", maximum=512)
        function_keys.add(function_key)
        flow_identity = _owned_text(draft["flow_identity"], "typescript_bridge_flow_invalid", maximum=256, blank=True)
        if flow_identity and (not flow_identity.startswith("flow_") or any(char not in _HEX for char in flow_identity[5:])):
            raise ValueError("typescript_bridge_flow_invalid")
        target = _owned_text(draft["target_resource"], "typescript_bridge_target_invalid", maximum=JAVASCRIPT_TYPESCRIPT_MAX_TEXT, blank=True)
        operation = StaticOperation.create(
            language=language,
            operation_kind=_owned_text(draft["operation_kind"], "typescript_bridge_operation_kind_invalid", maximum=64),
            source_location=StaticSourceLocation(
                locator=static_artifact_identity(snapshot.content_sha256),
                line=exact_bounded_nonnegative_int(location["line"], "typescript_bridge_line_invalid", maximum=2**31 - 1),
                column=exact_bounded_nonnegative_int(location["column"], "typescript_bridge_column_invalid", maximum=2**31 - 1),
                end_line=exact_bounded_nonnegative_int(location["end_line"], "typescript_bridge_end_line_invalid", maximum=2**31 - 1),
                end_column=exact_bounded_nonnegative_int(location["end_column"], "typescript_bridge_end_column_invalid", maximum=2**31 - 1),
            ),
            enclosing_function_id=_identity("fn_", snapshot.content_sha256, function_key),
            basic_block_id=_identity("bb_", snapshot.content_sha256, function_key, block_key),
            control_flow_ordinal=exact_bounded_nonnegative_int(draft["control_flow_ordinal"], "typescript_bridge_ordinal_invalid", maximum=2**31 - 1),
            control_flow_provenance="static_control_flow",
            reachability_state=_owned_text(draft["reachability_state"], "typescript_bridge_reachability_invalid", maximum=64),
            platform=_owned_text(draft["platform"], "typescript_bridge_platform_invalid", maximum=128, blank=True),
            actor_program_entity=_identity("spe_", snapshot.content_sha256, function_key),
            target_resource_identity="" if not target else _identity("res_", snapshot.content_sha256, target),
            input_value_ids=_owned_text_sequence(
                draft["input_value_ids"],
                "typescript_bridge_input_value_invalid",
                maximum_items=128,
                maximum_text=256,
                prefix="val_",
            ),
            output_value_ids=_owned_text_sequence(
                draft["output_value_ids"],
                "typescript_bridge_output_value_invalid",
                maximum_items=128,
                maximum_text=256,
                prefix="val_",
            ),
            flow_identity=flow_identity,
            resolved_arguments=_validate_json_value(draft["resolved_arguments"]),
            resolution_state=_owned_text(draft["resolution_state"], "typescript_bridge_resolution_invalid", maximum=64),
            limitations=_owned_text_sequence(
                draft["limitations"],
                "typescript_bridge_operation_limitation_invalid",
                maximum_items=64,
            ),
            integrity_status=_owned_text(draft["integrity_status"], "typescript_bridge_integrity_invalid", maximum=64),
        )
        drafts.append((draft, operation))
    edge_fields = frozenset((
        "edge_kind",
        "flow_identity",
        "integrity_status",
        "limitations",
        "resolution_state",
        "source_operation_index",
        "source_value_id",
        "target_operation_index",
        "target_value_id",
    ))
    edges: list[StaticFlowEdge] = []
    for record in edge_records:
        draft = _exact_fields(record, edge_fields, "typescript_bridge_edge_fields_invalid")
        source_index = _owned_optional_index(
            draft["source_operation_index"],
            len(drafts),
            "typescript_bridge_source_operation_index_invalid",
        )
        target_index = _owned_optional_index(
            draft["target_operation_index"],
            len(drafts),
            "typescript_bridge_target_operation_index_invalid",
        )
        edges.append(StaticFlowEdge.create(
            flow_identity=_owned_text(draft["flow_identity"], "typescript_bridge_edge_flow_invalid", maximum=256),
            edge_kind=_owned_text(draft["edge_kind"], "typescript_bridge_edge_kind_invalid", maximum=64),
            source_value_id=_owned_text(draft["source_value_id"], "typescript_bridge_edge_source_value_invalid", maximum=256),
            target_value_id=_owned_text(draft["target_value_id"], "typescript_bridge_edge_target_value_invalid", maximum=256),
            source_operation_id="" if source_index is None else drafts[source_index][1].operation_id,
            target_operation_id="" if target_index is None else drafts[target_index][1].operation_id,
            resolution_state=_owned_text(draft["resolution_state"], "typescript_bridge_edge_resolution_invalid", maximum=64),
            limitations=_owned_text_sequence(
                draft["limitations"],
                "typescript_bridge_edge_limitation_invalid",
                maximum_items=64,
            ),
            integrity_status=_owned_text(draft["integrity_status"], "typescript_bridge_edge_integrity_invalid", maximum=64),
        ))
    entrypoint_keys = _owned_text_sequence(
        root["entrypoint_function_keys"],
        "typescript_bridge_entrypoint_invalid",
        maximum_items=JAVASCRIPT_TYPESCRIPT_MAX_FUNCTIONS,
        maximum_text=256,
    )
    function_keys.update(entrypoint_keys)
    unresolved = _owned_text_sequence(
        root["unresolved_constructs"],
        "typescript_bridge_unresolved_invalid",
        maximum_items=JAVASCRIPT_TYPESCRIPT_MAX_UNRESOLVED,
    )
    limitations = _owned_text_sequence(
        root["limitations"],
        "typescript_bridge_limitation_invalid",
        maximum_items=256,
    )
    return StaticProgramAnalysis(
        content_sha256=snapshot.content_sha256,
        content_size=snapshot.size,
        artifact_identity=static_artifact_identity(snapshot.content_sha256),
        language=language,
        language_version="typescript_" + TYPESCRIPT_PARSER_VERSION,
        parser_status=status,
        parser_schema_version=JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION,
        parser_digest=JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST,
        operations=tuple(operation for _draft, operation in drafts),
        flow_edges=tuple(edges),
        entrypoint_function_ids=tuple(
            _identity("fn_", snapshot.content_sha256, key)
            for key in entrypoint_keys
        ),
        unresolved_constructs=unresolved,
        limitations=limitations,
        integrity_status="partial" if status == "truncated" else "verified",
    )


def analyze_javascript_typescript_snapshot(snapshot: object) -> JavaScriptTypeScriptAnalysisResult:
    """Analyze one exact JS/TS artifact through the packaged real parser."""
    owned = require_artifact_read_snapshot(snapshot)
    extension = owned.extension.lower()
    if extension not in _ALL_EXTENSIONS:
        raise ValueError("javascript_typescript_extension_not_applicable")
    if not owned.complete:
        return JavaScriptTypeScriptAnalysisResult(
            _unavailable(owned, owned.unavailable_reason or "artifact_read_unavailable"),
            "computed",
        )
    dependency = javascript_typescript_analysis_dependency_digest(extension)
    hit = scan_cache_repository().get_static_analysis(
        content_sha256=owned.content_sha256,
        analysis_dependency_digest=dependency,
    )
    if hit is not None:
        return JavaScriptTypeScriptAnalysisResult(hit.analysis, "sqlite_cache")
    if owned.size > JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES or owned.prefix_truncated:
        analysis = _truncated(owned, "source_size_limit_exceeded")
    else:
        parser_resource = javascript_typescript_parser_resource_state()
        if not parser_resource.available:
            analysis = _unavailable(owned, parser_resource.reason)
        else:
            raw = owned.read_prefix(owned.size)
            try:
                source = _decode_source(raw)
                response = _run_parser_bridge(source, extension, Path(owned.canonical_path).name)
                analysis = _analysis_from_bridge(owned, response)
            except UnicodeDecodeError as exc:
                analysis = _unavailable(owned, "parser_failed:" + type(exc).__name__, status="failed")
            except subprocess.TimeoutExpired:
                analysis = _truncated(owned, "parser_timeout")
            except OverflowError as exc:
                reason = exc.args[0] if len(exc.args) == 1 and type(exc.args[0]) is str else ""
                if reason == "typescript_parser_bridge_output_limit_exceeded":
                    analysis = _truncated(owned, reason)
                else:
                    analysis = _unavailable(owned, "parser_failed:OverflowError", status="failed")
            except (FileNotFoundError, RuntimeError, TypeError, ValueError) as exc:
                analysis = _unavailable(
                    owned,
                    "parser_failed:" + type(exc).__name__ + ":" + str(exc)[:320],
                    status="failed",
                )
    scan_cache_repository().put_static_analysis(
        content_sha256=owned.content_sha256,
        content_size=owned.size,
        analysis_dependency_digest=dependency,
        analysis=analysis,
    )
    return JavaScriptTypeScriptAnalysisResult(analysis, "computed")


__all__ = (
    "JAVASCRIPT_TYPESCRIPT_FRONTEND_DIGEST",
    "JAVASCRIPT_TYPESCRIPT_FRONTEND_SCHEMA_VERSION",
    "JAVASCRIPT_TYPESCRIPT_MAX_SOURCE_BYTES",
    "JAVASCRIPT_TYPESCRIPT_NODE_HEAP_MIB",
    "JAVASCRIPT_TYPESCRIPT_PARSER_TIMEOUT_SECONDS",
    "JavaScriptTypeScriptAnalysisResult",
    "TYPESCRIPT_PARSER_VERSION",
    "TypeScriptParserResourceState",
    "analyze_javascript_typescript_snapshot",
    "javascript_typescript_analysis_dependency_digest",
    "javascript_typescript_parser_resource_state",
)
