"""Canonical orchestration scan lifecycle owner for UMIGE.

Runtime owns platform/configuration snapshots and scan guards. Orchestration
connects runtime state to scheduler, scanner public contracts, detection,
publication, reporting, and YARA-facing scan services after startup has selected
scan execution.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple
import hashlib
import json
import logging
from pathlib import Path, PosixPath, WindowsPath
import sys
import time
from argparse import Namespace
from types import SimpleNamespace

from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE

import Virus_Scan.cli.args as cli_args
from Virus_Scan.runtime.api import (
    RuntimeConfig,
    build_scan_log_output_plan,
    derive_scan_log_scan_id,
    resource_root_snapshot,
)
from Virus_Scan.core.logging import (
    configure_single_parent_log,
    emit_parent_scan_log_line,
    get_detector_errors,
)
from Virus_Scan.core.paths import configure_runtime_engine_and_ilspy
from Virus_Scan.routing.profile_model_projection import ProfileSchemaInvariantError
from Virus_Scan.models.api.profile_persistence import ensure_authoritative_engine_profiles
from Virus_Scan.storage import scan_cache_repository, sqlite_lifecycle
from Virus_Scan.cli.exit_codes import score_from_result, exit_code_for_score
from Virus_Scan.runtime.api import configure_deep_scan_mode, configure_profile_corruption_policy
from Virus_Scan.persistence import flush_persistent_state
from Virus_Scan.reporting.output import clear_scan_results_before_scan
from Virus_Scan.runtime.api import publish_workload_queue_plan
from Virus_Scan.scheduler.api.runtime import (
    build_workload_classification_plan,
    workload_plan_summary,
)
import Virus_Scan.scheduler.api.runner as scheduler_runner
from Virus_Scan.scheduler.api.final_json import enrich_scheduler_final_json_results
import Virus_Scan.reporting.compact as compact_report
import Virus_Scan.virustotal.reporting as vt_report
from Virus_Scan.virustotal.runtime import initialize_virustotal_runtime
from Virus_Scan.publication.api import (
    ScanResultLedgerAccumulator,
    build_scan_publication_snapshot,
    finalize_scan_results,
    publish_scan_report_set,
    recover_results_from_partial,
)
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.retained_scan_result import (
    retained_publication_record,
    retained_result_marker_present,
)
from Virus_Scan.contracts.env_config import bool_env
from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    no_hook_exact_nonnegative_int,
    no_hook_exact_owner_field,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
import Virus_Scan.yara.match as yara_match
from Virus_Scan.runtime.api import RuntimeContext, acquire_parent_scan_guard, release_parent_scan_guard
from Virus_Scan.orchestration.bootstrap_initialization import initialize_runtime
from Virus_Scan.orchestration.model_state_loader import load_runtime_model_state
from Virus_Scan.orchestration.mitre_initialization import initialize_mitre_from_args
from Virus_Scan.orchestration.yara_initialization import initialize_yara_from_args
from Virus_Scan.orchestration.direct_audit_projection import (
    DirectAuditProjectionContext,
    project_direct_audit_results,
)
from Virus_Scan.runtime.api import release_mitre_runtime, release_yara_runtime
from Virus_Scan.init_runtime.top_level import run_top_level_init


PLR2004N25_0 = 25.0
PLR2004N4 = 4

_CONTEXTUAL_PAYLOAD_ENGINES = frozenset({"embedded_pe_payload", "embedded_zip_payload"})
_CONTEXTUAL_PAYLOAD_TAGS = frozenset({"polyglot_artifact", "embedded_pe_payload", "embedded_zip_payload"})
_REQUIRED_ROUTING_EVIDENCE_KEYS = frozenset({
    "container_engine",
    "artifact_engine",
    "declared_extension",
    "sniffed_type",
    "effective_analysis_engine",
    "baseline_key",
    "extension_baseline",
    "contextual_baseline",
    "fingerprint_evidence",
})
_OWNED_PATH_TYPES = (Path, PosixPath, WindowsPath)
_OWNED_NAMESPACE_TYPES = (Namespace, SimpleNamespace)


def _owned_class_attr(value: object, name: str, default: object = None) -> object:
    if type(name) is not str:
        return default
    try:
        mro = type.__getattribute__(type(value), "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return default
    if type(mro) is not tuple:
        return default
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return default
        class_items = no_hook_mapping_items(class_dict)
        if class_items is None:
            return default
        found = False
        attr = default
        for candidate_key, candidate_value in class_items:
            if type(candidate_key) is str and str.__eq__(candidate_key, name):
                found = True
                attr = candidate_value
                break
        if not found:
            continue
        if type(attr) in (str, bool, int, float, tuple, list, dict, set, frozenset, type(None)) or type(attr) in _OWNED_PATH_TYPES:
            return attr
        return default
    return default


def _owned_attr(value: object, name: str, default: object = None) -> object:
    if type(name) is not str:
        return default
    data = no_hook_plain_instance_dict(value)
    if data is not None and name in data:
        return dict.get(data, name)
    return _owned_class_attr(value, name, default)


def _owned_bound_method(value: object, name: str) -> object:
    if type(name) is not str:
        return None
    data = no_hook_plain_instance_dict(value)
    if data is not None and name in data:
        candidate = dict.get(data, name)
        return candidate if type(candidate) is RUNTIME_NATIVE_FUNCTION_TYPE else None
    try:
        mro = type.__getattribute__(type(value), "__mro__")
    except (AttributeError, TypeError, RuntimeError):
        return None
    if type(mro) is not tuple:
        return None
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError, RuntimeError):
            return None
        class_items = no_hook_mapping_items(class_dict)
        if class_items is None:
            return None
        candidate = None
        for candidate_key, candidate_value in class_items:
            if type(candidate_key) is str and str.__eq__(candidate_key, name):
                candidate = candidate_value
                break
        if type(candidate) is RUNTIME_NATIVE_FUNCTION_TYPE:
            return no_hook_exact_owner_field(value, type(value), name)
    return None


def _set_owned_attr(value: object, name: str, item: object) -> bool:
    if type(name) is not str:
        return False
    data = no_hook_plain_instance_dict(value)
    if data is None:
        return False
    dict.__setitem__(data, name, item)
    return True


def _safe_text(value: object, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_orchestration_text",
        unsupported_reason="unsafe_orchestration_text_rejected",
    )
    if not reason:
        return str.strip(text)
    if type(value) in _OWNED_PATH_TYPES:
        try:
            return str(value)
        except (OSError, ValueError, TypeError, RuntimeError):
            return default
    return default


def _safe_lower(value: object, default: str = "") -> str:
    text = _safe_text(value, default)
    return str.lower(text) if text else default


def _safe_bool(value: object, *, default: bool = False) -> bool:
    metric = exact_bool_or_none(value)
    if metric is not None:
        return metric
    if type(value) is int and type(value) is not bool:
        return value != 0
    text = _safe_lower(value)
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default is True


def _safe_nonnegative_int(value: object, default: int = 0) -> int:
    metric, _reason = no_hook_exact_nonnegative_int(value, default=default, allow_exact_text=True)
    return metric


def _safe_float(value: object, default: float = 0.0) -> float:
    metric, _reason = no_hook_finite_float(value, default=default, allow_exact_text=True)
    return metric


def _mapping_get(mapping: object, key: str, default: object = None) -> object:
    if type(key) is not str:
        return default
    if type(mapping) is dict:
        return dict.get(mapping, key, default)
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for candidate_key, value in items:
        if type(candidate_key) is str and str.__eq__(candidate_key, key):
            return value
    return default


def _mapping_items(mapping: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(mapping)
    return items if items is not None else ()


def _mapping_values(mapping: object) -> tuple[object, ...]:
    return tuple(value for _key, value in _mapping_items(mapping))


def _copy_mapping(mapping: object) -> dict[object, object]:
    out: dict[object, object] = {}
    for key, value in _mapping_items(mapping):
        if type(key) is str:
            out[str.__str__(key)] = value
    return out


def _text_sequence(value: object) -> tuple[str, ...]:
    items = no_hook_mapping_items(value)
    if items is not None:
        candidates = tuple(key for key, _item in items)
    else:
        candidates = no_hook_sequence_items(value)
    normalized: list[str] = []
    for item in candidates:
        text_value = _safe_lower(item)
        if text_value and text_value not in normalized:
            normalized.append(text_value)
    return tuple(normalized)


def _scan_output_plan(args: object) -> object:
    root_value = _owned_attr(args, "scan_log_root", None)
    root_text = _safe_text(root_value)
    root = None if root_text == "" else root_value
    supplied_scan_id = _safe_lower(_owned_attr(args, "scan_id", None))
    started_ns = time.time_ns()
    if supplied_scan_id == "":
        identity_material = "\n".join((
            "scan_log_output_plan_v1",
            _safe_text(_owned_attr(args, "dir", "")),
            _safe_lower(_owned_attr(args, "scheduler", "process"), "process"),
            int.__str__(started_ns),
        ))
        generation = hashlib.sha256(identity_material.encode("utf-8")).hexdigest()
        supplied_scan_id = derive_scan_log_scan_id(
            session_generation=generation,
            started_ns=started_ns,
        )
    return build_scan_log_output_plan(scan_id=supplied_scan_id, root=root)


def parse_and_configure(runtime: object, argv: Optional[list]) -> object:
    return configure_parsed(runtime, cli_args.parse_args(argv))


def configure_parsed(runtime: object, args: object) -> object:
    args = cli_args.normalize_runtime_args(args)
    plan = _scan_output_plan(args)
    Path(plan.staging_path).mkdir(parents=True, exist_ok=True)
    scheduler_mode = _safe_lower(_owned_attr(args, "scheduler", "process"), "process")
    worker_output = _safe_text(_owned_attr(args, "worker_output", ""))
    output_path = (
        worker_output
        if scheduler_mode == "queue-child" and worker_output != ""
        else plan.staging_report_path("scan_results.json").as_posix()
    )
    _set_owned_attr(args, "scan_log_root", plan.scan_log_root)
    _set_owned_attr(args, "scan_id", plan.scan_id)
    _set_owned_attr(args, "scan_log_staging_path", plan.staging_path)
    _set_owned_attr(args, "scan_log_run_path", plan.run_path)
    _set_owned_attr(args, "scan_log_latest_path", plan.latest_path)
    _set_owned_attr(args, "scan_log_output_plan", plan)
    _set_owned_attr(args, "output", output_path)
    _set_owned_attr(args, "log", plan.staging_report_path("scanlog").as_posix())
    requested_log = _owned_attr(args, "log", None)
    if _safe_bool(_owned_attr(args, "no_scanlog", default=False)):
        requested_log = None
    configure_single_parent_log(requested_log)
    if _safe_bool(_owned_attr(args, "debug", default=False)):
        logging.getLogger().setLevel(logging.DEBUG)

    profile_corruption_policy = configure_profile_corruption_policy(_safe_text(_owned_attr(args, "profile_corruption_policy", "hard-fail"), "hard-fail"))
    runtime.set("PROFILE_CORRUPTION_POLICY", profile_corruption_policy)

    deep_default = runtime.get("DEEP_SCAN_MODE", "auto")
    deep_mode = configure_deep_scan_mode(
        _safe_lower(_owned_attr(args, "deep_scan_mode", deep_default), "auto") or "auto"
    )
    runtime.set("DEEP_SCAN_MODE", deep_mode)
    runtime.environment.publish({"UMIGE_DEEP_SCAN_MODE": deep_mode})
    logging.info("Deep scan mode: %s", deep_mode)

    scan_dir = _safe_text(_owned_attr(args, "dir", ""))
    if not Path(scan_dir).exists():
        raise SystemExit(str.__add__("scan target does not exist: ", scan_dir))

    configure_runtime_engine_and_ilspy(args)
    ensure_authoritative_engine_profiles()

    runtime.environment.publish({
        "UMIGE_NO_YARA": "1" if _safe_bool(_owned_attr(args, "no_yara", default=False)) else "0",
        "UMIGE_NO_YARALIGHT": "1" if (_safe_bool(_owned_attr(args, "no_yara", default=False)) or _safe_bool(_owned_attr(args, "no_yaralight", default=False))) else "0",
        "UMIGE_NO_SCAN_CACHE": "1" if _safe_bool(_owned_attr(args, "no_scan_cache", default=False)) else "0",
        "UMIGE_NO_MITRE": "1" if _safe_bool(_owned_attr(args, "no_mitre", default=False)) else "0",
        "UMIGE_YARA_RULE_PATH": _safe_text(_owned_attr(args, "yara", default="")),
        "UMIGE_YARALIGHT_RULE_PATH": _safe_text(_owned_attr(args, "yaralight", default="")),
    })
    scan_cache_enabled = not _safe_bool(_owned_attr(args, "no_scan_cache", default=False))
    runtime.set("SCAN_CACHE_ENABLED", scan_cache_enabled)
    runtime.set("YARA_FORCE_REFRESH", _safe_bool(_owned_attr(args, "yara_force_refresh", default=False)))
    scan_cache_repository().configure(
        sqlite_lifecycle().paths().profiles_dir,
        enabled=scan_cache_enabled,
    )
    load_runtime_model_state()

    is_process_shard = _owned_bound_method(runtime.environment, "is_process_shard")
    _set_owned_attr(runtime, "parent_cli", not bool(is_process_shard() if is_process_shard is not None else False))
    return args


def exit_code_for_results(runtime: object, max_score: float) -> int:
    return exit_code_for_score(
        max_score,
        had_error=bool(runtime.get("SCAN_HAD_ERROR", False) or get_detector_errors(clear=False)),
    )


def attach_direct_audit_fields(args: object, results: Dict[str, object], *, yara_ok: bool) -> Dict[str, object]:
    """Project all records through the single canonical direct-audit owner."""
    scheduler_mode = _safe_text(_owned_attr(args, "scheduler", ""), "unknown") or "unknown"
    requested_engine = _safe_text(_owned_attr(args, "engine", "auto"), "auto") or "auto"
    return project_direct_audit_results(
        results,
        DirectAuditProjectionContext(
            scheduler_mode=scheduler_mode,
            requested_engine=requested_engine,
            yara_enabled=_safe_bool(yara_ok),
        ),
    )


def _publication_results(results: object) -> dict[str, object]:
    publication: dict[str, object] = {}
    for key, retained_or_public in _mapping_items(results):
        key_text = _safe_text(key)
        if key_text == "":
            raise ValueError("scan_publication_result_key_invalid")
        if key_text in publication:
            raise ValueError("scan_publication_result_key_duplicate")
        publication[key_text] = (
            retained_publication_record(retained_or_public)
            if retained_result_marker_present(retained_or_public)
            else retained_or_public
        )
    return publication


def report_results(runtime: object, args: object, results: Dict[str, object], *, yara_ok: bool, persistence_status: object = None) -> Tuple[float, float]:
    output_path = _safe_text(_owned_attr(args, "output", "scan_results.json"), "scan_results.json")
    results = recover_results_from_partial(output_path, results)
    results = attach_direct_audit_fields(args, results, yara_ok=yara_ok)
    results = enrich_scheduler_final_json_results(results)
    parent_cli = _safe_bool(_owned_attr(runtime, "parent_cli", default=False))
    ledger = ScanResultLedgerAccumulator() if parent_cli else None
    if not finalize_scan_results(
        output_path,
        results,
        make_json_safe=None,
        ledger_accumulator=ledger,
    ):
        raise RuntimeError(str.__add__("final scan_results.json write failed: ", output_path))
    publication_results = (
        ledger.publication_results()
        if ledger is not None
        else _publication_results(results)
    )
    max_score = 0.0
    scan_had_error = False
    for public_record in _mapping_values(publication_results):
        max_score = max(max_score, score_from_result(public_record))
        if type(public_record) is dict and (
            len(_text_sequence(_mapping_get(public_record, "errors"))) > 0
            or (
                _safe_lower(_mapping_get(public_record, "verdict"))
                or _safe_lower(_mapping_get(public_record, "classification"))
                or _safe_lower(_mapping_get(public_record, "class"))
            ) == "error"
            or _safe_nonnegative_int(_mapping_get(public_record, "exit_code"), 0) == PLR2004N4
        ):
            scan_had_error = True
    runtime_set = _owned_bound_method(runtime, "set")
    if runtime_set is not None:
        runtime_set("SCAN_HAD_ERROR", scan_had_error is True)
    elapsed_sec = time.time() - _safe_float(_owned_attr(runtime, "scan_started_at", time.time()), time.time())

    if parent_cli:
        if ledger is None:
            raise RuntimeError("scan_result_ledger_accumulator_missing")
        plan = _owned_attr(args, "scan_log_output_plan", None)
        if plan is None:
            raise RuntimeError("scan_log_output_plan_missing")
        ledger_summary = ledger.publish(
            output_path,
            log_info=emit_parent_scan_log_line,
            persistence_status=persistence_status,
            published_path=plan.report_path("scan_results.json").as_posix(),
        )
        vt_result = vt_report.run_virustotal_reporting(
            publication_results,
            _owned_attr(runtime, "virustotal_runtime", None),
        )
        snapshot = build_scan_publication_snapshot(
            output_plan=plan,
            local_results=publication_results,
            ledger_summary=ledger_summary,
            virustotal_result=vt_result,
            persistence_status=persistence_status,
            max_score=max_score,
            elapsed_sec=elapsed_sec,
            scan_had_error=scan_had_error,
        )
        publication_result = publish_scan_report_set(snapshot)
        if runtime_set is not None:
            runtime_set("SCAN_PUBLICATION_SNAPSHOT_DIGEST", snapshot.semantic_digest)
            runtime_set("SCAN_PUBLICATION_LOCAL_RESULTS_DIGEST", snapshot.local_results_digest)
            runtime_set("SCAN_PUBLICATION_LOCAL_RESULT_COUNT", snapshot.local_result_count)
            runtime_set("SCAN_PUBLICATION_RESULT", publication_result.to_record())
        compact_report.print_compact_scan_report(
            publication_results,
            target=_owned_attr(args, "dir", ""),
            output_path=plan.report_path("scan_results.json").as_posix(),
            yara_active=_safe_bool(yara_ok),
            yara_rule_count=runtime.get("YARA_RULES_LOADED_COUNT"),
            elapsed_sec=elapsed_sec,
        )
    return max_score, elapsed_sec


def prepare_scan(runtime: object, args: object) -> None:
    """Prepare scan output/runtime knobs through the lifecycle-owned runtime."""
    if _safe_bool(_owned_attr(runtime, "parent_cli", default=False)):
        clear_scan_results_before_scan(
            _safe_text(_owned_attr(args, "output", "scan_results.json"), "scan_results.json"),
            preserve=_safe_bool(_owned_attr(args, "preserve_scan_results", default=False)),
        )

    runtime.scan_started_at = time.time()
    workers = max(1, min(16, _safe_nonnegative_int(_owned_attr(args, "stage_parallel_workers", 6), 6)))
    stage_mode = _safe_lower(_owned_attr(args, "stage_parallel_mode", "thread"), "thread") or "thread"
    runtime.environment.publish({
        "UMIGE_STAGE_PARALLEL": "0" if _safe_bool(_owned_attr(args, "no_stage_parallel", default=False)) else "1",
        "UMIGE_STAGE_PARALLEL_WORKERS": int.__str__(workers),
        "UMIGE_STAGE_PARALLEL_MODE": stage_mode,
    })

    cfg = _owned_attr(runtime, "config", None)
    if cfg is not None:
        runtime.environment.publish_defaults(cfg.env_mapping())
        empty_plan = dict(publish_workload_queue_plan(workload_plan_summary(build_workload_classification_plan(()))))
        runtime.owner.update({
            "UMIGE_SHARED_STAGE_LIMITS": cfg.stage_limits.as_dict(),
            "UMIGE_ARCHIVE_QUOTA_POLICY": cfg.archive_limits,
            "UMIGE_FAULT_DOMAIN_POLICY": "contain",
            "UMIGE_WORKLOAD_QUEUE_PLAN": empty_plan,
            "UMIGE_PERSISTENCE_CONFIG": cfg.persistence,
            "UMIGE_RESOURCE_ECONOMICS": _owned_attr(cfg, "economics", None),
            "UMIGE_RUNTIME_TELEMETRY": _owned_attr(runtime, "telemetry", None),
        }, domain="runtime_configuration")


def run_scan(args: object, compiled_rules: object, *, scheduler_pipeline: object = None) -> Dict[str, object]:
    """Invoke the canonical scheduler pipeline directly through an explicit callable seam."""
    run_pipeline = scheduler_pipeline or scheduler_runner.run_pipeline_safe
    no_yara = _safe_bool(_owned_attr(args, "no_yara", default=False))
    return run_pipeline(
        _safe_text(_owned_attr(args, "dir", "")),
        compiled_rules=compiled_rules,
        max_workers=_safe_nonnegative_int(_owned_attr(args, "workers", 1), 1),
        strict=_safe_bool(_owned_attr(args, "strict", default=False)),
        per_file_timeout_sec=_safe_float(_owned_attr(args, "per_file_timeout", 0.0), 0.0),
        progress_every=_safe_nonnegative_int(_owned_attr(args, "progress_every", 1), 1),
        throttle_sec=_safe_float(_owned_attr(args, "throttle", 0.0), 0.0),
        max_files=_owned_attr(args, "max_files", None),
        freeze_existing_baselines=not _safe_bool(_owned_attr(args, "no_freeze_baseline", default=False)),
        defer_profile_flush=not _safe_bool(_owned_attr(args, "flush_during_scan", default=False)),
        partial_output_path=_safe_text(_owned_attr(args, "output", "")),
        partial_output_every=_safe_nonnegative_int(_owned_attr(args, "partial_output_every", 0), 0),
        slow_file_warn_sec=_safe_float(_owned_attr(args, "slow_file_warn", 0.0), 0.0),
        scheduler=_safe_text(_owned_attr(args, "scheduler", "serial"), "serial"),
        file_list_path=_safe_text(_owned_attr(args, "file_list", "")) or None,
        work_queue_dir=_safe_text(_owned_attr(args, "work_queue_dir", "")) or None,
        worker_output_path=_safe_text(_owned_attr(args, "worker_output", "")) or None,
        scan_session_manifest_path=_safe_text(_owned_attr(args, "scan_session_manifest", "")) or None,
        yara_enabled=compiled_rules is not None and not no_yara,
        requested_engine=_safe_text(_owned_attr(args, "engine", "auto"), "auto") or "auto",
        **(
            {"result_view": scheduler_runner.RETAINED_PUBLICATION_RESULT_VIEW}
            if scheduler_pipeline is None
            else {}
        ),
    )


def prepare_yara(runtime: object, args: object) -> Tuple[object, bool]:
    """Load YARA through the canonical generated-control initialization boundary."""
    if type(runtime) is not RuntimeContext:
        raise TypeError("yara_prepare_runtime_owner_invalid")
    return initialize_yara_from_args(runtime, args)


def run_scan_lifecycle(argv: Optional[list] = None, args: object = None) -> int:
    """Run the single canonical scan lifecycle after scan mode is selected."""
    runtime = RuntimeContext()

    try:
        try:
            runtime.initialize(initialize_runtime)
            runtime.owner.refresh(run_top_level_init())
            if args is None:
                args = parse_and_configure(runtime, argv)
            else:
                args = configure_parsed(runtime, args)
            acquire_parent_scan_guard(args)
            runtime.virustotal_runtime = initialize_virustotal_runtime(resource_root_snapshot())
            mitre_snapshot = initialize_mitre_from_args(args)
            if _safe_bool(_owned_attr(args, "mitre_status", default=False)):
                logging.info("MITRE ATT&CK status: %s", dict(mitre_snapshot.status))
            compiled_rules, yara_ok = prepare_yara(runtime, args)
            runtime.config = RuntimeConfig.from_args(args)
            runtime.environment.publish_defaults(runtime.config.env_mapping())
            runtime.owner.install_config(runtime.config)
            runtime.owner.install_telemetry(runtime.telemetry)
            prepare_scan(runtime, args)
            results = run_scan(args, compiled_rules)
            persistence_status = flush_persistent_state(runtime, args)
            max_score, _elapsed_sec = report_results(runtime, args, results, yara_ok=yara_ok, persistence_status=persistence_status)
            return int(exit_code_for_results(runtime, max_score))
        except ProfileSchemaInvariantError as exc:
            print(str.__add__("[ERROR] Profile schema corruption stopped the scan: ", no_hook_type_name(exc)), file=sys.stderr)
            return 4
    finally:
        runtime.virustotal_runtime = None
        release_yara_runtime()
        release_mitre_runtime()
        release_parent_scan_guard()


__all__ = ("attach_direct_audit_fields", "configure_parsed", "parse_and_configure", "prepare_scan", "prepare_yara", "report_results", "run_scan", "run_scan_lifecycle")
