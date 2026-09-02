"""Bounded routing stage handlers used by the extension scan router."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.result_record import scanner_degraded_tags
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.routing.extension_outcome import RouteScanOutcome
from Virus_Scan.detection.api.routing_contracts import (
    merge_stage_collector_results,
    merge_tag_evidence_inputs,
    validate_tag_evidence_input_for_path,
)
from Virus_Scan.detection.api.routing_contracts import micro_stage_collect as _micro_stage_collect
from Virus_Scan.detection.api.routing_contracts import scan_binary
from Virus_Scan.routing.asset_triage import (
    scan_media_asset_file,
    scan_passive_font_asset_file,
    scan_unity_asset_file,
)
from Virus_Scan.routing.extension_intrastage import run_raw_task_queue
from Virus_Scan.routing.intrastage_execution_plan import stage_parallel_workers
from Virus_Scan.routing.passive_assets import _is_font_asset_extension, _is_media_asset_extension
from Virus_Scan.routing.scanner_execution_plan import (
    ScannerExecutionPlan,
    scanner_result_status,
)
from Virus_Scan.runtime.api import (
    deep_scan_auto_enabled,
    deep_scan_thorough_enabled,
    has_any_tag,
    report_scan_stage_progress,
    scan_strings,
)
from Virus_Scan.scanners.api.binary_contracts import scan_binary_embedded_pickle_payloads
from Virus_Scan.scanners.api.image_contracts import scan_image_file
from Virus_Scan.utils.stages import UNITY_CONTAINER_ASSET_EXTENSIONS
from Virus_Scan.utils.text_validation import text_boundary_value



def _require_scanner_execution_plan(value: object) -> ScannerExecutionPlan:
    if type(value) is not ScannerExecutionPlan:
        raise TypeError("scanner_execution_plan_required")
    return value


def _task_outcome_plan(
    plan: ScannerExecutionPlan,
    stage_results: object,
    task_scanners: dict[str, str],
) -> ScannerExecutionPlan:
    seen: set[str] = set()
    if type(stage_results) in (tuple, list):
        for result in stage_results:
            if type(result) is not dict:
                continue
            name = dict.get(result, "name")
            if type(name) is not str or name not in task_scanners:
                continue
            scanner_id = task_scanners[name]
            seen.add(scanner_id)
            raw_error = dict.get(result, "error")
            status = scanner_result_status(dict.get(result, "tags"), raw_error)
            reason = "" if raw_error is None else "stage_task_error:" + str.__str__(raw_error) if type(raw_error) is str else "stage_task_error"
            plan = plan.with_outcome(scanner_id, status, reason)
    for scanner_id in task_scanners.values():
        if plan.allows(scanner_id) and scanner_id not in seen:
            plan = plan.with_outcome(scanner_id, "failed", "scanner_task_result_missing")
    return plan

def _extension_text(ext: object) -> object:
    text = text_boundary_value(ext, unsupported=None)
    if type(text) is not str:
        return ""
    return str.__str__(text).strip().lower()


def is_unity_container_asset_extension(ext: object) -> object:
    return _extension_text(ext) in UNITY_CONTAINER_ASSET_EXTENSIONS


def _handler_tag_items(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if type(value) is str:
        return (str.__str__(value),)
    if type(value) in (tuple, list, set, frozenset):
        out: list[str] = []
        for item in value:
            text = _extension_text(item)
            if text:
                out.append(text)
        return tuple(out)
    return ()


def _stage_evidence(
    tags: object,
    *,
    path: object,
    source: str,
    strings_blob: object = "",
) -> TagEvidence:
    modality = "static_string" if "string" in source.lower() else "static_structure"
    observations = artifact_observations_for_path_tags(
        list(tags) if type(tags) in (tuple, list, set, frozenset) else tags,
        producer_id=source,
        stage_id="scanner_output",
        path=path,
        strings_blob=strings_blob,
        modality=modality,
    )
    return validate_tag_evidence_input_for_path(
        observations, path=path, strings_blob=strings_blob, source=source,
    )


def _merge_stage_evidence(
    bundles: object,
    *,
    path: object,
    source: str,
    strings_blob: object = "",
) -> TagEvidence:
    records = []
    if type(bundles) in (tuple, list):
        for bundle in bundles:
            if type(bundle) is TagEvidence:
                records.extend(bundle.records)
    del path, source, strings_blob
    return merge_tag_evidence_inputs(tuple(
        bundle for bundle in bundles if type(bundle) is TagEvidence
    ))


def _collector_stage_evidence(
    stage_results: object,
    *,
    path: object,
    strings_blob: object = "",
) -> TagEvidence:
    bundles = []
    if type(stage_results) in (tuple, list):
        for index, result in enumerate(stage_results):
            if type(result) is not dict:
                continue
            name = dict.get(result, "name")
            source = str.__str__(name) if type(name) is str and name else "stage_collector_" + int.__str__(index)
            raw_tags = dict.get(result, "tags")
            bundles.append(_stage_evidence(
                raw_tags, path=path, source=source, strings_blob=strings_blob,
            ))
    return _merge_stage_evidence(
        bundles, path=path, source="stage_collector_merge", strings_blob=strings_blob,
    )



def route_asset_stage(
    path: object,
    ext: object,
    identity: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: object,
) -> object:
    """Run asset-stage routing while preserving producer-owned evidence."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    plan = _require_scanner_execution_plan(scanner_execution_plan)
    report_scan_stage_progress("asset_route")
    bundles = []
    suspicious = False
    asset_score = 0.0
    strings_for_validation = ""
    asset_escalated = False
    unity_asset = False
    passive_fast_asset = False
    identity_actual_category = str(identity.get("actual_category", "")).lower()

    if plan.allows("media_asset"):
        report_scan_stage_progress("media_triage")
        outcome = scan_media_asset_file(path, identity=identity)
        stage_tags, stage_suspicious = outcome
        plan = plan.with_outcome("media_asset", scanner_result_status(stage_tags))
        stage_tag_items = _handler_tag_items(stage_tags)
        bundles.append(
            outcome.tag_evidence
            if type(outcome) is RouteScanOutcome and outcome.tag_evidence.records
            else _stage_evidence(stage_tag_items, path=path, source="media_asset")
        )
        suspicious = suspicious or bool(stage_suspicious)
        asset_escalated = asset_escalated or "asset_deep_scan_escalated" in set(stage_tag_items)
    elif plan.allows("unity_asset"):
        unity_asset = True
        stage_tags, asset_score = scan_unity_asset_file(path, identity=identity)
        plan = plan.with_outcome("unity_asset", scanner_result_status(stage_tags))
        stage_tag_items = _handler_tag_items(stage_tags)
        bundles.append(_stage_evidence(stage_tag_items, path=path, source="unity_asset"))
        asset_escalated = asset_escalated or "asset_deep_scan_escalated" in set(stage_tag_items)
    elif plan.allows("font_asset"):
        passive_fast_asset = True
        outcome = scan_passive_font_asset_file(path, identity=identity)
        stage_tags, stage_suspicious = outcome
        plan = plan.with_outcome("font_asset", scanner_result_status(stage_tags))
        stage_tag_items = _handler_tag_items(stage_tags)
        bundles.append(
            outcome.tag_evidence
            if type(outcome) is RouteScanOutcome and outcome.tag_evidence.records
            else _stage_evidence(stage_tag_items, path=path, source="font_asset")
        )
        suspicious = suspicious or bool(stage_suspicious)
        asset_escalated = asset_escalated or "asset_deep_scan_escalated" in set(stage_tag_items)

    selected_asset_scanner = (
        "media_asset" if plan.decision("media_asset").outcome_status != "pending"
        else "unity_asset" if plan.decision("unity_asset").outcome_status != "pending"
        else "font_asset" if plan.decision("font_asset").outcome_status != "pending"
        else ""
    )
    for scanner_id in ("media_asset", "unity_asset", "font_asset"):
        if scanner_id != selected_asset_scanner and plan.allows(scanner_id) and plan.decision(scanner_id).outcome_status == "pending":
            plan = plan.with_outcome(scanner_id, "not_applicable", "higher_priority_asset_family_selected")

    route_tags = []
    force_thorough_asset = bool(deep_scan_thorough_enabled() or (deep_scan_auto_enabled() and asset_escalated))
    if force_thorough_asset:
        route_tags.append("asset_thorough_enrichment" if deep_scan_thorough_enabled() else "asset_auto_thorough_enrichment")
    if asset_escalated or force_thorough_asset or (not _is_media_asset_extension(ext) and not unity_asset and not passive_fast_asset):
        raw = snapshot.read_prefix(1_000_000)
        strings_for_validation = raw.decode("latin1", errors="ignore")
        string_tags = scan_strings(strings_for_validation, path=path)
        plan = plan.with_outcome("asset_string", scanner_result_status(string_tags))
        bundles.append(_stage_evidence(
            string_tags, path=path, source="asset_string_scanner", strings_blob=strings_for_validation,
        ))
    if plan.allows("asset_string") and plan.decision("asset_string").outcome_status == "pending":
        plan = plan.with_outcome("asset_string", "not_applicable", "asset_predecessor_did_not_escalate")
    if route_tags:
        bundles.append(_stage_evidence(
            route_tags, path=path, source="asset_stage", strings_blob=strings_for_validation,
        ))
    evidence = _merge_stage_evidence(
        bundles, path=path, source="asset_stage_merge", strings_blob=strings_for_validation,
    )
    return evidence, suspicious, asset_score, asset_escalated, strings_for_validation, plan


def route_binary_stage(
    path: object,
    router_identity: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: object,
) -> object:
    """Run binary-stage collectors and preserve each collector producer."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    plan = _require_scanner_execution_plan(scanner_execution_plan)
    report_scan_stage_progress("binary_route")
    dotnet_meta = {"is_dotnet": False}
    binary_tasks = []
    task_scanners: dict[str, str] = {}
    if plan.allows("binary_static"):
        binary_tasks.append(("static_binary_raw", scan_binary, (path,), {"artifact_read_snapshot": snapshot, "finalize": False}))
        task_scanners["static_binary_raw"] = "binary_static"
    if plan.allows("binary_embedded_pickle"):
        binary_tasks.append(("binary_embedded_pickle_raw", scan_binary_embedded_pickle_payloads, (path,), {"artifact_read_snapshot": snapshot}))
        task_scanners["binary_embedded_pickle_raw"] = "binary_embedded_pickle"
    report_scan_stage_progress("binary_collectors_start")
    stage_results = run_raw_task_queue(binary_tasks, max_workers=stage_parallel_workers())
    plan = _task_outcome_plan(plan, stage_results, task_scanners)
    report_scan_stage_progress("binary_collectors_done")
    stage_tags, stage_meta, stage_suspicious, stage_errors = merge_stage_collector_results(stage_results).as_tuple()
    bundles = [_collector_stage_evidence(stage_results, path=path)]
    route_tags = []
    if stage_errors:
        route_tags.extend(scanner_degraded_tags(["binary_collector_error"]))
    dotnet_meta = (
        stage_meta.get("micro_dotnet_layered_raw")
        or stage_meta.get("micro_dotnet_metadata_raw")
        or stage_meta.get("dotnet_layered_raw")
        or stage_meta.get("dotnet_metadata_raw")
        or stage_meta.get("dotnet_layered")
        or stage_meta.get("dotnet_metadata")
        or dotnet_meta
    )
    magic_type = ""
    if type(router_identity) is dict:
        raw_magic = dict.get(router_identity, "magic_type")
        if type(raw_magic) is str:
            magic_type = str.__str__(raw_magic).strip().lower()
    if not dotnet_meta.get("is_dotnet") and magic_type == "pe_mz":
        route_tags.append("native_pe")
    if len(binary_tasks) > 1:
        route_tags.append("stage_parallel_binary_micro_collectors")
    missing = [tag for tag in stage_tags if tag not in bundles[0].tags]
    route_tags.extend(missing)
    if route_tags:
        bundles.append(_stage_evidence(route_tags, path=path, source="binary_stage"))
    return _merge_stage_evidence(bundles, path=path, source="binary_stage_merge"), bool(stage_suspicious), plan


def route_image_stage(
    path: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: object,
) -> object:
    """Run image-stage scanner and preserve scanner/string producers."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    plan = _require_scanner_execution_plan(scanner_execution_plan)
    report_scan_stage_progress("image_route")
    image_tags = []
    image_suspicious = False
    if plan.allows("image_static"):
        image_tags, image_suspicious = scan_image_file(path, artifact_read_snapshot=snapshot)
        plan = plan.with_outcome("image_static", scanner_result_status(image_tags))
    bundles = [_stage_evidence(image_tags, path=path, source="image_scanner")]
    route_tags = []
    strings_for_validation = ""
    image_escalated = bool(
        image_suspicious
        or has_any_tag(
            image_tags,
            "image_appended_payload",
            "image_payload_confirmed",
            "embedded_payload_after_eof",
            "embedded_command_or_url",
        )
    )
    force_thorough_image = bool(deep_scan_thorough_enabled() or (deep_scan_auto_enabled() and image_escalated))
    if force_thorough_image:
        route_tags.append("image_thorough_enrichment" if deep_scan_thorough_enabled() else "image_auto_thorough_enrichment")
    if image_escalated or force_thorough_image:
        raw = snapshot.read_prefix(512_000)
        strings_for_validation = raw.decode("latin1", errors="ignore")
        image_string_tags = scan_strings(strings_for_validation, path=path)
        plan = plan.with_outcome("image_string", scanner_result_status(image_string_tags))
        bundles.append(_stage_evidence(
            image_string_tags,
            path=path,
            source="image_string_scanner",
            strings_blob=strings_for_validation,
        ))
    if plan.allows("image_string") and plan.decision("image_string").outcome_status == "pending":
        plan = plan.with_outcome("image_string", "not_applicable", "image_predecessor_did_not_escalate")
    if route_tags:
        bundles.append(_stage_evidence(
            route_tags, path=path, source="image_stage", strings_blob=strings_for_validation,
        ))
    evidence = _merge_stage_evidence(
        bundles, path=path, source="image_stage_merge", strings_blob=strings_for_validation,
    )
    return evidence, bool(image_suspicious), strings_for_validation, plan


def route_runtime_stage(
    path: object,
    ext: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: object,
) -> object:
    """Run runtime-stage micro collectors with physical producer identity."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    plan = _require_scanner_execution_plan(scanner_execution_plan)
    report_scan_stage_progress("runtime_route")
    route_tags = []
    if ext in (".rpy", ".rpyc", ".rpyb"):
        route_tags.append("renpy_script")
    if ext in (".rvdata", ".rvdata2", ".rxdata"):
        route_tags.append("rpgm_resource")
    runtime_tasks = []
    task_scanners: dict[str, str] = {}
    strings_for_validation = ""
    if plan.allows("runtime_context") or plan.allows("runtime_decoded"):
        raw = snapshot.read_prefix(1_500_000)
        strings_for_validation = raw.decode("latin1", errors="ignore")
    if plan.allows("runtime_context"):
        runtime_tasks.append(("micro_runtime_context_raw", _micro_stage_collect, ("runtime_context", strings_for_validation), {"path": path}))
        task_scanners["micro_runtime_context_raw"] = "runtime_context"
    if plan.allows("runtime_decoded"):
        runtime_tasks.append(("micro_runtime_decoded_raw", _micro_stage_collect, ("runtime_decoded", strings_for_validation), {"path": path}))
        task_scanners["micro_runtime_decoded_raw"] = "runtime_decoded"
    report_scan_stage_progress("runtime_collectors_start")
    stage_results = run_raw_task_queue(runtime_tasks, max_workers=stage_parallel_workers())
    plan = _task_outcome_plan(plan, stage_results, task_scanners)
    report_scan_stage_progress("runtime_collectors_done")
    stage_tags, _stage_meta, stage_suspicious, stage_errors = merge_stage_collector_results(stage_results).as_tuple()
    bundles = [_collector_stage_evidence(
        stage_results, path=path, strings_blob=strings_for_validation,
    )]
    if stage_errors:
        route_tags.extend(scanner_degraded_tags(["runtime_collector_error"]))
    if len(runtime_tasks) > 1:
        route_tags.append("stage_parallel_runtime_micro_collectors")
    route_tags.extend(tag for tag in stage_tags if tag not in bundles[0].tags)
    if route_tags:
        bundles.append(_stage_evidence(
            route_tags, path=path, source="runtime_stage", strings_blob=strings_for_validation,
        ))
    evidence = _merge_stage_evidence(
        bundles, path=path, source="runtime_stage_merge", strings_blob=strings_for_validation,
    )
    return evidence, bool(stage_suspicious), strings_for_validation, plan


def route_other_stage(
    path: object,
    *,
    artifact_read_snapshot: object,
    scanner_execution_plan: object,
) -> object:
    """Run the bounded fallback route with explicit scanner ownership."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    plan = _require_scanner_execution_plan(scanner_execution_plan)
    report_scan_stage_progress("other_route")
    raw = snapshot.read_prefix(750_000)
    strings_blob = raw.decode("latin1", errors="ignore")
    route = _stage_evidence(["router_other_unknown"], path=path, source="other_stage")
    string_tags = scan_strings(strings_blob, path=path, finalize=False)
    plan = plan.with_outcome("other_string", scanner_result_status(string_tags))
    strings = _stage_evidence(
        string_tags,
        path=path,
        source="other_string_scanner",
        strings_blob=strings_blob,
    )
    return _merge_stage_evidence(
        [route, strings], path=path, source="other_stage_merge", strings_blob=strings_blob,
    ), plan


__all__ = (
    "is_unity_container_asset_extension",
    "route_asset_stage",
    "route_binary_stage",
    "route_image_stage",
    "route_other_stage",
    "route_runtime_stage",
)
