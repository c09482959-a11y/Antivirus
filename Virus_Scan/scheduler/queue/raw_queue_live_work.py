from __future__ import annotations
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias, TYPE_CHECKING
from Virus_Scan.contracts.env_config import str_env
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items_status, no_hook_sequence_items, no_hook_text
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float, scheduler_int, scheduler_path_text
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.runtime.queue_filesystem import safe_queue_listdir
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.scheduler.queue.raw_queue_path_support import raw_queue_path_text_or_error

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping
RawQueueDirs: TypeAlias = tuple[object, object, object, object, object, object]
RawAccumulatorData: TypeAlias = dict[str, object]
LiveAccumulatorCounts: TypeAlias = dict[str, int]
@dataclass(frozen=True)
class RawQueueLiveWorkDependencies:
    global_raw_dirs: Callable[[object], RawQueueDirs]
    read_json: Callable[..., object]
    raw_accumulator_store: object
    ordered_unique_tags: Callable[[Iterable[object]], list[object]]
    write_json_durable: Callable[..., bool]
    record_suppressed: Callable[[str, BaseException], None]
    current_time: Callable[[], float] = time.time
    path_mtime: Callable[[str], float] = os.path.getmtime
    environment_value: Callable[[str, str | None], str | None] = lambda name, default=None: str_env(name, "" if default is None else default)
    safe_listdir: Callable[[object], object] = safe_queue_listdir
@dataclass(frozen=True)
class RawQueueNameDecision:
    text: str
    accepted: bool
    reason: str
@dataclass(frozen=True)
class RawAccumulatorMappingDecision:
    mapping: RawAccumulatorData
    accepted: bool
    reason: str
def _raw_queue_name_decision(value: object) -> RawQueueNameDecision:
    text, reason = no_hook_text(
        value,
        missing_reason="raw_queue_live_work_name_missing",
        unsupported_reason="raw_queue_live_work_name_rejected",
    )
    if reason == "" and text != "":
        return RawQueueNameDecision(text=text, accepted=True, reason="")
    path_text, path_reason = scheduler_path_text(value)
    if path_reason == "" and path_text != "":
        return RawQueueNameDecision(text=Path(path_text).name, accepted=True, reason="")
    return RawQueueNameDecision(text="", accepted=False, reason=reason or path_reason or "raw_queue_live_work_name_rejected")
def _queue_json_names(directory: object, deps: RawQueueLiveWorkDependencies) -> tuple[str, ...]:
    names: list[str] = []
    for candidate in queue_listdir_names(deps.safe_listdir(directory), context=directory):
        decision = _raw_queue_name_decision(candidate)
        if decision.accepted and decision.text.endswith(".json"):
            names.append(decision.text)
    return tuple(names)
def _owned_mapping_decision(value: object) -> RawAccumulatorMappingDecision:
    items, reason = no_hook_mapping_items_status(value, allow_dict_subclass=True)
    if items is None:
        return RawAccumulatorMappingDecision(mapping={}, accepted=False, reason=reason or "raw_live_mapping_rejected")
    return RawAccumulatorMappingDecision(
        mapping=scheduler_str_key_mapping_from_items(items),
        accepted=True,
        reason="",
    )
def _safe_nonnegative_int(value: object) -> int:
    if type(value) is bool:
        return 1 if value else 0
    parsed, _reason = scheduler_int(value, default=0, minimum=0, reason="raw_live_accumulator_count_rejected")
    return parsed
def _safe_age_seconds(value: object) -> float:
    parsed, reason = scheduler_float(value, default=0.0, minimum=0.0, reason="raw_live_accumulator_age_rejected")
    return parsed if reason == "" else 0.0

def _stale_error_text(age: object, missing_i: int | None = None) -> str:
    age_text = format(_safe_age_seconds(age), ".1f")
    if type(missing_i) is int:
        return "raw accumulator stale for " + age_text + "s; missing=" + int.__str__(missing_i)
    return "raw accumulator stale for " + age_text + "s"
def raw_queue_has_live_work(queue_dir: object, deps: RawQueueLiveWorkDependencies) -> bool:
    live = False
    try:
        pending, active, _done, _failed, accum, _locks = deps.global_raw_dirs(queue_dir)
        for directory in (pending, active):
            try:
                if _queue_json_names(directory, deps):
                    return True
            except FileNotFoundError:
                continue
        accum_missing = False
        try:
            names = _queue_json_names(accum, deps)
        except FileNotFoundError:
            accum_missing = True
            names = ()
        if accum_missing:
            return live
        accum_path = raw_queue_path_text_or_error(accum, reason="raw_accumulator_dir_rejected")
        for name in names:
            accumulator_path = Path(accum_path) / name
            raw_data = deps.read_json(accumulator_path, default={})
            data_decision = _owned_mapping_decision(raw_data)
            if not data_decision.accepted:
                continue
            data = data_decision.mapping
            counts = normalize_live_accumulator_counts(data)
            if counts["expected"] <= 0:
                continue
            if counts["completed"] >= counts["expected"]:
                continue
            age = 0.0
            try:
                now = _safe_age_seconds(deps.current_time())
                path_text = raw_queue_path_text_or_error(accumulator_path, reason="raw_accumulator_path_rejected")
                age = max(0.0, now - _safe_age_seconds(deps.path_mtime(path_text)))
            except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
                age = 0.0
            try:
                raw_stall_value = deps.environment_value(
                    "UMIGE_RAW_ACCUMULATOR_STALL_SEC",
                    deps.environment_value("UMIGE_QUEUE_PROGRESS_STALL_SEC", "300"),
                )
                parsed_stall, stall_reason = scheduler_float(
                    raw_stall_value,
                    default=300.0,
                    minimum=0.0,
                    reason="raw_live_accumulator_stall_rejected",
                )
                raw_stall = parsed_stall if stall_reason == "" else 300.0
            except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
                raw_stall = 300.0
            if age <= raw_stall:
                return True
            try:
                mark_stalled_accumulator(accumulator_path, data, age, deps)
            except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
                deps.record_suppressed("raw_accumulator_stall_mark_failed", exc)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS as exc:
        deps.record_suppressed("raw_queue_live_work_list_failed", exc)
        live = True
    return live
def normalize_live_accumulator_counts(data: object) -> LiveAccumulatorCounts:
    source = _owned_mapping_decision(data).mapping
    expected_i = _safe_nonnegative_int(dict.get(source, "expected", 0))
    completed_i = _safe_nonnegative_int(dict.get(source, "completed", 0))
    failed_i = _safe_nonnegative_int(dict.get(source, "failed", 0))
    return {"expected": expected_i, "completed": completed_i, "failed": failed_i}
def mark_stalled_accumulator(accumulator_path: Path, data: Mapping[str, object] | object, age: object, deps: RawQueueLiveWorkDependencies) -> None:
    data = dict(_owned_mapping_decision(data).mapping)
    counts = normalize_live_accumulator_counts(data)
    expected_i = counts["expected"]
    completed_i = counts["completed"]
    missing_i = max(0, expected_i - completed_i)
    data["closed"] = True
    data["degraded"] = True
    data["completed"] = expected_i
    data["failed"] = counts["failed"] + missing_i
    tags: list[str] = []
    for tag in no_hook_sequence_items(dict.get(data, "tags")):
        text, reason = no_hook_text(
            tag,
            missing_reason="raw_live_tag_missing",
            unsupported_reason="raw_live_tag_rejected",
        )
        if reason == "" and text != "":
            tags.append(text)
    tags.extend(["raw_accumulator_stalled", "scanner_failure", "scanner_degraded", "scan_incomplete"])
    try:
        data["tags"] = deps.ordered_unique_tags(tags)
    except RAW_QUEUE_RECOVERABLE_EXCEPTIONS:
        data["tags"] = list(dict.fromkeys(tags))
    failures = list(no_hook_sequence_items(dict.get(data, "raw_failures")))[-64:]
    failures.append({"collector": "raw_accumulator", "seq": None, "attempt": None, "error": _stale_error_text(age, missing_i)})
    data["raw_failures"] = failures[-64:]
    data["failure_info"] = {"stage": "raw_accumulator_stalled", "error": _stale_error_text(age), "missing_chunks": missing_i}
    data["expected"] = expected_i
    data["completed"] = expected_i
    accumulator_text = raw_queue_path_text_or_error(accumulator_path, reason="raw_accumulator_stall_path_rejected")
    tmp = accumulator_text + ".stalled.tmp"
    if not deps.write_json_durable(tmp, accumulator_path, data, log_context="raw_accumulator_stall_mark"):
        raise RuntimeError("raw accumulator stall mark failed: " + accumulator_text)
