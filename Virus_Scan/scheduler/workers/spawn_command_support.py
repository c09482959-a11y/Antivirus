"""No-hook process-queue worker command construction support."""
from __future__ import annotations

import sys

from Virus_Scan.contracts.env_config import bool_env, int_env, str_env
from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text, scheduler_text
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_float, worker_int


def _spawn_rejection(field: str, value: object, reason: str) -> dict[str, object]:
    return {
        "scheduler_worker_spawn_input_rejected": True,
        "field": field,
        "reason": reason,
        "evidence": unsupported_scheduler_value_evidence(value, field_name=field),
    }


def _command_text(value: object, *, field: str, rejections: list[dict[str, object]]) -> str:
    text, reason = scheduler_path_text(value)
    if reason == "" and text != "":
        return text
    rejections.append(_spawn_rejection(field, value, reason or "scheduler_path_rejected"))
    return str.__add__("<rejected-", str.__add__(field, ">"))


def _append_explicit_rule_source(
    command: list[str], env_base: object, *, env_name: str, option: str,
    rejections: list[dict[str, object]],
) -> None:
    try:
        value = env_base[env_name]
    except KeyError:
        return
    if type(value) is str and value == "":
        return
    command.extend([
        option,
        _command_text(value, field=env_name, rejections=rejections),
    ])


def _build_process_queue_worker_command_with_evidence(request: object) -> tuple[tuple[str, ...], tuple[dict[str, object], ...]]:
    """Build queue-child command without invoking caller-owned hooks."""
    rejections: list[dict[str, object]] = []
    python_executable = _command_text(request.python_executable, field="python_executable", rejections=rejections)
    script_path = _command_text(request.script_path, field="script_path", rejections=rejections)
    root = _command_text(request.root, field="root", rejections=rejections)
    output = _command_text(request.output, field="output", rejections=rejections)
    queue_dir = _command_text(request.queue_dir, field="queue_dir", rejections=rejections)
    session_manifest = _command_text(
        request.scan_session_manifest_path,
        field="scan_session_manifest_path",
        rejections=rejections,
    )
    try:
        deep_scan_mode_value = request.env_base["UMIGE_DEEP_SCAN_MODE"]
    except KeyError:
        deep_scan_mode = "auto"
    else:
        text_rejected_reason = "UMIGE_DEEP_SCAN_MODE_text_rejected"
        deep_scan_mode, reason = scheduler_text(
            deep_scan_mode_value,
            replacement_text="auto",
            unsupported_reason=text_rejected_reason,
        )
        if reason or deep_scan_mode == "":
            if deep_scan_mode_value is not None:
                rejections.append(_spawn_rejection("UMIGE_DEEP_SCAN_MODE", deep_scan_mode_value, reason or text_rejected_reason))
            deep_scan_mode = "auto"
    per_file_timeout, per_file_timeout_reason = worker_int(
        request.per_file_timeout_sec,
        replacement=0,
        minimum=0,
        maximum=None,
        reason="per_file_timeout_sec_integer_rejected",
    )
    if per_file_timeout_reason:
        rejections.append(_spawn_rejection("per_file_timeout_sec", request.per_file_timeout_sec, per_file_timeout_reason))
    progress_every, progress_every_reason = worker_int(
        request.progress_every,
        replacement=10,
        minimum=1,
        maximum=None,
        reason="progress_every_integer_rejected",
    )
    if progress_every_reason:
        rejections.append(_spawn_rejection("progress_every", request.progress_every, progress_every_reason))
    partial_output_every, partial_output_every_reason = worker_int(
        request.partial_output_every,
        replacement=0,
        minimum=0,
        maximum=None,
        reason="partial_output_every_integer_rejected",
    )
    if partial_output_every_reason:
        rejections.append(_spawn_rejection("partial_output_every", request.partial_output_every, partial_output_every_reason))
    slow_file_warn, slow_file_warn_reason = worker_float(
        request.slow_file_warn_sec,
        replacement=0.0,
        minimum=0.0,
        reason="slow_file_warn_sec_numeric_rejected",
    )
    if slow_file_warn_reason:
        rejections.append(_spawn_rejection("slow_file_warn_sec", request.slow_file_warn_sec, slow_file_warn_reason))
    throttle, throttle_reason = worker_float(
        request.throttle_sec,
        replacement=0.0,
        minimum=0.0,
        reason="throttle_sec_numeric_rejected",
    )
    if throttle_reason:
        rejections.append(_spawn_rejection("throttle_sec", request.throttle_sec, throttle_reason))

    command = [python_executable] if sys.__dict__.get("frozen") is True else [python_executable, script_path]
    command.extend([
        "--dir", root,
        "--scheduler", "queue-child",
        "--workers", "1",
        "--work-queue-dir", queue_dir,
        "--worker-output", output,
        "--scan-session-manifest", session_manifest,
        "--deep-scan-mode", deep_scan_mode,
        "--per-file-timeout", int.__str__(per_file_timeout),
        "--progress-every", int.__str__(progress_every),
        "--partial-output-every", int.__str__(partial_output_every),
        "--slow-file-warn", float.__str__(slow_file_warn),
        "--stage-parallel-workers", int.__str__(max(1, min(16, int_env("UMIGE_STAGE_PARALLEL_WORKERS", 6, 1, None)))),
        "--stage-parallel-mode", str_env("UMIGE_STAGE_PARALLEL_MODE", "auto") or "auto",
    ])
    _append_explicit_rule_source(
        command, request.env_base, env_name="UMIGE_YARA_RULE_PATH",
        option="--yara", rejections=rejections,
    )
    _append_explicit_rule_source(
        command, request.env_base, env_name="UMIGE_YARALIGHT_RULE_PATH",
        option="--yaralight", rejections=rejections,
    )
    command.extend([
        "--yara-no-download",
        "--yaralight-no-download",
        "--mitre-no-download",
    ])
    if throttle > 0.0:
        command.extend(["--throttle", float.__str__(throttle)])
    if bool_env("UMIGE_NO_YARA", False):
        command.append("--no-yara")
    if bool_env("UMIGE_NO_YARALIGHT", False):
        command.append("--no-yaralight")
    if bool_env("UMIGE_NO_SCAN_CACHE", False):
        command.append("--no-scan-cache")
    if bool_env("UMIGE_NO_MITRE", False):
        command.append("--no-mitre")
    if request.strict is True:
        command.append("--strict")
    elif type(request.strict) is not bool:
        rejections.append(_spawn_rejection("strict", request.strict, "strict_bool_rejected"))
    return tuple(command), tuple(rejections)

