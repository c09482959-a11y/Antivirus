"""Scheduler queue JSON read publication."""
from __future__ import annotations

import json
from pathlib import Path
import time


from Virus_Scan.contracts.env_config import int_env
from Virus_Scan.scheduler.runtime.queue_filesystem_common import queue_filesystem_path_text
from Virus_Scan.scheduler.runtime.queue_json_common import QUEUE_JSON_EXCEPTIONS, record_queue_json_degraded
from Virus_Scan.scheduler.runtime.queue_json_publication_boundary import (
    queue_json_path_name,
    queue_json_read_failure,
)
from Virus_Scan.scheduler.runtime.queue_json_schema import validate_persistent_record_semantics


def read_json_file(path: object, default: object = None) -> object:
    filesystem_path, path_reason = queue_filesystem_path_text(path)
    if path_reason:
        record_queue_json_degraded("json_read_path_rejected", ValueError(path_reason), domain="persistence")
        return default if default is not None else queue_json_read_failure(path_reason)
    path_name = queue_json_path_name(filesystem_path)
    try:
        path_text = Path(filesystem_path).as_posix().lower()
    except QUEUE_JSON_EXCEPTIONS:
        path_text = ""
    try:
        retries = int_env("UMIGE_QUEUE_JSON_READ_RETRIES", 6, 1, None)
    except QUEUE_JSON_EXCEPTIONS:
        retries = 6
    last_exc: BaseException | None = None
    last_stage = "read"
    for index in range(retries):
        try:
            with Path(filesystem_path).open("r", encoding="utf-8", errors="strict") as handle:
                data = json.load(handle)
            try:
                validate_persistent_record_semantics(data, context="read_json_file:" + path_name)
            except QUEUE_JSON_EXCEPTIONS as semantic_exc:
                record_queue_json_degraded("json_read_semantic_validation_failed", semantic_exc, domain="persistence")
                return default if default is not None else {}
        except (UnicodeDecodeError, PermissionError, OSError, json.JSONDecodeError, ValueError) as exc:
            last_exc = exc
            last_stage = "decode" if isinstance(exc, (UnicodeDecodeError, json.JSONDecodeError, ValueError)) else "io"
            queueish = "umige_process_queue" in path_text or "/queue/" in path_text or path_text.endswith(".tmp")
            if queueish and index < retries - 1:
                time.sleep(min(0.25, 0.025 * (index + 1)))
                continue
            break
        except QUEUE_JSON_EXCEPTIONS as exc:
            last_exc = exc
            last_stage = "unexpected"
            break
        else:
            return data
    if last_exc is not None:
        record_queue_json_degraded("json_read_" + last_stage + "_failed", last_exc, domain="persistence")
    return default if default is not None else {}


__all__ = ("read_json_file",)
