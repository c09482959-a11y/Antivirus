"""No-hook result-merge materialization helpers."""
from __future__ import annotations

from pathlib import Path
from types import BuiltinFunctionType

from Virus_Scan.contracts.runtime_function_identity import RUNTIME_NATIVE_FUNCTION_TYPE
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.scheduler.api.contracts import (
    QueueResultReadError,
    QueueResultSchemaError,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_text,
)
from Virus_Scan.scheduler.queue.field_name_support import queue_field_name
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import (
    queue_listdir_names,
)


result_field_name = queue_field_name
_RESULT_RECORD_MISSING_EXACT_RESULT_OBJECT = "result record missing exact result object"
_RESULT_RECORD_LACKS_RESULT_EVIDENCE = "result record lacks result evidence"


def result_path(value: object, *, field_name: str) -> Path:
    """Materialize a queue-result filesystem path without caller hooks."""
    safe_field_name = result_field_name(field_name)
    path_value, reason = scheduler_filesystem_path(value)
    if reason or (type(path_value) is str and path_value == ""):
        raise QueueResultReadError(
            safe_field_name + ":" + (reason or "scheduler_path_missing")
        )
    return Path(path_value)


def result_text(value: object, *, field_name: str) -> str:
    """Materialize a non-empty queue-result text field without caller hooks."""
    safe_field_name = result_field_name(field_name)
    text, reason = scheduler_text(
        value,
        unsupported_reason="queue_result_" + safe_field_name + "_rejected",
    )
    if reason or text == "":
        raise QueueResultSchemaError(
            reason or "queue_result_" + safe_field_name + "_missing"
        )
    return text


_LISTDIR_CALLABLE_TYPES = frozenset((BuiltinFunctionType, RUNTIME_NATIVE_FUNCTION_TYPE))


def result_listdir_sort_key(value: object) -> str:
    """Sort queue-result filenames while rejecting non-text names elsewhere."""
    return str.__str__(value) if type(value) is str else ""


def result_listdir_names(safe_listdir: object, directory: object, *, field_name: str) -> tuple[str, ...]:
    """List queue-result entries using only queue-owned exact callables."""
    safe_field_name = result_field_name(field_name)
    if type(safe_listdir) not in _LISTDIR_CALLABLE_TYPES:
        raise QueueResultReadError(
            "queue_result_"
            + safe_field_name
            + "_listdir_callable_rejected:"
            + no_hook_type_name(safe_listdir)
        )
    return tuple(
        result_text(name, field_name=safe_field_name + "_entry")
        for name in queue_listdir_names(safe_listdir(directory), context=directory)
    )


def queue_file_result_payload(record: object) -> tuple[object, dict[str, object]]:
    """Extract one exact queue-result payload or fail closed."""
    record_items = no_hook_mapping_items(record)
    if record_items is None:
        raise QueueResultSchemaError(
            "result record is not an exact owned mapping: " + no_hook_type_name(record)
        )
    record_snapshot = dict(record_items)
    file_key = dict.get(record_snapshot, "file")
    if "result" in record_snapshot:
        result_items = no_hook_mapping_items(dict.get(record_snapshot, "result"))
        if result_items is None:
            raise QueueResultSchemaError(_RESULT_RECORD_MISSING_EXACT_RESULT_OBJECT)
        payload = dict(result_items)
    elif any(key in record_snapshot for key in ("tags", "error", "ok")):
        payload = record_snapshot
    else:
        raise QueueResultSchemaError(_RESULT_RECORD_LACKS_RESULT_EVIDENCE)
    return file_key, payload


__all__ = (
    "queue_file_result_payload",
    "result_field_name",
    "result_listdir_names",
    "result_listdir_sort_key",
    "result_path",
    "result_text",
)
