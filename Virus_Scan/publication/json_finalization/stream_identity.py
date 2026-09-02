"""Stream-key identity projection for final and partial JSON records."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items


def record_with_stream_identity(value: object, key_text: str) -> object:
    if key_text == "":
        return value
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    if items is None:
        return value
    snapshot = dict(items)
    has_path = (
        "input_file_path" in snapshot
        or "path" in snapshot
        or "file" in snapshot
        or "node" in snapshot
    )
    if not has_path:
        snapshot["input_file_path"] = key_text
        snapshot["path"] = key_text
        snapshot["file"] = key_text
        snapshot["node"] = key_text
    if "filename" not in snapshot:
        snapshot["filename"] = Path(key_text).name
    return snapshot


__all__ = ("record_with_stream_identity",)
