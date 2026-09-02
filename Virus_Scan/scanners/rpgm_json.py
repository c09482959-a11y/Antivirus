"""Scanner-owned RPGM JSON helper boundaries."""
from __future__ import annotations

import json
from pathlib import Path

RPGM_JSON_EXCEPTIONS = (OSError, ValueError, TypeError, json.JSONDecodeError, UnicodeError)


def queue_read_json_file(path: object, default: object = None) -> object:
    """Read bounded RPGM/queue JSON metadata without importing private core helpers."""
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except RPGM_JSON_EXCEPTIONS:
        return default


__all__ = ("queue_read_json_file",)
