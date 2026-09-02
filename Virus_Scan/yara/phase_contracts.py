from __future__ import annotations
from pathlib import Path

from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.contracts.env_config import int_env_status
from Virus_Scan.yara.no_hook import yara_lower_text, yara_text

import os
import re
import zipfile
from Virus_Scan.contracts.yara_hits import (
    normalize_yara_hits as _neutral_normalize_yara_hits,
    normalize_yara_rule_name as _neutral_normalize_yara_rule_name,
    yara_expected_behavior as _neutral_yara_expected_behavior,
)


def normalize_yara_rule_name(rule: object) -> str:
    """Stable YARA rule key used in JSON, graph edges, and chain hints."""
    return _neutral_normalize_yara_rule_name(rule)


def normalize_yara_hits(yara_hits: object) -> list[str]:
    """Convert arbitrary YARA match objects to deterministic unique rule names."""
    return _neutral_normalize_yara_hits(yara_hits)


def yara_expected_behavior(rule_name: object) -> str:
    """Classify YARA rule names into audit/chain buckets without changing the rule itself."""
    return _neutral_yara_expected_behavior(rule_name)

def yara_rule_count_from_source(rule_path: object) -> int | None:
    """Best-effort count of .yar/.yara files/rules for CLI display."""
    count_result = None
    try:
        path_text = yara_text(rule_path)
        if not path_text or not os.path.exists(path_text):
            return count_result
        low = path_text.lower()
        if low.endswith(".zip"):
            count = 0
            with zipfile.ZipFile(path_text, "r") as z:
                for m in z.infolist():
                    ml = yara_lower_text(m.filename)
                    if (not m.is_dir()) and (ml.endswith((".yar", ".yara"))):
                        count += 1
            count_result = count
        if low.endswith((".yar", ".yara")):
            text = Path(path_text).read_text(encoding="utf-8", errors="ignore")
            count_result = len(re.findall(r"(?m)^\s*(?:private\s+|global\s+)*rule\s+[A-Za-z0-9_]+", text)) or 1
    except IO_CONFIGURATION_ERRORS:
        count_result = None
    return count_result


def yara_parallel_group_count(source_path: object = None, *, default_groups: int = 4, max_groups: int = 16) -> int:
    """Choose safe deterministic YARA rule-group count using only source shape/env."""
    group_count = 1
    try:
        src = yara_text(source_path)
        if not src or not os.path.exists(src) or not zipfile.is_zipfile(src):
            return group_count
        total = 0
        with zipfile.ZipFile(src, "r") as z:
            for m in z.infolist():
                low = yara_lower_text(m.filename)
                if (not m.is_dir()) and low.endswith((".yar", ".yara")):
                    total += 1
        if total <= 1:
            return group_count
        requested_status, requested = int_env_status("UMIGE_YARA_PARALLEL_GROUPS", default_groups, 1, None)
        max_status, max_allowed = int_env_status("UMIGE_YARA_PARALLEL_GROUPS_MAX", max_groups, 1, None)
        if requested_status != "valid" or max_status != "valid":
            return group_count
        group_count = max(1, min(total, requested, max_allowed))
    except IO_CONFIGURATION_ERRORS:
        group_count = 1
    return group_count


__all__ = (
    "normalize_yara_rule_name",
    "normalize_yara_hits",
    "yara_expected_behavior",
    "yara_rule_count_from_source",
    "yara_parallel_group_count",
)
