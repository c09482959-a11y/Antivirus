from __future__ import annotations

import ast
from pathlib import Path

PROFILE_ROOT = Path(__file__).resolve().parents[1] / "models" / "profiles"

PUBLIC_PROFILE_OWNER_NAMES = (
    "profile_safe_text",
    "profile_public_tags",
    "profile_public_yara_hits",
    "profile_public_ordered_events",
    "profile_finite_float",
    "profile_int",
    "profile_model_failure_record",
    "profile_model_unavailable",
    "profile_tag_behavior_bucket",
    "ensure_extension_model_fields",
    "profile_nonnegative_int",
    "extension_profile_unavailable",
    "adaptive_profile_unavailable",
    "merge_profile_subsignal_unavailable",
    "profile_timeline_unavailable",
    "handle_invalid_engine_profile",
    "profile_update_marker",
    "profile_ext_lock",
    "resolved_profiles_dir",
    "profile_persistence_state_owner",
)

FORBIDDEN_IMPORTED_PRIVATE_PROFILE_HELPERS = (
    "_profile_safe_text",
    "_profile_public_tags",
    "_profile_public_yara_hits",
    "_profile_public_ordered_events",
    "_profile_finite_float",
    "_profile_int",
    "_profile_model_failure_record",
    "_profile_model_unavailable",
    "_profile_tag_behavior_bucket",
    "_ensure_extension_model_fields",
    "_profile_nonnegative_int",
    "_extension_profile_unavailable",
    "_adaptive_profile_unavailable",
    "_merge_profile_subsignal_unavailable",
    "_profile_timeline_unavailable",
    "_handle_invalid_engine_profile",
    "_profile_update_marker",
    "_profile_ext_lock",
    "_resolved_profiles_dir",
    "_PROFILE_PERSISTENCE_STATE",
)


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_stage1465_profile_modules_do_not_import_private_profile_owner_helpers() -> None:
    offenders = []
    for path in PROFILE_ROOT.glob("*.py"):
        tree = _tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom):
                continue
            if not (node.module or "").startswith("Virus_Scan.models.profiles"):
                continue
            for alias in node.names:
                if alias.name in FORBIDDEN_IMPORTED_PRIVATE_PROFILE_HELPERS:
                    offenders.append((path.name, node.lineno, alias.name))
    assert offenders == []


def test_stage1465_profile_public_owner_names_exist_without_private_reachthrough() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in PROFILE_ROOT.glob("*.py"))
    for name in PUBLIC_PROFILE_OWNER_NAMES:
        assert name in source
    for private_name in FORBIDDEN_IMPORTED_PRIVATE_PROFILE_HELPERS:
        assert f"import {private_name}" not in source
        assert f" {private_name}," not in source
