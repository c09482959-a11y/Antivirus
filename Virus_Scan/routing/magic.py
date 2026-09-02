from Virus_Scan.contracts.artifact_read_snapshot import read_artifact_prefix, require_artifact_read_snapshot
from Virus_Scan.routing.filetype_tables import EXPECTED_MAGIC_TYPES_BY_EXTENSION, ROUTABLE_EXTENSIONS_BY_CLAIM
from Virus_Scan.contracts.no_hook_materialization import exact_bool_or_none, no_hook_mapping_items
from Virus_Scan.routing.magic_extension_tags import (
    apply_extension_consistency_tags,
    apply_filetype_category_tags,
    apply_magic_mismatch_tags,
    exact_magic_boundary_text,
    rpgm_passive_recovery_record,
)
from Virus_Scan.routing.magic_header_rules import classify_magic_header
from Virus_Scan.utils.pathing import normalize_scan_path
from Virus_Scan.utils.stages import (
    FONT_ASSET_EXTENSIONS,
    UNITY_CONTAINER_ASSET_EXTENSIONS,
    get_scan_extension,
    normalize_stage,
    sanitize_tag_part as _umige_sanitize_tag_part,
)


def _identity_from_header(path: str, header: bytes) -> object:
    ext = get_scan_extension(path)
    ext_stage = normalize_stage(ext)
    tags = ["file_seen", str.__add__("ext_", _umige_sanitize_tag_part(ext or "no_ext")), str.__add__("ext_stage_", ext_stage)]
    if not header:
        tags += ["file_empty_or_unreadable", "magic_unknown"]
        return {"ext": ext, "ext_stage": ext_stage, "magic_stage": "unknown", "magic_type": "unknown", "confidence": 0.0, "tags": tags}

    identity = classify_magic_header(path, ext, ext_stage, header)
    tags += list(identity.tags)
    claimed_category = claimed_filetype_category(ext)
    actual_category = "unknown"
    mis_score, mis_sev = (0, "none")
    rpgm_recovery = rpgm_passive_recovery_record(ext, ext_stage, identity.magic_type, tags)
    rpgm_recovered = exact_bool_or_none(rpgm_recovery["recovered"]) is True
    for field, reason in no_hook_mapping_items(rpgm_recovery["unavailable_reasons"]) or ():
        field_text = exact_magic_boundary_text(field) or "unknown"
        reason_text = exact_magic_boundary_text(reason) or "unknown"
        tags.append("routing_magic_" + field_text + "_" + reason_text)
    apply_extension_consistency_tags(tags, ext_stage, identity.magic_stage, rpgm_recovered=rpgm_recovered)
    apply_magic_mismatch_tags(
        tags, ext, identity.magic_type,
        mismatch=expected_magic_mismatch(ext, identity.magic_type),
        rpgm_recovered=rpgm_recovered,
    )
    apply_filetype_category_tags(tags, claimed_category, actual_category, mis_score, mis_sev)
    tags += [str.__add__("magic_type_", _umige_sanitize_tag_part(identity.magic_type)), str.__add__("observed_stage_", identity.magic_stage)]
    return {
        "ext": ext, "ext_stage": ext_stage, "magic_stage": identity.magic_stage,
        "magic_type": identity.magic_type, "rpgm_recovered_type": identity.rpgm_recovered_type,
        "rpgm_recovered_header": identity.rpgm_recovered_header,
        "rpgm_recovery_key_found": identity.rpgm_recovery_key_found,
        "confidence": identity.confidence, "claimed_category": claimed_category,
        "actual_category": actual_category, "misclassification_score": mis_score,
        "misclassification_severity": mis_sev, "tags": tags,
    }


def sniff_file_identity(path: object) -> object:
    """Standalone file-identity entrypoint using its own bounded header read."""
    normalized = normalize_scan_path(path, require_exists=False)
    try:
        header = read_artifact_prefix(normalized, 8192)
    except (OSError, RuntimeError, TypeError, UnicodeError, ValueError):
        header = b""
    return _identity_from_header(normalized, header)


def sniff_file_identity_from_snapshot(path: object, artifact_read_snapshot: object) -> object:
    """Project file identity from the canonical scan-time artifact snapshot."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    normalized = snapshot.canonical_path or normalize_scan_path(path, require_exists=False)
    return _identity_from_header(normalized, snapshot.read_prefix(8192))


def expected_magic_mismatch(ext: object, magic_type: object) -> object:
    ext = exact_magic_boundary_text(ext).lower()
    magic_type = exact_magic_boundary_text(magic_type).lower() or "unknown"
    expected = EXPECTED_MAGIC_TYPES_BY_EXTENSION.get(ext)
    if not expected or magic_type in {"unknown", "unknown_binary_blob"}:
        return False
    if magic_type == "rpgm_mv_encrypted_asset":
        return False
    if ext in UNITY_CONTAINER_ASSET_EXTENSIONS and magic_type in {"unity_assetbundle", "unity_webdata", "unity_serialized_asset", "unity_resource"}:
        return False
    if ext in FONT_ASSET_EXTENSIONS and magic_type in {"ttf_font", "otf_font", "woff_font", "woff2_font"}:
        return False
    return magic_type not in expected


def claimed_filetype_category(ext: object) -> object:
    ext = exact_magic_boundary_text(ext).lower()
    for cat, exts in no_hook_mapping_items(ROUTABLE_EXTENSIONS_BY_CLAIM) or ():
        if ext in exts:
            return cat
    return "unknown"


class MagicRouter:
    sniff_file_identity = staticmethod(sniff_file_identity)
    expected_magic_mismatch = staticmethod(expected_magic_mismatch)
    claimed_filetype_category = staticmethod(claimed_filetype_category)


__all__ = ("MagicRouter", "claimed_filetype_category", "expected_magic_mismatch", "sniff_file_identity", "sniff_file_identity_from_snapshot")
