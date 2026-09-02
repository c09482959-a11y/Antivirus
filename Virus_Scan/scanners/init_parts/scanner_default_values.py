"""Scanner-owned default value construction for package initialization.

The initializer publishes runtime values through ``publish_init_values``.  This
module keeps those defaults in bounded construction helpers so the package
initializer stays a thin orchestration boundary and scanner defaults remain
owned by scanner code.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.runtime.api import configure_deep_scan_mode
from Virus_Scan.contracts.env_config import int_env, str_env
from Virus_Scan.scanners.filetype_policy import (
    ALL_ROUTABLE_EXTENSIONS as SCANNER_ALL_ROUTABLE_EXTENSIONS,
    EXPECTED_MAGIC_TYPES_BY_EXTENSION as SCANNER_EXPECTED_MAGIC_TYPES_BY_EXTENSION,
    MAGIC_TYPE_CATEGORY as SCANNER_MAGIC_TYPE_CATEGORY,
    ROUTABLE_EXTENSIONS_BY_CLAIM as SCANNER_ROUTABLE_EXTENSIONS_BY_CLAIM,
)
from Virus_Scan.scanners.image_tags import confirmed_image_payload_tags, stego_tag_rewrite_map


def _runtime_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("ENGINE_PROFILES", defaultdict(lambda: {"files": 0, "risk_sum": 0.0, "avg_risk": 0.0, "extensions": Counter(), "tags": Counter()})),
        ("FUSION_SCORE_HISTORY", []),
        ("METHOD_DB", defaultdict(dict)),
        ("METHOD_CALLS", defaultdict(set)),
        ("METHOD_GRAPH", defaultdict(lambda: {"edges": set(), "tags": set()})),
        ("STAGE_EVENTS", defaultdict(list)),
    )


def _image_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("IMAGE_EXT", {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif"}),
        ("IMAGE_STEGO_MAX_PIXELS", 16000000),
        ("IMAGE_STEGO_SAMPLE_PIXELS", 250000),
        ("IMAGE_STEGO_MAX_FILE_BYTES", 64 * 1024 * 1024),
        ("IMAGE_STEGO_RESIZE_SAMPLE_MAX_SIDE", 512),
        ("_CONFIRMED_IMAGE_PAYLOAD_TAGS", set(confirmed_image_payload_tags())),
        ("_WEAK_IMAGE_STEGO_TAG_REWRITE", stego_tag_rewrite_map()),
    )


def _release_hygiene_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("DEFAULT_EXCLUDED_DIRS", {".git", "__pycache__", "profiles", "yara.cache", ".pytest_cache", "node_modules", ".venv", "venv", "env", "build", "dist"}),
        ("DEFAULT_EXCLUDED_FILES", {"scan_results.json", "test_scan_results.json", "yara-forge-rules-extended.zip", "compiled_rules.yarc", "manifest.json"}),
        ("DEFAULT_EXCLUDED_SUFFIXES", {".pyc", ".pyo", ".tmp", ".download", ".yarc", ".cache"}),
    )


def _stage_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("VALID_STAGES", {"cs", "binary", "runtime", "asset", "image", "archive", "renpy", "rpgm", "other", "unknown"}),
        ("STAGE_NORMALIZATION", {".cs": "cs", ".dll": "binary", ".exe": "binary", ".bin": "binary", ".so": "binary", ".dylib": "binary", ".py": "runtime", ".ps1": "runtime", ".bat": "runtime", ".cmd": "runtime", ".sh": "runtime", ".js": "runtime", ".vbs": "runtime", ".rpy": "renpy", ".rpyc": "renpy", ".rpyb": "renpy", ".rpa": "asset", ".rvdata": "rpgm", ".rvdata2": "rpgm", ".rxdata": "rpgm", ".assets": "asset", ".asset": "asset", ".bundle": "asset", ".resource": "asset", ".resources": "asset", ".png": "image", ".jpg": "image", ".jpeg": "image", ".bmp": "image", ".webp": "image", ".zip": "archive", ".tar": "archive", ".gz": "archive", ".bz2": "archive", ".tgz": "archive", ".7z": "archive", ".rar": "archive"}),
        ("STAGE_WEIGHT", {"cs": 1.0, "binary": 1.55, "runtime": 1.25, "asset": 1.2, "image": 0.8, "archive": 1.3, "renpy": 1.2, "rpgm": 1.2, "other": 1.0, "unknown": 1.0}),
        ("ASSET_FINDING_WEIGHTS", {"unity_script_ref": 2, "runtime_injection": 4, "high_entropy_asset": 3, "very_high_entropy_asset": 4, "pe_magic_present": 5, "zip_magic_present": 4, "embedded_pe_signature_found": 6, "embedded_zip_signature_found": 5}),
    )


def _engine_behavior_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("GAME_ENGINE_CONTEXT_TAGS", {"renpy", "renpy_script", "renpy_bytecode", "unity", "unity_asset", "rpgm", "rpgm_js", "nwjs", "actual_stage_asset", "actual_stage_script", "router_stage_asset", "router_stage_script"}),
        ("GAME_ENGINE_ADMIN_IMPOSSIBLE_TAGS", {"schtasks_create", "scheduled_task", "service_create", "service_persistence", "local_admin_add", "defender_disable", "security_service_disable", "shadowcopy_delete", "recovery_disable", "lsass_access", "credential_dump_attempt", "mimikatz_credential_dump", "browser_credential_access", "browser_profile_access", "dpapi_access", "token_secret_access", "remote_scheduled_task", "remote_registry", "admin_share_access", "winrm_exec", "wmi_exec"}),
        ("DOTNET_DYNAMIC_LOADER_TAGS", {"assembly_load", "reflection", "reflection_dotnet", "binary_deserialize", "dynamic_method", "dll_load", "managed_dotnet", "dotnet_execution"}),
        ("DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS", {"encoded_payload_candidate", "payload_decode_candidate", "payload_decode_confirmed", "embedded_pe_payload", "confirmed_embedded_pe_payload", "in_memory_execution", "memory_allocate", "memory_write", "memory_protect"}),
    )


def _media_filetype_default_values() -> tuple[tuple[str, object], ...]:
    audio_ext = {".mp3", ".ogg", ".wav", ".flac", ".aac", ".m4a", ".wma", ".opus", ".mid", ".midi", ".xm", ".mod", ".it", ".s3m", ".aiff", ".aif", ".oga", ".mka"}
    video_ext = {".mp4", ".m4v", ".avi", ".mov", ".webm", ".ogv", ".wmv", ".mkv", ".mpeg", ".mpg", ".ts"}
    return (
        ("MEDIA_AUDIO_EXTENSIONS", audio_ext),
        ("MEDIA_VIDEO_EXTENSIONS", video_ext),
        ("MEDIA_ASSET_EXTENSIONS", audio_ext | video_ext),
        ("DEEP_SCAN_MODE", configure_deep_scan_mode(str_env("UMIGE_DEEP_SCAN_MODE", "auto"))),
        ("MEDIA_TRIAGE_PREFIX_BYTES", int_env("UMIGE_MEDIA_PREFIX_BYTES", 32768, 1, None)),
        ("MEDIA_TRIAGE_SUFFIX_BYTES", int_env("UMIGE_MEDIA_SUFFIX_BYTES", 32768, 1, None)),
        ("IMAGE_FAST_STRING_BYTES", int_env("UMIGE_IMAGE_FAST_STRING_BYTES", 131072, 1, None)),
        ("FONT_ASSET_EXTENSIONS", {".ttf", ".otf", ".ttc", ".woff", ".woff2", ".bdf", ".fnt", ".eot", ".pfa", ".pfb"}),
        ("UNITY_CONTAINER_ASSET_EXTENSIONS", {".assets", ".asset", ".bundle", ".assetbundle", ".unity3d", ".resource", ".resources", ".ress"}),
    )


def _filetype_routing_default_values() -> tuple[tuple[str, object], ...]:
    return (
        ("EXPECTED_MAGIC_TYPES_BY_EXTENSION", SCANNER_EXPECTED_MAGIC_TYPES_BY_EXTENSION),
        ("ROUTABLE_EXTENSIONS_BY_CLAIM", SCANNER_ROUTABLE_EXTENSIONS_BY_CLAIM),
        ("ALL_ROUTABLE_EXTENSIONS", SCANNER_ALL_ROUTABLE_EXTENSIONS),
        ("MAGIC_TYPE_CATEGORY", SCANNER_MAGIC_TYPE_CATEGORY),
        ("CLAIM_CATEGORY_STAGE", {"binary": "binary", "archive": "archive", "image": "image", "media": "asset", "font": "asset", "unity_asset": "asset", "runtime": "runtime", "rpgm": "runtime", "text_asset": "asset"}),
        ("DANGEROUS_FILETYPE_MISCLASSIFICATION_PAIRS", {("image", "runtime"), ("image", "binary"), ("image", "archive"), ("media", "runtime"), ("media", "binary"), ("media", "archive"), ("font", "runtime"), ("font", "binary"), ("text_asset", "binary"), ("runtime", "binary"), ("archive", "binary")}),
        ("PASSIVE_TEXTUAL_CATEGORIES", {"text_asset", "runtime"}),
        ("PASSIVE_ASSET_CATEGORIES", {"image", "media", "font", "unity_asset", "text_asset"}),
        ("EMBEDDED_PAYLOAD_SIGNATURES", ((b"MZ", "embedded_pe_signature"), (b"PK\x03\x04", "embedded_zip_signature"), (b"7z\xbc\xaf'\x1c", "embedded_7z_signature"), (b"Rar!\x1a\x07", "embedded_rar_signature"))),
        ("MEDIA_SUSPICIOUS_STRINGS", (b"powershell", b"frombase64string", b"cmd.exe", b"wscript", b"cscript", b"mshta", b"certutil", b"bitsadmin", b"rundll32", b"regsvr32", b"http://", b"https://", b"downloadstring", b"mimikatz")),
    )


def scanner_default_init_values() -> tuple[tuple[str, object], ...]:
    return (
        *_runtime_default_values(),
        *_image_default_values(),
        *_release_hygiene_default_values(),
        *_stage_default_values(),
        *_engine_behavior_default_values(),
        *_media_filetype_default_values(),
        *_filetype_routing_default_values(),
    )


__all__ = ("scanner_default_init_values",)
