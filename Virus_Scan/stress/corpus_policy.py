"""Immutable stress-corpus policy constants.

The values in this module are declarative stress-plan policy. They are consumed
by the corpus planner and exposed through the stress public API.
"""
from __future__ import annotations

from types import MappingProxyType

TOTAL_SYNTHETIC_SAMPLES = 10_000
BENIGN_SYNTHETIC_SAMPLES = 5_000
MALICIOUS_SYNTHETIC_SAMPLES = 5_000
INERT_MALICIOUS_STRESS_SAMPLES = 10_000
INERT_MALICIOUS_ORACLE_SCHEMA_VERSION = "inert_malicious_oracle_v3"
INERT_MALICIOUS_FAMILIES = (
    "powershell_script",
    "javascript_script",
    "python_script",
    "batch_script",
    "command_script",
    "vbscript_script",
    "hta_script",
)
INERT_MALICIOUS_EXTENSIONS = (".ps1", ".js", ".py", ".bat", ".cmd", ".vbs", ".hta")
INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS = ("malicious",)
INERT_MALICIOUS_MINIMUM_SCORE = 90.0
INERT_MALICIOUS_MAXIMUM_SCORE = 100.0
INERT_MALICIOUS_REQUIRED_TAGS = (
    "encoded_powershell",
    "network_download",
    "payload_execution",
    "registry_mod",
)
INERT_MALICIOUS_FORBIDDEN_TAGS = ("benign_clean",)

WORKER_MATRIX = (1, 2, 4, 8, "max_configured")
QUEUE_DEPTH_MATRIX = (1, 8, 64, 256, "max_configured")
RESTART_POINT_MATRIX = (
    "before_ingestion",
    "after_queue_claim",
    "during_worker_execution",
    "during_evidence_generation",
    "during_reconciliation",
    "during_json_write",
    "during_replay_reconstruction",
)
TIMEOUT_PRESSURE_MATRIX = ("none", "low", "medium", "high", "forced_timeout")
ARCHIVE_DEPTH_MATRIX = (0, 1, 2, 4, 8)
SCAN_ORDER_MATRIX = ("sorted", "reverse_sorted", "seeded_shuffle")

FAST_PATH_CONFIGURATION = MappingProxyType({
    "path": "fast",
    "deep_scan_mode": "auto",
    "recursive_archives": False,
    "nested_archives": False,
    "yara": False,
    "yara_light": False,
    "signatures": True,
    "metadata_enrichment": False,
    "binary_analysis": "minimal",
    "string_extraction": "bounded",
    "full_evidence_generation": True,
    "replay_checkpoint_generation": True,
})

DEEP_SCAN_CONFIGURATION = MappingProxyType({
    "path": "deep",
    "deep_scan_mode": "thorough",
    "recursive_archives": True,
    "nested_archives": True,
    "yara": True,
    "yara_light": True,
    "signatures": True,
    "metadata_enrichment": True,
    "binary_analysis": "full",
    "string_extraction": "full",
    "full_evidence_generation": True,
    "replay_checkpoint_generation": True,
})

FAST_PATH_RESULT_ARTIFACTS = (
    "fast_path_results.json",
    "fast_path_replay_results.json",
    "fast_path_forensic_audit.json",
)
DEEP_SCAN_RESULT_ARTIFACTS = (
    "deep_scan_results.json",
    "deep_scan_replay_results.json",
    "deep_scan_forensic_audit.json",
)
CROSS_PATH_RESULT_ARTIFACTS = ("cross_path_comparison.json",)

PIPELINE_PERSISTENCE_COUNTERS = (
    "generated_results",
    "reconciled_results",
    "serialized_results",
    "written_results",
    "replay_recovered_results",
)
PIPELINE_ZERO_LOSS_REQUIREMENTS = MappingProxyType({
    "missing_results": 0,
    "duplicate_results": 0,
    "serialization_mismatches": 0,
    "replay_mismatches": 0,
    "json_corruption_events": 0,
    "failed_persistence_events": 0,
})

GENERIC_STRESS_FILE_TYPES = (
    "pe_exe",
    "pe_dll",
    "python_script",
    "javascript_script",
    "powershell_script",
    "batch_script",
    "office_docm",
    "office_xlsm",
    "office_pptm",
    "zip_archive",
    "nested_zip_archive",
    "renamed_malware_payload",
    "corrupted_binary",
    "large_binary",
    "tiny_binary",
    "timeout_triggering_blob",
    "replay_recovery_checkpoint",
)

SCRIPT_FILE_TYPE_EXTENSIONS = (".py", ".js", ".ps1", ".bat", ".cmd", ".vbs", ".hta")
OFFICE_FILE_TYPE_EXTENSIONS = (".docm", ".xlsm", ".pptm", ".rtf", ".one")
ARCHIVE_FILE_TYPE_EXTENSIONS = (".zip", ".7z", ".rar", ".tar", ".gz")
PE_FILE_TYPE_EXTENSIONS = (".exe", ".dll", ".scr", ".sys")

ENGINE_ANCHOR_FILENAMES = MappingProxyType({
    "renpy": (
        "game/script.rpy",
        "game/script.rpyc",
        "game/archive.rpa",
        "game/options.rpy",
        "renpy/common/00start.rpy",
    ),
    "unity": (
        "UnityPlayer.dll",
        "GameAssembly.dll",
        "Game_Data/globalgamemanagers",
        "Game_Data/Managed/Assembly-CSharp.dll",
        "Game_Data/Resources/unity_builtin_extra",
        "Game_Data/il2cpp_data/Metadata/global-metadata.dat",
    ),
    "rpgm": (
        "www/js/rpg_core.js",
        "www/js/plugins/PluginCommand.js",
        "www/data/Actors.json",
        "www/img/pictures/picture.rpgmvp",
        "www/audio/bgm/theme.rpgmvo",
        "Game.rgss3a",
        "nw.dll",
        "node.dll",
    ),
})

__all__ = (
    "ARCHIVE_DEPTH_MATRIX",
    "ARCHIVE_FILE_TYPE_EXTENSIONS",
    "BENIGN_SYNTHETIC_SAMPLES",
    "CROSS_PATH_RESULT_ARTIFACTS",
    "DEEP_SCAN_CONFIGURATION",
    "DEEP_SCAN_RESULT_ARTIFACTS",
    "ENGINE_ANCHOR_FILENAMES",
    "FAST_PATH_CONFIGURATION",
    "FAST_PATH_RESULT_ARTIFACTS",
    "GENERIC_STRESS_FILE_TYPES",
    "INERT_MALICIOUS_EXPECTED_CLASSIFICATIONS",
    "INERT_MALICIOUS_EXTENSIONS",
    "INERT_MALICIOUS_FAMILIES",
    "INERT_MALICIOUS_ORACLE_SCHEMA_VERSION",
    "INERT_MALICIOUS_STRESS_SAMPLES",
    "INERT_MALICIOUS_FORBIDDEN_TAGS",
    "INERT_MALICIOUS_MAXIMUM_SCORE",
    "INERT_MALICIOUS_MINIMUM_SCORE",
    "INERT_MALICIOUS_REQUIRED_TAGS",
    "MALICIOUS_SYNTHETIC_SAMPLES",
    "OFFICE_FILE_TYPE_EXTENSIONS",
    "PE_FILE_TYPE_EXTENSIONS",
    "PIPELINE_PERSISTENCE_COUNTERS",
    "PIPELINE_ZERO_LOSS_REQUIREMENTS",
    "QUEUE_DEPTH_MATRIX",
    "RESTART_POINT_MATRIX",
    "SCAN_ORDER_MATRIX",
    "SCRIPT_FILE_TYPE_EXTENSIONS",
    "TIMEOUT_PRESSURE_MATRIX",
    "TOTAL_SYNTHETIC_SAMPLES",
    "WORKER_MATRIX",
)
