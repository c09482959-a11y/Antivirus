"""Scanner config validator for binary policy."""
from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

from Virus_Scan.scanners.config.contracts import BinaryPolicySnapshot, ScannerConfigError
from Virus_Scan.scanners.config.validation_binary_helpers import (
    _require_binary_bucket_terms,
    _require_binary_chain_definitions,
    _require_binary_persistence_rules,
    _require_binary_ransomware_terms,
    _require_hex_bytes_tuple,
    _require_native_elf_import_semantics,
    _require_native_elf_syscall_semantics,
)
from Virus_Scan.scanners.config.validation_helpers import (
    _FloatRequirement,
    _config_failure,
    _require_float,
    _require_named_pattern_tuple,
    _require_pair_tuple,
    _require_weight_tuple,
)
from Virus_Scan.scanners.config.validation_helpers import _IntRequirement, _StringTupleRequirement, _require_int, _require_str_tuple

def validate_binary_policy(policy: dict[str, object], *, source: str) -> BinaryPolicySnapshot:
    config_name = "binary_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "binary policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return BinaryPolicySnapshot(
        entropy_read_max_bytes=_require_int(_IntRequirement(policy, 'entropy_read_max_bytes', (1024, 128 * 1024 * 1024), source, config_name)),
        entropy_high_threshold=_require_float(_FloatRequirement(policy, "entropy_high_threshold", (0.0, 8.0), source, config_name)),
        entropy_high_score=_require_float(_FloatRequirement(policy, "entropy_high_score", (0.0, 10.0), source, config_name)),
        entropy_very_high_threshold=_require_float(_FloatRequirement(policy, "entropy_very_high_threshold", (0.0, 8.0), source, config_name)),
        entropy_very_high_score=_require_float(_FloatRequirement(policy, "entropy_very_high_score", (0.0, 10.0), source, config_name)),
        entropy_low_visibility_threshold=_require_float(_FloatRequirement(policy, "entropy_low_visibility_threshold", (0.0, 8.0), source, config_name)),
        entropy_low_visibility_printable_ratio=_require_float(_FloatRequirement(policy, "entropy_low_visibility_printable_ratio", (0.0, 1.0), source, config_name)),
        entropy_low_visibility_score=_require_float(_FloatRequirement(policy, "entropy_low_visibility_score", (0.0, 10.0), source, config_name)),
        entropy_packer_markers=_require_str_tuple(_StringTupleRequirement(policy, 'entropy_packer_markers', (1, 256), source, config_name)),
        entropy_packer_score=_require_float(_FloatRequirement(policy, "entropy_packer_score", (0.0, 10.0), source, config_name)),
        dotnet_read_max_bytes=_require_int(_IntRequirement(policy, 'dotnet_read_max_bytes', (1024, 128 * 1024 * 1024), source, config_name)),
        dotnet_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'dotnet_extensions', (1, 64), source, config_name))),
        dotnet_extension_mismatch_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'dotnet_extension_mismatch_extensions', (1, 64), source, config_name))),
        dotnet_metadata_markers=_require_str_tuple(_StringTupleRequirement(policy, 'dotnet_metadata_markers', (1, 256), source, config_name)),
        dotnet_behavior_markers=tuple((tag, needle) for needle, tag in _require_pair_tuple(policy, "dotnet_behavior_markers", source=source, config_name=config_name)),
        il_opcode_patterns=_require_named_pattern_tuple(policy, "il_opcode_patterns", source=source, config_name=config_name),
        il_obfuscation_markers=_require_str_tuple(_StringTupleRequirement(policy, 'il_obfuscation_markers', (1, 256), source, config_name)),
        il_behavior_tag_weights=MappingProxyType(dict(_require_weight_tuple(policy, "il_behavior_tag_weights", source=source, config_name=config_name))),
        il_score_call_ldstr_bonus=_require_float(_FloatRequirement(policy, "il_score_call_ldstr_bonus", (0.0, 10.0), source, config_name)),
        il_score_process_call_bonus=_require_float(_FloatRequirement(policy, "il_score_process_call_bonus", (0.0, 10.0), source, config_name)),
        il_score_network_call_bonus=_require_float(_FloatRequirement(policy, "il_score_network_call_bonus", (0.0, 10.0), source, config_name)),
        il_score_memory_pinvoke_bonus=_require_float(_FloatRequirement(policy, "il_score_memory_pinvoke_bonus", (0.0, 10.0), source, config_name)),
        il_obfuscation_per_marker=_require_float(_FloatRequirement(policy, "il_obfuscation_per_marker", (0.0, 10.0), source, config_name)),
        il_obfuscation_packed_bonus=_require_float(_FloatRequirement(policy, "il_obfuscation_packed_bonus", (0.0, 10.0), source, config_name)),
        il_obfuscation_indirect_call_bonus=_require_float(_FloatRequirement(policy, "il_obfuscation_indirect_call_bonus", (0.0, 10.0), source, config_name)),
        il_op_score_weight=_require_float(_FloatRequirement(policy, "il_op_score_weight", (0.0, 10.0), source, config_name)),
        il_max_ops_for_score=_require_int(_IntRequirement(policy, 'il_max_ops_for_score', (1, 256), source, config_name)),
        il_obfuscation_marker_result_limit=_require_int(_IntRequirement(policy, 'il_obfuscation_marker_result_limit', (1, 1024), source, config_name)),
        dotnet_il_op_limit=_require_int(_IntRequirement(policy, 'dotnet_il_op_limit', (1, 1024), source, config_name)),
        dotnet_il_obfuscation_threshold=_require_float(_FloatRequirement(policy, "dotnet_il_obfuscation_threshold", (0.0, 10.0), source, config_name)),
        dotnet_il_behavior_threshold=_require_float(_FloatRequirement(policy, "dotnet_il_behavior_threshold", (0.0, 10.0), source, config_name)),
        binary_lolbin_chain_definitions=_require_binary_chain_definitions(policy, "binary_lolbin_chain_definitions", source=source, config_name=config_name),
        binary_scheduled_task_persistence_rules=_require_binary_persistence_rules(policy, "binary_scheduled_task_persistence_rules", source=source, config_name=config_name),
        binary_command_execution_terms=_require_str_tuple(_StringTupleRequirement(policy, 'binary_command_execution_terms', (1, 256), source, config_name)),
        binary_c2_tasking_terms=_require_str_tuple(_StringTupleRequirement(policy, 'binary_c2_tasking_terms', (1, 256), source, config_name)),
        binary_ransomware_terms=_require_binary_ransomware_terms(policy, "binary_ransomware_terms", source=source, config_name=config_name),
        binary_os_execution_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'binary_os_execution_tags', (1, 256), source, config_name))),
        binary_behavior_bucket_terms=_require_binary_bucket_terms(policy, "binary_behavior_bucket_terms", source=source, config_name=config_name),
        binary_high_confidence_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'binary_high_confidence_tags', (1, 512), source, config_name))),
        raw_escalation_dangerous_anchor_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'raw_escalation_dangerous_anchor_tags', (1, 512), source, config_name))),
        strict_fast_benign_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'strict_fast_benign_extensions', (1, 128), source, config_name))),
        strict_fast_benign_max_bytes=_require_int(_IntRequirement(policy, 'strict_fast_benign_max_bytes', (1, 128 * 1024 * 1024), source, config_name)),
        strict_fast_benign_binary_magic=_require_hex_bytes_tuple(policy, "strict_fast_benign_binary_magic_hex", minimum=1, maximum=64, source=source, config_name=config_name),
        strict_fast_benign_deny_tokens=_require_str_tuple(_StringTupleRequirement(policy, 'strict_fast_benign_deny_tokens', (1, 256), source, config_name)),
        binary_string_rules=_require_pair_tuple(policy, "binary_string_rules", source=source, config_name=config_name),
        native_elf_import_semantics=_require_native_elf_import_semantics(policy, "native_elf_import_semantics", source=source, config_name=config_name),
        native_elf_syscall_semantics=_require_native_elf_syscall_semantics(policy, "native_elf_syscall_semantics", source=source, config_name=config_name),
        source=str(Path(source)),
    )

__all__ = (
    "validate_binary_policy",
)
