"""Immutable scanner binary policy snapshot contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scanners.contracts.scanner_evidence import freeze_scanner_contract_value
from Virus_Scan.scanners.config.immutable_policy import (
    policy_bytes_tuple,
    policy_float,
    policy_int,
    policy_string_pairs,
    policy_text,
    policy_text_frozenset,
    policy_text_tuple,
)


def _tuple_str_values(value: object) -> tuple[str, ...]:
    return policy_text_tuple(value)


def _tuple_bytes_values(value: object) -> tuple[bytes, ...]:
    return policy_bytes_tuple(value)


def _tuple_string_pairs(value: object) -> tuple[tuple[str, str], ...]:
    return policy_string_pairs(value)


def _tuple_native_syscall_semantics(value: object) -> tuple[tuple[int, str, str], ...]:
    out: list[tuple[int, str, str]] = []
    for item in no_hook_sequence_items(value):
        if type(item) in (tuple, list) and len(item) >= 3:
            out.append((policy_int(item[0]), policy_text(item[1]), policy_text(item[2])))
        else:
            out.append((0, "unsupported_scanner_policy_syscall", type(item).__name__))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class BinaryPolicySnapshot:
    entropy_read_max_bytes: int
    entropy_high_threshold: float
    entropy_high_score: float
    entropy_very_high_threshold: float
    entropy_very_high_score: float
    entropy_low_visibility_threshold: float
    entropy_low_visibility_printable_ratio: float
    entropy_low_visibility_score: float
    entropy_packer_markers: tuple[str, ...]
    entropy_packer_score: float
    dotnet_read_max_bytes: int
    dotnet_extensions: frozenset[str]
    dotnet_extension_mismatch_extensions: frozenset[str]
    dotnet_metadata_markers: tuple[str, ...]
    dotnet_behavior_markers: tuple[tuple[str, str], ...]
    il_opcode_patterns: tuple[tuple[str, str], ...]
    il_obfuscation_markers: tuple[str, ...]
    il_behavior_tag_weights: object
    il_score_call_ldstr_bonus: float
    il_score_process_call_bonus: float
    il_score_network_call_bonus: float
    il_score_memory_pinvoke_bonus: float
    il_obfuscation_per_marker: float
    il_obfuscation_packed_bonus: float
    il_obfuscation_indirect_call_bonus: float
    il_op_score_weight: float
    il_max_ops_for_score: int
    il_obfuscation_marker_result_limit: int
    dotnet_il_op_limit: int
    dotnet_il_obfuscation_threshold: float
    dotnet_il_behavior_threshold: float
    binary_lolbin_chain_definitions: tuple[Mapping[str, object], ...]
    binary_scheduled_task_persistence_rules: tuple[Mapping[str, object], ...]
    binary_command_execution_terms: tuple[str, ...]
    binary_c2_tasking_terms: tuple[str, ...]
    binary_ransomware_terms: object
    binary_os_execution_tags: frozenset[str]
    binary_behavior_bucket_terms: object
    binary_high_confidence_tags: frozenset[str]
    raw_escalation_dangerous_anchor_tags: frozenset[str]
    strict_fast_benign_extensions: frozenset[str]
    strict_fast_benign_max_bytes: int
    strict_fast_benign_binary_magic: tuple[bytes, ...]
    strict_fast_benign_deny_tokens: tuple[str, ...]
    binary_string_rules: tuple[tuple[str, str], ...]
    native_elf_import_semantics: tuple[tuple[str, str], ...]
    native_elf_syscall_semantics: tuple[tuple[int, str, str], ...]
    source: str
    schema: str = "binary_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "entropy_read_max_bytes", policy_int(self.entropy_read_max_bytes))
        object.__setattr__(self, "entropy_high_threshold", policy_float(self.entropy_high_threshold))
        object.__setattr__(self, "entropy_high_score", policy_float(self.entropy_high_score))
        object.__setattr__(self, "entropy_very_high_threshold", policy_float(self.entropy_very_high_threshold))
        object.__setattr__(self, "entropy_very_high_score", policy_float(self.entropy_very_high_score))
        object.__setattr__(self, "entropy_low_visibility_threshold", policy_float(self.entropy_low_visibility_threshold))
        object.__setattr__(self, "entropy_low_visibility_printable_ratio", policy_float(self.entropy_low_visibility_printable_ratio))
        object.__setattr__(self, "entropy_low_visibility_score", policy_float(self.entropy_low_visibility_score))
        object.__setattr__(self, "entropy_packer_markers", _tuple_str_values(self.entropy_packer_markers))
        object.__setattr__(self, "entropy_packer_score", policy_float(self.entropy_packer_score))
        object.__setattr__(self, "dotnet_read_max_bytes", policy_int(self.dotnet_read_max_bytes))
        object.__setattr__(self, "dotnet_extensions", policy_text_frozenset(self.dotnet_extensions))
        object.__setattr__(self, "dotnet_extension_mismatch_extensions", policy_text_frozenset(self.dotnet_extension_mismatch_extensions))
        object.__setattr__(self, "dotnet_metadata_markers", _tuple_str_values(self.dotnet_metadata_markers))
        object.__setattr__(self, "dotnet_behavior_markers", _tuple_string_pairs(self.dotnet_behavior_markers))
        object.__setattr__(self, "il_opcode_patterns", _tuple_string_pairs(self.il_opcode_patterns))
        object.__setattr__(self, "il_obfuscation_markers", _tuple_str_values(self.il_obfuscation_markers))
        object.__setattr__(self, "il_behavior_tag_weights", freeze_scanner_contract_value(self.il_behavior_tag_weights))
        object.__setattr__(self, "il_score_call_ldstr_bonus", policy_float(self.il_score_call_ldstr_bonus))
        object.__setattr__(self, "il_score_process_call_bonus", policy_float(self.il_score_process_call_bonus))
        object.__setattr__(self, "il_score_network_call_bonus", policy_float(self.il_score_network_call_bonus))
        object.__setattr__(self, "il_score_memory_pinvoke_bonus", policy_float(self.il_score_memory_pinvoke_bonus))
        object.__setattr__(self, "il_obfuscation_per_marker", policy_float(self.il_obfuscation_per_marker))
        object.__setattr__(self, "il_obfuscation_packed_bonus", policy_float(self.il_obfuscation_packed_bonus))
        object.__setattr__(self, "il_obfuscation_indirect_call_bonus", policy_float(self.il_obfuscation_indirect_call_bonus))
        object.__setattr__(self, "il_op_score_weight", policy_float(self.il_op_score_weight))
        object.__setattr__(self, "il_max_ops_for_score", policy_int(self.il_max_ops_for_score))
        object.__setattr__(self, "il_obfuscation_marker_result_limit", policy_int(self.il_obfuscation_marker_result_limit))
        object.__setattr__(self, "dotnet_il_op_limit", policy_int(self.dotnet_il_op_limit))
        object.__setattr__(self, "dotnet_il_obfuscation_threshold", policy_float(self.dotnet_il_obfuscation_threshold))
        object.__setattr__(self, "dotnet_il_behavior_threshold", policy_float(self.dotnet_il_behavior_threshold))
        object.__setattr__(self, "binary_lolbin_chain_definitions", tuple(freeze_scanner_contract_value(item) for item in no_hook_sequence_items(self.binary_lolbin_chain_definitions)))
        object.__setattr__(self, "binary_scheduled_task_persistence_rules", tuple(freeze_scanner_contract_value(item) for item in no_hook_sequence_items(self.binary_scheduled_task_persistence_rules)))
        object.__setattr__(self, "binary_command_execution_terms", _tuple_str_values(self.binary_command_execution_terms))
        object.__setattr__(self, "binary_c2_tasking_terms", _tuple_str_values(self.binary_c2_tasking_terms))
        object.__setattr__(self, "binary_ransomware_terms", freeze_scanner_contract_value(self.binary_ransomware_terms))
        object.__setattr__(self, "binary_os_execution_tags", policy_text_frozenset(self.binary_os_execution_tags))
        object.__setattr__(self, "binary_behavior_bucket_terms", freeze_scanner_contract_value(self.binary_behavior_bucket_terms))
        object.__setattr__(self, "binary_high_confidence_tags", policy_text_frozenset(self.binary_high_confidence_tags))
        object.__setattr__(self, "raw_escalation_dangerous_anchor_tags", policy_text_frozenset(self.raw_escalation_dangerous_anchor_tags))
        object.__setattr__(self, "strict_fast_benign_extensions", policy_text_frozenset(self.strict_fast_benign_extensions))
        object.__setattr__(self, "strict_fast_benign_max_bytes", policy_int(self.strict_fast_benign_max_bytes))
        object.__setattr__(self, "strict_fast_benign_binary_magic", _tuple_bytes_values(self.strict_fast_benign_binary_magic))
        object.__setattr__(self, "strict_fast_benign_deny_tokens", _tuple_str_values(self.strict_fast_benign_deny_tokens))
        object.__setattr__(self, "binary_string_rules", _tuple_string_pairs(self.binary_string_rules))
        object.__setattr__(self, "native_elf_import_semantics", _tuple_string_pairs(self.native_elf_import_semantics))
        object.__setattr__(self, "native_elf_syscall_semantics", _tuple_native_syscall_semantics(self.native_elf_syscall_semantics))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="binary_policy.v1"))


__all__ = ("BinaryPolicySnapshot",)
