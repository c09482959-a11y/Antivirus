from __future__ import annotations

import re
from pathlib import Path

import pytest

from Virus_Scan.scanners.config.archive_limits_contracts import ArchivePolicySnapshot, ScannerLimitsPolicySnapshot
from Virus_Scan.scanners.config.binary_contracts import BinaryPolicySnapshot
from Virus_Scan.scanners.config.contracts import ScannerConfigError
from Virus_Scan.scanners.config.core_contracts import (
    PayloadPolicySnapshot,
    PicklePolicySnapshot,
    RawChunkPolicySnapshot,
    TextPolicySnapshot,
)
from Virus_Scan.scanners.config.filetype_engine_contracts import EnginePolicySnapshot, FiletypePolicySnapshot
from Virus_Scan.scanners.config.validation_binary_helpers import (
    _require_binary_chain_definitions,
    _require_hex_bytes_tuple,
)
from Virus_Scan.scanners.config.validation_helpers import (
    _IntRequirement, _StringTupleRequirement, _require_int, _require_str_tuple,
)
from Virus_Scan.scanners.binary_appended_payload import _add_appended_observation_tags
from Virus_Scan.scanners.binary_behavior_detectors import _binary_behavior_score, _ransomware_tags


class HostilePolicyValue:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self, hook: str) -> None:
        type(self).touched += 1
        raise AssertionError(f"{hook} hook executed")

    def __bool__(self) -> bool:  # pragma: no cover - must never execute
        self._touch("__bool__")

    def __str__(self) -> str:  # pragma: no cover - must never execute
        self._touch("__str__")

    def __repr__(self) -> str:  # pragma: no cover - must never execute
        self._touch("__repr__")

    def __format__(self, _format_spec: str) -> str:  # pragma: no cover - must never execute
        self._touch("__format__")

    def __iter__(self):  # pragma: no cover - must never execute
        self._touch("__iter__")

    def __len__(self) -> int:  # pragma: no cover - must never execute
        self._touch("__len__")

    def __int__(self) -> int:  # pragma: no cover - must never execute
        self._touch("__int__")

    def __float__(self) -> float:  # pragma: no cover - must never execute
        self._touch("__float__")

    def __bytes__(self) -> bytes:  # pragma: no cover - must never execute
        self._touch("__bytes__")


def test_stage1995_policy_snapshots_preserve_exact_primitive_constructor_behavior() -> None:
    payload = PayloadPolicySnapshot(
        max_candidates="3",  # type: ignore[arg-type]
        max_text_bytes=True,  # type: ignore[arg-type]
        min_base64_chars=None,  # type: ignore[arg-type]
        min_hex_chars=4,
        default_max_depth="5",  # type: ignore[arg-type]
        source=123,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )
    archive = ArchivePolicySnapshot(
        default_max_depth="2",  # type: ignore[arg-type]
        default_max_members=True,  # type: ignore[arg-type]
        default_max_member_size=100,
        member_probe_bytes=10,
        member_text_max_size=20,
        ecosystem_score_limit=30,
        ecosystem_score_warn=40,
        rpa_read_max_bytes=50,
        rpa_index_max_bytes=60,
        rpa_member_max_bytes=70,
        rpa_member_max_count=80,
        rpa_zip_max_depth=90,
        rpa_zip_max_members=100,
        rpa_zip_max_member_size=110,
        nested_archive_suffixes=[".zip"],  # type: ignore[arg-type]
        rarity_high_risk_probability="0.1",  # type: ignore[arg-type]
        rarity_high_risk_min_score=1,
        rarity_high_risk_multiplier=2,
        rarity_rare_probability=3,
        rarity_rare_multiplier=4,
        rarity_uncommon_probability=5,
        rarity_uncommon_multiplier=6,
        rarity_common_probability=7,
        rarity_common_multiplier=8,
        rarity_default_multiplier=9,
        source=456,  # type: ignore[arg-type]
        schema=None,  # type: ignore[arg-type]
    )

    assert payload.max_candidates == 3
    assert payload.max_text_bytes == 1
    assert payload.min_base64_chars == 0
    assert payload.default_max_depth == 5
    assert payload.source == "123"
    assert payload.schema == "payload_policy.v1"
    assert archive.default_max_depth == 2
    assert archive.default_max_members == 1
    assert archive.nested_archive_suffixes == (".zip",)
    assert archive.rarity_high_risk_probability == 0.1
    assert archive.source == "456"
    assert archive.schema == "archive_policy.v1"


def test_stage1995_core_policy_snapshots_reject_hostile_constructor_values_without_hooks() -> None:
    hostile = HostilePolicyValue()
    HostilePolicyValue.reset()

    payload = PayloadPolicySnapshot(hostile, hostile, hostile, hostile, hostile, hostile, hostile)  # type: ignore[arg-type]
    pickle_policy = PicklePolicySnapshot(
        hostile, hostile, [hostile], hostile, hostile, hostile, hostile, hostile, hostile, hostile,
        [hostile], [hostile], [hostile], [hostile], [hostile], [hostile], [hostile], [hostile], hostile, hostile,  # type: ignore[arg-type]
    )
    raw = RawChunkPolicySnapshot([hostile], [hostile], hostile, hostile)  # type: ignore[arg-type]
    text = TextPolicySnapshot(
        runtime_strong_attack_context=[hostile],  # type: ignore[arg-type]
        broad_unvalidated_tags=[hostile],  # type: ignore[arg-type]
        library_baseline_hard_proof_tags=[hostile],  # type: ignore[arg-type]
        passive_textual_categories=[hostile],  # type: ignore[arg-type]
        game_engine_context_tags=[hostile],  # type: ignore[arg-type]
        correlation_group_keywords=[(hostile, [hostile])],  # type: ignore[arg-type]
        contextual_baseline_min_keep_without_anchor=hostile,  # type: ignore[arg-type]
        contextual_baseline_min_keep_with_anchor=hostile,  # type: ignore[arg-type]
        contextual_baseline_min_files=hostile,  # type: ignore[arg-type]
        contextual_baseline_common_tag_prob=hostile,  # type: ignore[arg-type]
        contextual_baseline_max_reduction=hostile,  # type: ignore[arg-type]
        vector_cluster_max_bonus=hostile,  # type: ignore[arg-type]
        context_corroboration_max_bonus=hostile,  # type: ignore[arg-type]
        combined_context_max_bonus=hostile,  # type: ignore[arg-type]
        min_concrete_tags_for_context_boost=hostile,  # type: ignore[arg-type]
        min_score_for_context_boost=hostile,  # type: ignore[arg-type]
        api_groups={hostile: hostile},
        api_specific_tags={hostile: [hostile]},
        api_group_tags={hostile: hostile},
        api_group_inferred_tags={hostile: hostile},
        spyware_collection_tags=[hostile],  # type: ignore[arg-type]
        spyware_sensitive_tags=[hostile],  # type: ignore[arg-type]
        spyware_sensitive_text_terms=[hostile],  # type: ignore[arg-type]
        spyware_suppressed_tags=[hostile],  # type: ignore[arg-type]
        source=hostile,  # type: ignore[arg-type]
        schema=hostile,  # type: ignore[arg-type]
    )

    assert payload.max_candidates == 0
    assert payload.source == ""
    assert pickle_policy.renpy_extensions == ("unsupported_scanner_policy_value:HostilePolicyValue",)
    assert raw.context_anchors == ("unsupported_scanner_policy_value:HostilePolicyValue",)
    assert text.correlation_group_keywords == (
        ("unsupported_scanner_policy_value:HostilePolicyValue", ("unsupported_scanner_policy_value:HostilePolicyValue",)),
    )
    assert text.api_groups["unsupported_scanner_policy_value:HostilePolicyValue"]["unavailable_reason"] == "unsupported_scanner_policy_value"
    assert text.schema == "text_policy.v1"
    assert HostilePolicyValue.touched == 0


def test_stage1995_archive_filetype_and_binary_policy_snapshots_reject_hostile_values_without_hooks() -> None:
    hostile = HostilePolicyValue()
    HostilePolicyValue.reset()

    archive = ArchivePolicySnapshot(
        hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile,
        hostile, hostile, [hostile], hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile,
        hostile, hostile, hostile,  # type: ignore[arg-type]
    )
    limits = ScannerLimitsPolicySnapshot(
        hostile, hostile, hostile, hostile, hostile, hostile, hostile, [hostile], [hostile], [hostile], [hostile],
        {hostile: hostile}, [hostile], [hostile], [hostile], {hostile: hostile}, hostile, hostile, hostile, hostile,
        hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile, hostile,  # type: ignore[arg-type]
    )
    filetype = FiletypePolicySnapshot(
        behavior_model_version=hostile,  # type: ignore[arg-type]
        high_risk_buckets=[hostile],  # type: ignore[arg-type]
        non_execution_capabilities=[hostile],  # type: ignore[arg-type]
        container_execution_capabilities=[hostile],  # type: ignore[arg-type]
        passive_asset_categories=[hostile],  # type: ignore[arg-type]
        dangerous_actual_categories=[hostile],  # type: ignore[arg-type]
        engine_extension_bucket_policies={hostile: hostile},
        global_common_filetype_buckets={hostile: hostile},
        engine_specific_filetype_buckets={hostile: hostile},
        expected_magic_types_by_extension={hostile: hostile},
        routable_extensions_by_claim={hostile: hostile},
        all_routable_extensions=[hostile],  # type: ignore[arg-type]
        magic_type_category={hostile: hostile},
        source=hostile,  # type: ignore[arg-type]
        schema=hostile,  # type: ignore[arg-type]
    )
    engine = EnginePolicySnapshot(
        use_ilspy=hostile,  # type: ignore[arg-type]
        unity_lifecycle_hooks=[hostile],  # type: ignore[arg-type]
        unity_runtime_checks=[(hostile, hostile)],  # type: ignore[arg-type]
        unity_container_asset_extensions=[hostile],  # type: ignore[arg-type]
        rpgm_encrypted_media_url_markers=[hostile],  # type: ignore[arg-type]
        rpgm_decrypted_media_suspicious_tokens=[hostile],  # type: ignore[arg-type]
        engine_file_context_cues={hostile: hostile},
        media_profile_extensions=[hostile],  # type: ignore[arg-type]
        media_profile_tags=[hostile],  # type: ignore[arg-type]
        engine_context_runtime_hint_ambiguous_threshold=hostile,  # type: ignore[arg-type]
        engine_context_runtime_hint_confidence_threshold=hostile,  # type: ignore[arg-type]
        engine_context_runtime_hint_ambiguous_weight=hostile,  # type: ignore[arg-type]
        engine_context_runtime_hint_weak_weight=hostile,  # type: ignore[arg-type]
        source=hostile,  # type: ignore[arg-type]
        schema=hostile,  # type: ignore[arg-type]
    )
    binary = BinaryPolicySnapshot(
        entropy_read_max_bytes=hostile,  # type: ignore[arg-type]
        entropy_high_threshold=hostile,  # type: ignore[arg-type]
        entropy_high_score=hostile,  # type: ignore[arg-type]
        entropy_very_high_threshold=hostile,  # type: ignore[arg-type]
        entropy_very_high_score=hostile,  # type: ignore[arg-type]
        entropy_low_visibility_threshold=hostile,  # type: ignore[arg-type]
        entropy_low_visibility_printable_ratio=hostile,  # type: ignore[arg-type]
        entropy_low_visibility_score=hostile,  # type: ignore[arg-type]
        entropy_packer_markers=[hostile],  # type: ignore[arg-type]
        entropy_packer_score=hostile,  # type: ignore[arg-type]
        dotnet_read_max_bytes=hostile,  # type: ignore[arg-type]
        dotnet_extensions=[hostile],  # type: ignore[arg-type]
        dotnet_extension_mismatch_extensions=[hostile],  # type: ignore[arg-type]
        dotnet_metadata_markers=[hostile],  # type: ignore[arg-type]
        dotnet_behavior_markers=[(hostile, hostile)],  # type: ignore[arg-type]
        il_opcode_patterns=[(hostile, hostile)],  # type: ignore[arg-type]
        il_obfuscation_markers=[hostile],  # type: ignore[arg-type]
        il_behavior_tag_weights={hostile: hostile},
        il_score_call_ldstr_bonus=hostile,  # type: ignore[arg-type]
        il_score_process_call_bonus=hostile,  # type: ignore[arg-type]
        il_score_network_call_bonus=hostile,  # type: ignore[arg-type]
        il_score_memory_pinvoke_bonus=hostile,  # type: ignore[arg-type]
        il_obfuscation_per_marker=hostile,  # type: ignore[arg-type]
        il_obfuscation_packed_bonus=hostile,  # type: ignore[arg-type]
        il_obfuscation_indirect_call_bonus=hostile,  # type: ignore[arg-type]
        il_op_score_weight=hostile,  # type: ignore[arg-type]
        il_max_ops_for_score=hostile,  # type: ignore[arg-type]
        il_obfuscation_marker_result_limit=hostile,  # type: ignore[arg-type]
        dotnet_il_op_limit=hostile,  # type: ignore[arg-type]
        dotnet_il_obfuscation_threshold=hostile,  # type: ignore[arg-type]
        dotnet_il_behavior_threshold=hostile,  # type: ignore[arg-type]
        binary_lolbin_chain_definitions=[{hostile: hostile}],  # type: ignore[arg-type]
        binary_scheduled_task_persistence_rules=[{hostile: hostile}],  # type: ignore[arg-type]
        binary_command_execution_terms=[hostile],  # type: ignore[arg-type]
        binary_c2_tasking_terms=[hostile],  # type: ignore[arg-type]
        binary_ransomware_terms={hostile: hostile},
        binary_os_execution_tags=[hostile],  # type: ignore[arg-type]
        binary_behavior_bucket_terms={hostile: hostile},
        binary_high_confidence_tags=[hostile],  # type: ignore[arg-type]
        raw_escalation_dangerous_anchor_tags=[hostile],  # type: ignore[arg-type]
        strict_fast_benign_extensions=[hostile],  # type: ignore[arg-type]
        strict_fast_benign_max_bytes=hostile,  # type: ignore[arg-type]
        strict_fast_benign_binary_magic=[hostile],  # type: ignore[arg-type]
        strict_fast_benign_deny_tokens=[hostile],  # type: ignore[arg-type]
        binary_string_rules=[(hostile, hostile)],  # type: ignore[arg-type]
        native_elf_import_semantics=[(hostile, hostile)],  # type: ignore[arg-type]
        native_elf_syscall_semantics=[(hostile, hostile, hostile)],  # type: ignore[arg-type]
        source=hostile,  # type: ignore[arg-type]
        schema=hostile,  # type: ignore[arg-type]
    )

    marker = "unsupported_scanner_policy_value:HostilePolicyValue"
    assert archive.default_max_depth == 0
    assert archive.nested_archive_suffixes == (marker,)
    assert limits.image_stego_max_file_bytes == 0
    assert limits.image_payload_magic_prefixes == (marker,)
    assert filetype.high_risk_buckets == frozenset({marker})
    assert filetype.magic_type_category[marker]["unavailable_reason"] == "unsupported_scanner_policy_value"
    assert engine.use_ilspy is False
    assert engine.unity_runtime_checks == ((marker, marker),)
    assert binary.entropy_read_max_bytes == 0
    assert binary.dotnet_extensions == frozenset({marker})
    assert binary.strict_fast_benign_binary_magic == (b"unsupported_scanner_policy_bytes:HostilePolicyValue",)
    assert binary.binary_ransomware_terms["scanner_contract_key_0"]["unavailable_reason"] == "invalid_json_mapping_key"
    assert HostilePolicyValue.touched == 0


def test_stage1995_scanner_config_validation_failures_reject_hostile_inputs_without_hooks() -> None:
    hostile = HostilePolicyValue()
    HostilePolicyValue.reset()

    with pytest.raises(ScannerConfigError) as int_error:
        _require_int(_IntRequirement(hostile, hostile, (1, 4), hostile, hostile))  # type: ignore[arg-type]
    with pytest.raises(ScannerConfigError) as tuple_error:
        _require_str_tuple(_StringTupleRequirement({"names": [hostile]}, "names", (1, 4), hostile, hostile))  # type: ignore[arg-type]
    with pytest.raises(ScannerConfigError) as chain_error:
        _require_binary_chain_definitions({"chains": [hostile]}, "chains", source=hostile, config_name=hostile)  # type: ignore[arg-type]
    with pytest.raises(ScannerConfigError) as hex_error:
        _require_hex_bytes_tuple({}, hostile, minimum=1, maximum=2, source=hostile, config_name=hostile)  # type: ignore[arg-type]

    assert int_error.value.failure.config_name == "scanner_config"
    assert int_error.value.failure.source == ""
    assert "unsupported_scanner_config_key:HostilePolicyValue must be an integer" == int_error.value.failure.reason
    assert tuple_error.value.failure.reason == "names[0] must be a non-empty string"
    assert chain_error.value.failure.reason == "chains[0] must be an object"
    assert hex_error.value.failure.reason == "unsupported_scanner_config_key:HostilePolicyValue must be a list"
    assert HostilePolicyValue.touched == 0


def test_stage1995_early_scanner_binary_helpers_reject_hostile_values_without_hooks() -> None:
    hostile = HostilePolicyValue()
    HostilePolicyValue.reset()

    tags: list[str] = []
    _add_appended_observation_tags(tags, hostile)  # type: ignore[arg-type]

    assert tags == ["image_appended_data", "stego_candidate_observation"]
    assert _binary_behavior_score(hostile) == 0.0
    assert _ransomware_tags(hostile) == set()  # type: ignore[arg-type]
    assert HostilePolicyValue.touched == 0


def test_stage1995_scanner_config_source_does_not_reintroduce_hook_patterns() -> None:
    root = Path(__file__).resolve().parents[2]
    files = (
        "Virus_Scan/scanners/config/archive_limits_contracts.py",
        "Virus_Scan/scanners/config/binary_contracts.py",
        "Virus_Scan/scanners/config/core_contracts.py",
        "Virus_Scan/scanners/config/error_contracts.py",
        "Virus_Scan/scanners/config/filetype_engine_contracts.py",
        "Virus_Scan/scanners/config/immutable_policy.py",
        "Virus_Scan/scanners/config/validation_binary_helpers.py",
        "Virus_Scan/scanners/config/validation_helpers.py",
        "Virus_Scan/scanners/binary.py",
        "Virus_Scan/scanners/binary_appended_payload.py",
        "Virus_Scan/scanners/binary_behavior_detectors.py",
    )
    forbidden_patterns = (
        r"int\(self\.[^)]+ or 0\)",
        r"float\(self\.[^)]+ or 0\.0\)",
        r"str\(self\.[^)]+ or ",
        r"tuple\(str\(item\)",
        r"frozenset\(str\(item\)",
        r"sorted\(value\.keys\(\), key=lambda item: str\(item\)\)",
        r"\bbool\(self\.use_ilspy\)",
        r"error_source=f\"scanner_config\.",
        r"super\(\)\.__init__\(f\"",
        r"f\"\{key",
        r"f\"\{key\}\[",
        r"contains no scanner logic, fallback implementation",
        r"tags\.append\(f'\{kind\}_appended_",
        r"bool\(has_payload_magic or entropy >= 7\.35\)",
        r"float\(s or 0\.0\)",
        r"flags\.get\(key\)",
    )

    for relative in files:
        source = (root / relative).read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            assert not re.search(pattern, source), f"{relative} still matches {pattern}"
