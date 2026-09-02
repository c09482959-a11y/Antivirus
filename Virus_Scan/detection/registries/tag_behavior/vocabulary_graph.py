"""Canonical immutable tag synonym and derivation graph registry."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.tag_vocabulary import (
    DEFAULT_CANONICAL_TAG_ALIASES,
    TAG_VOCABULARY_VERSION,
    tag_vocabulary_manifest,
)

TAG_DERIVATION_GRAPH_VERSION = "tag_derivation_graph_v1"
MAX_TAG_DERIVATION_DEPTH = 6
MAX_TAG_DERIVATION_OUTPUTS = 256
_ALLOWED_RULE_KINDS = frozenset(("normalized", "derived", "composite", "suppression"))
_ALLOWED_RULE_POLARITIES = frozenset(("positive", "negative", "neutral"))
_ALLOWED_RULE_SCOREABILITY = frozenset(("support", "scoreable", "composite", "suppressed", "none"))


@dataclass(frozen=True, slots=True)
class TagDerivationRule:
    source_tag: str
    target_tag: str
    evidence_kind: str = "derived"
    scoreability_class: str = "support"
    correlation_group: str = ""
    polarity: str = "positive"
    rule_id: str = ""

    def __post_init__(self) -> None:
        for name in (
            "source_tag", "target_tag", "evidence_kind", "scoreability_class",
            "correlation_group", "polarity", "rule_id",
        ):
            if type(getattr(self, name)) is not str:
                raise TypeError("tag derivation rule fields must be exact strings")
        if not self.source_tag or not self.target_tag or self.source_tag == self.target_tag:
            raise ValueError("tag derivation rules require distinct non-empty tags")
        if self.evidence_kind not in _ALLOWED_RULE_KINDS:
            raise ValueError("invalid tag derivation evidence kind")
        if self.evidence_kind == "normalized":
            raise ValueError("synonym normalization belongs to the canonical synonym graph")
        if self.polarity not in _ALLOWED_RULE_POLARITIES:
            raise ValueError("invalid tag derivation polarity")
        if self.scoreability_class not in _ALLOWED_RULE_SCOREABILITY:
            raise ValueError("invalid tag derivation scoreability")
        if self.scoreability_class in {"scoreable", "composite"} and not self.correlation_group:
            raise ValueError("scoreable tag derivation requires a correlation group")
        if self.evidence_kind == "suppression":
            if self.polarity != "negative" or self.scoreability_class != "suppressed":
                raise ValueError("suppression rules require negative suppressed semantics")
        elif self.polarity == "negative" or self.scoreability_class == "suppressed":
            raise ValueError("negative/suppressed semantics require a suppression rule")
        if not self.rule_id:
            object.__setattr__(self, "rule_id", self.source_tag + "->" + self.target_tag)


_DECLARED_DERIVATION_EDGES = (
    ('admin_share_access', 'lateral_movement'),
    ('amsi_bypass_attempt', 'defense_evasion'),
    ('amsi_scanbuffer_patch', 'amsi_bypass_attempt'),
    ('amsi_scanbuffer_patch', 'defense_evasion'),
    ('anti_sandbox', 'defense_evasion'),
    ('anti_vm', 'defense_evasion'),
    ('archive_dropper', 'dropper_behavior'),
    ('assembly_load', 'reflection'),
    ('at_exec', 'scheduled_execution'),
    ('at_exec', 'schtasks_create'),
    ('background_transfer', 'network_download'),
    ('backup_delete', 'ransomware_behavior'),
    ('base64', 'base64_blob_detected'),
    ('base64', 'decoded_base64_blob'),
    ('bash_exec', 'script_execution'),
    ('binaryformatter_deserialize', 'binary_deserialize'),
    ('bitsadmin_exec', 'background_transfer'),
    ('bitsadmin_exec', 'network_download'),
    ('blockchain_api_access', 'blockchain_activity'),
    ('blockchain_c2_polling', 'backdoor_or_c2'),
    ('blockchain_command_parse', 'backdoor_or_c2'),
    ('blockchain_p2p_or_rpc', 'blockchain_activity'),
    ('browser_credential_access', 'browser_profile_access'),
    ('browser_credential_access', 'credential_access'),
    ('browser_extraction', 'browser_credential_access'),
    ('browser_extraction', 'browser_profile_access'),
    ('browser_extraction', 'credential_access'),
    ('browser_xhr_fetch', 'asset_resource_fetch'),
    ('c2_beacon', 'backdoor_or_c2'),
    ('c2_beacon', 'network_activity'),
    ('c2_beacon', 'network_c2'),
    ('certutil', 'certutil_exec'),
    ('certutil_decode', 'base64'),
    ('certutil_decode', 'payload_decode_candidate'),
    ('clipboard_access', 'collection'),
    ('clipboard_crypto', 'collection'),
    ('cmd_exec', 'process_exec'),
    ('comsvcs_exec', 'credential_dump_attempt'),
    ('comsvcs_exec', 'memory_dump'),
    ('confirmed_injection_chain', 'process_injection'),
    ('credential_access_attempt', 'credential_access'),
    ('credential_api_access', 'credential_access'),
    ('credential_dump_attempt', 'credential_access'),
    ('credential_memory_access', 'credential_access'),
    ('cron_modify', 'new_job'),
    ('cron_modify', 'schtasks_create'),
    ('crypto_address_display', 'ransomware_behavior'),
    ('crypto_file_operation', 'ransomware_behavior'),
    ('crypto_wallet_clipboard_replace', 'collection'),
    ('crypto_wallet_pattern', 'collection'),
    ('cscript_exec', 'script_execution'),
    ('decoded_payload_rescanned', 'payload_decode'),
    ('decoded_payload_rescanned', 'payload_decode_candidate'),
    ('defender_disable', 'defense_evasion'),
    ('dll_hijack', 'dll_load'),
    ('dll_sideload', 'dll_load'),
    ('dotnet_execution', 'process_exec'),
    ('dpapi_access', 'credential_access'),
    ('embedded_archive_payload', 'dropper_behavior'),
    ('embedded_base64_payload', 'payload_decode_candidate'),
    ('embedded_payload_after_eof', 'encoded_payload_candidate'),
    ('emit_calli', 'dynamic_method'),
    ('etw_bypass_attempt', 'defense_evasion'),
    ('etw_eventwrite_patch', 'defense_evasion'),
    ('etw_eventwrite_patch', 'etw_bypass_attempt'),
    ('execution_persistence', 'schtasks_create'),
    ('exfiltration', 'network_exfiltration'),
    ('file_collection', 'collection'),
    ('file_read', 'file_access'),
    ('file_rename_delete', 'ransomware_behavior'),
    ('file_traversal', 'ransomware_behavior'),
    ('fileless_execution', 'script_execution'),
    ('firewall_rule_change', 'defense_evasion'),
    ('game_resource_cache', 'asset_resource_fetch'),
    ('high_confidence_browser_credential_theft', 'browser_credential_access'),
    ('high_confidence_browser_credential_theft', 'credential_access'),
    ('high_confidence_browser_credential_theft', 'dpapi_access'),
    ('high_confidence_credential_theft', 'credential_access'),
    ('high_confidence_credential_theft', 'credential_dump_attempt'),
    ('high_confidence_credential_theft', 'lsass_access'),
    ('high_entropy_packed', 'packed_or_obfuscated'),
    ('high_entropy_section', 'high_entropy_sections'),
    ('http', 'url_present'),
    ('http_upload', 'network_activity'),
    ('https', 'url_present'),
    ('image_payload_candidate', 'stego_candidate_observation'),
    ('image_stego_lsb_anomaly', 'lsb_statistical_anomaly'),
    ('impacket_exec', 'lateral_movement'),
    ('impacket_exec', 'smb_activity'),
    ('inline_task', 'fileless_execution'),
    ('installutil_exec', 'dotnet_execution'),
    ('installutil_exec', 'process_exec'),
    ('invoke_expression', 'script_execution'),
    ('javascript_execution', 'script_execution'),
    ('jpeg_metadata_encoded_reference', 'image_metadata_encoded_reference'),
    ('jpeg_metadata_url_reference', 'image_metadata_url_reference'),
    ('keylogging_behavior', 'collection'),
    ('lolbin_download', 'network_download'),
    ('low_string_visibility', 'packed_or_obfuscated'),
    ('lsb_randomness_anomaly', 'lsb_statistical_anomaly'),
    ('macro_office', 'script_execution'),
    ('memory_dump', 'credential_access'),
    ('memory_protection', 'memory_protect'),
    ('mimikatz_credential_dump', 'credential_access'),
    ('mimikatz_credential_dump', 'credential_dump_attempt'),
    ('mimikatz_credential_dump', 'lsass_access'),
    ('miner_binary', 'cryptomining_behavior'),
    ('mining_pool_connection', 'cryptomining_behavior'),
    ('msbuild_exec', 'dotnet_execution'),
    ('msbuild_exec', 'process_exec'),
    ('mshta', 'mshta_exec'),
    ('network_c2', 'backdoor_or_c2'),
    ('network_download', 'network_activity'),
    ('network_exfiltration', 'network_activity'),
    ('new_job', 'schtasks_create'),
    ('obfuscated_script', 'packed_or_obfuscated'),
    ('obfuscation_pack', 'packed_or_obfuscated'),
    ('office_macro_execution', 'script_execution'),
    ('packed_exe', 'packed_or_obfuscated'),
    ('packer_marker', 'packed_or_obfuscated'),
    ('password', 'credential_access'),
    ('payload_decode', 'payload_decode_candidate'),
    ('pickle_external_executable_reference', 'process_exec'),
    ('pickle_external_file_reference', 'file_access'),
    ('pickle_external_script_reference', 'script_execution'),
    ('pickle_file_load_context', 'file_access'),
    ('pickle_fragmented_base64_payload', 'encoded_payload_candidate'),
    ('pickle_fragmented_payload', 'encoded_payload_candidate'),
    ('possible_lsb_stego', 'lsb_statistical_anomaly'),
    ('possible_stego_payload', 'stego_statistical_anomaly'),
    ('powershell', 'powershell_exec'),
    ('priv_esc_uac', 'defense_evasion'),
    ('ps_exec', 'powershell_exec'),
    ('python_exec', 'script_execution'),
    ('ransom_note_indicator', 'ransomware_behavior'),
    ('rapid_file_write', 'ransomware_behavior'),
    ('rdp_enable_or_use', 'lateral_movement'),
    ('recovery_disable', 'defense_evasion'),
    ('recovery_disable', 'ransomware_behavior'),
    ('reflection_dotnet', 'reflection'),
    ('reg_exec', 'registry_mod'),
    ('registry_persistence', 'persistence'),
    ('registry_persistence', 'registry_mod'),
    ('regsvr32', 'regsvr32_exec'),
    ('regsvr32_sct', 'regsvr32_exec'),
    ('remote_command_channel', 'backdoor_or_c2'),
    ('remote_command_channel', 'network_activity'),
    ('remote_command_channel', 'network_c2'),
    ('remote_execution', 'lateral_movement'),
    ('remote_payload_download', 'network_activity'),
    ('remote_payload_download', 'network_download'),
    ('remote_powershell', 'winrm_exec'),
    ('remote_registry', 'lateral_movement'),
    ('remote_scheduled_task', 'lateral_movement'),
    ('remote_scheduled_task', 'schtasks_create'),
    ('remote_thread', 'thread_execution'),
    ('reverse_shell', 'backdoor_or_c2'),
    ('run_key_mod', 'persistence'),
    ('run_key_mod', 'registry_mod'),
    ('run_key_mod', 'registry_persistence'),
    ('run_key_mod', 'startup_persistence'),
    ('rundll32', 'rundll32_exec'),
    ('scheduled_execution', 'schtasks_create'),
    ('schtasks_create', 'schtasks'),
    ('screenshot_capture', 'collection'),
    ('scriptlet_execution', 'script_execution'),
    ('security_process_kill', 'defense_evasion'),
    ('security_service_disable', 'defense_evasion'),
    ('set_item_property', 'registry_mod'),
    ('shadowcopy_delete', 'defense_evasion'),
    ('shadowcopy_delete', 'ransomware_behavior'),
    ('shadowcopy_delete', 'recovery_disable'),
    ('smb_activity', 'lateral_movement'),
    ('socket_usage', 'network_activity'),
    ('startup_persistence', 'registry_mod'),
    ('stego_payload_suspect', 'stego_statistical_anomaly'),
    ('stratum_protocol', 'cryptomining_behavior'),
    ('strong_lsb_balance_anomaly', 'lsb_statistical_anomaly'),
    ('syscall_sequence', 'shellcode_loader'),
    ('systemd_modify', 'new_job'),
    ('systemd_modify', 'schtasks_create'),
    ('tamper_protection_disable', 'defense_evasion'),
    ('token_exfiltration', 'network_activity'),
    ('token_exfiltration', 'network_exfiltration'),
    ('token_secret_access', 'credential_access'),
    ('uac_bypass', 'defense_evasion'),
    ('url_in_image', 'image_metadata_url_reference'),
    ('vbs_execution', 'script_execution'),
    ('very_high_entropy', 'packed_or_obfuscated'),
    ('vssadmin_delete', 'defense_evasion'),
    ('vssadmin_delete', 'ransomware_behavior'),
    ('vssadmin_delete', 'recovery_disable'),
    ('vssadmin_delete', 'shadowcopy_delete'),
    ('wbadmin_delete', 'defense_evasion'),
    ('wbadmin_delete', 'ransomware_behavior'),
    ('wbadmin_delete', 'recovery_disable'),
    ('wbadmin_delete', 'shadowcopy_delete'),
    ('win32_process_create', 'wmi_exec'),
    ('wmi', 'wmi_exec'),
    ('wmic', 'wmi_exec'),
    ('wscript_exec', 'script_execution'),
)

_DECLARED_TAGS = frozenset(
    tag
    for edge in _DECLARED_DERIVATION_EDGES
    for tag in edge
) | frozenset(DEFAULT_CANONICAL_TAG_ALIASES) | frozenset(DEFAULT_CANONICAL_TAG_ALIASES.values())

_DEFAULT_RULES = tuple(
    TagDerivationRule(source_tag=source, target_tag=target)
    for source, target in _DECLARED_DERIVATION_EDGES
)


def validate_tag_derivation_rules(
    rules: object,
    *,
    declared_tags: object = _DECLARED_TAGS,
    version: object = TAG_DERIVATION_GRAPH_VERSION,
) -> tuple[TagDerivationRule, ...]:
    """Validate exact immutable rules and reject every ambiguous graph shape."""
    if type(version) is not str or not version:
        raise ValueError("tag derivation graph version is required")
    if type(rules) is not tuple or type(declared_tags) is not frozenset:
        raise TypeError("tag derivation graph inputs must be immutable exact builtins")
    if any(type(tag) is not str or not tag for tag in declared_tags):
        raise ValueError("declared tag vocabulary contains invalid tags")
    seen_pairs: dict[tuple[str, str], TagDerivationRule] = {}
    adjacency: dict[str, set[str]] = {}
    for rule in rules:
        if type(rule) is not TagDerivationRule:
            raise TypeError("tag derivation graph contains a non-canonical rule")
        if rule.source_tag not in declared_tags or rule.target_tag not in declared_tags:
            raise ValueError("tag derivation graph references an unknown target or source")
        key = (rule.source_tag, rule.target_tag)
        previous = seen_pairs.get(key)
        if previous is not None and previous != rule:
            raise ValueError("duplicate conflicting tag derivation definition")
        seen_pairs[key] = rule
        adjacency.setdefault(rule.source_tag, set()).add(rule.target_tag)
        adjacency.setdefault(rule.target_tag, set())

    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(tag: str) -> None:
        if tag in visiting:
            raise ValueError("cyclic tag derivation graph")
        if tag in visited:
            return
        visiting.add(tag)
        for target in sorted(adjacency.get(tag, ())):
            visit(target)
        visiting.remove(tag)
        visited.add(tag)
    for tag in sorted(adjacency):
        visit(tag)
    return tuple(sorted(seen_pairs.values(), key=lambda rule: (rule.source_tag, rule.target_tag, rule.rule_id)))


TAG_DERIVATION_RULES = validate_tag_derivation_rules(_DEFAULT_RULES)


def _rule_index(rules: tuple[TagDerivationRule, ...]) -> Mapping[str, tuple[TagDerivationRule, ...]]:
    grouped: dict[str, list[TagDerivationRule]] = {}
    for rule in rules:
        grouped.setdefault(rule.source_tag, []).append(rule)
    return MappingProxyType({
        source: tuple(sorted(values, key=lambda rule: (rule.target_tag, rule.rule_id)))
        for source, values in sorted(grouped.items())
    })


TAG_DERIVATION_INDEX = _rule_index(TAG_DERIVATION_RULES)

_ATTACK_PHASE_RULES = (
    ("execution", frozenset(("powershell_exec", "cmd_exec", "wscript_exec", "cscript_exec", "mshta_exec", "script_execution", "encoded_powershell"))),
    ("persistence", frozenset(("schtasks", "schtasks_create", "run_key_mod", "registry_mod", "registry_persistence", "startup_persistence", "persistence"))),
    ("credential_access", frozenset(("credential_access", "credential_dump_attempt", "lsass_access", "browser_credential_access", "browser_extraction", "dpapi_access"))),
    ("defense_evasion", frozenset(("encoded_powershell", "obfuscated_script", "amsi_bypass_attempt", "etw_bypass_attempt", "log_clearing", "packed_or_obfuscated", "defense_evasion"))),
    ("collection", frozenset(("collection", "keylogging_behavior", "screenshot_capture", "clipboard_access", "screen_capture"))),
    ("exfiltration", frozenset(("network_download", "network_activity", "http_upload", "network_exfiltration", "dns_tunneling", "cloud_upload", "ftp_transfer"))),
    ("lateral_movement", frozenset(("psexec_usage", "wmi_exec", "winrm_exec", "remote_service_creation", "lateral_movement", "remote_execution"))),
    ("privilege_escalation", frozenset(("token_impersonation", "runas_usage", "uac_bypass"))),
)
ATTACK_PHASE_BY_TAG = MappingProxyType({
    tag: phase
    for phase, tags in _ATTACK_PHASE_RULES
    for tag in sorted(tags)
})


def derivation_rules_for(tag: object) -> tuple[TagDerivationRule, ...]:
    if type(tag) is not str:
        return ()
    return TAG_DERIVATION_INDEX.get(tag, ())


def attack_phase_for_tag(tag: object) -> str:
    if type(tag) is not str:
        return "unknown"
    return ATTACK_PHASE_BY_TAG.get(tag, "unknown")


def tag_derivation_manifest() -> dict[str, object]:
    return {
        "vocabulary": tag_vocabulary_manifest(),
        "graph_version": TAG_DERIVATION_GRAPH_VERSION,
        "rule_count": len(TAG_DERIVATION_RULES),
        "declared_tag_count": len(_DECLARED_TAGS),
        "max_depth": MAX_TAG_DERIVATION_DEPTH,
        "max_outputs": MAX_TAG_DERIVATION_OUTPUTS,
        "rules": tuple((
            rule.source_tag, rule.target_tag, rule.evidence_kind,
            rule.scoreability_class, rule.correlation_group, rule.polarity, rule.rule_id,
        ) for rule in TAG_DERIVATION_RULES),
    }


__all__ = (
    "ATTACK_PHASE_BY_TAG",
    "MAX_TAG_DERIVATION_DEPTH",
    "MAX_TAG_DERIVATION_OUTPUTS",
    "TAG_DERIVATION_GRAPH_VERSION",
    "TAG_DERIVATION_INDEX",
    "TAG_DERIVATION_RULES",
    "TagDerivationRule",
    "attack_phase_for_tag",
    "derivation_rules_for",
    "tag_derivation_manifest",
    "validate_tag_derivation_rules",
)
