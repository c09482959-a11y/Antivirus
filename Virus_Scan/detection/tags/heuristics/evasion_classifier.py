"""Provenance-aware defense-evasion classification over canonical tag evidence."""

from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    add_classifier_contribution,
    add_classifier_root_contributions,
    classifier_result,
    classifier_root_matches,
    classifier_rule_matches,
    classifier_tag_evidence,
)

_EVASION_TAGS = frozenset({
    "amsi_bypass_attempt", "amsi_scanbuffer_patch", "etw_bypass_attempt",
    "etw_eventwrite_patch", "log_clearing", "uac_bypass", "defender_disable",
    "security_process_kill", "security_service_disable", "shadowcopy_delete",
    "recovery_disable", "firewall_rule_change", "tamper_protection_disable",
    "defense_evasion", "packed_or_obfuscated", "obfuscated_script",
})
_EXECUTION_TAGS = frozenset({"process_exec", "powershell_exec", "cmd_exec"})


def classify_defense_evasion(tags: object) -> object:
    """Return bounded evasion evidence without alias or same-root multiplication."""
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    add_classifier_root_contributions(
        contributions, classifier_root_matches(bundle, _EVASION_TAGS), 5.5,
    )
    rules = (
        ((frozenset({"amsi_scanbuffer_patch"}),), 10.0, "AMSI ScanBuffer patch/bypass"),
        ((frozenset({"amsi_bypass_attempt"}), frozenset({"memory_protect"})), 10.0, "AMSI ScanBuffer patch/bypass"),
        ((frozenset({"etw_eventwrite_patch"}),), 10.0, "ETW EventWrite/NtTraceEvent patch"),
        ((frozenset({"etw_bypass_attempt"}), frozenset({"process_injection"})), 10.0, "ETW EventWrite/NtTraceEvent patch"),
        ((frozenset({"defender_disable"}),), 12.0, "Microsoft Defender preference tampering"),
        ((frozenset({"security_process_kill", "security_service_disable"}),), 12.0, "security tooling kill/disable attempt"),
        ((frozenset({"log_clearing"}), _EXECUTION_TAGS), 8.0, "execution plus event log clearing"),
        ((frozenset({"shadowcopy_delete"}),), 8.0, "shadow copy deletion"),
        ((frozenset({"shadowcopy_delete"}), frozenset({"file_rename_delete"})), 10.0, "ransomware backup removal plus file destruction"),
        ((frozenset({"shadowcopy_delete"}), frozenset({"recovery_disable"})), 10.0, "backup and recovery disable chain"),
        ((frozenset({"recovery_disable"}),), 8.0, "recovery/safe boot disable"),
        ((frozenset({"firewall_rule_change"}), frozenset({"process_exec"})), 6.0, "firewall tampering with execution"),
        ((frozenset({"tamper_protection_disable"}),), 12.0, "tamper protection disable attempt"),
        ((frozenset({"uac_bypass"}), frozenset({"process_exec"})), 8.0, "UAC bypass execution chain"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(
            contributions, classifier_rule_matches(bundle, groups), points, label,
        )
    return classifier_result(contributions)


__all__ = ("classify_defense_evasion",)
