"""Provenance-aware movement and exfiltration classifiers."""

from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    add_classifier_contribution,
    add_classifier_root_contributions,
    classifier_result,
    classifier_root_matches,
    classifier_rule_matches,
    classifier_tag_evidence,
)

_EXFILTRATION_TAGS = frozenset({
    "http_upload", "network_exfiltration", "dns_tunneling", "cloud_upload",
    "ftp_transfer", "network_activity",
})
_LATERAL_TAGS = frozenset({
    "psexec_usage", "wmi_exec", "winrm_exec", "remote_powershell",
    "win32_process_create", "remote_execution", "remote_service_creation",
    "admin_share_access", "smb_activity", "impacket_exec",
    "remote_scheduled_task", "remote_registry", "rdp_enable_or_use",
    "lateral_movement",
})


def classify_exfiltration(tags: object) -> object:
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    add_classifier_root_contributions(
        contributions, classifier_root_matches(bundle, _EXFILTRATION_TAGS), 5.0,
    )
    rules = (
        ((frozenset({"collection"}), frozenset({"http_upload", "network_exfiltration"})), 10.0, "collection to HTTP exfiltration"),
        ((frozenset({"credential_access"}), frozenset({"network_activity"})), 8.0, "credential access with network activity"),
        ((frozenset({"dns_tunneling"}),), 9.0, "DNS tunneling indicator"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    return classifier_result(contributions)


def classify_lateral_movement(tags: object) -> object:
    """Return movement evidence whose multi-signal rules require distinct roots."""
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    lateral_matches = classifier_root_matches(bundle, _LATERAL_TAGS)
    add_classifier_root_contributions(contributions, lateral_matches, 5.0)
    rules = (
        ((frozenset({"wmi_exec"}), frozenset({"process_exec"})), 9.0, "WMI remote process creation"),
        ((frozenset({"win32_process_create"}), frozenset({"process_exec"})), 9.0, "Win32_Process.Create execution"),
        ((frozenset({"winrm_exec"}), frozenset({"powershell_exec"})), 9.0, "PowerShell remoting execution"),
        ((frozenset({"remote_powershell"}), frozenset({"process_exec"})), 9.0, "remote PowerShell process execution"),
        ((frozenset({"admin_share_access"}), frozenset({"remote_service_creation"})), 11.0, "admin share to service-control lateral movement"),
        ((frozenset({"impacket_exec"}), frozenset({"smb_activity"})), 10.0, "Impacket-style SMB remote execution"),
        ((frozenset({"remote_scheduled_task"}), frozenset({"scheduled_task"})), 9.0, "remote scheduled task execution"),
        ((frozenset({"credential_access"}), frozenset({"admin_share_access"})), 8.0, "credential-backed admin share access"),
        ((frozenset({"remote_registry"}), frozenset({"registry_mod"})), 7.0, "remote registry modification"),
        ((frozenset({"lateral_movement"}), frozenset({"file_write"}), frozenset({"process_exec"})), 11.0, "lateral payload write and execution"),
        ((frozenset({"lateral_movement"}), frozenset({"scheduled_task"}), frozenset({"process_exec"})), 11.0, "lateral scheduled execution propagation"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    if len(lateral_matches) >= 2:
        add_classifier_contribution(
            contributions, lateral_matches, 8.0, "multi-signal lateral movement",
        )
    return classifier_result(contributions)


__all__ = ("classify_exfiltration", "classify_lateral_movement")
