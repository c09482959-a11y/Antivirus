"""Provenance-aware credential, spyware, and collection chain classifier."""

from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    add_classifier_contribution,
    classifier_result,
    classifier_rule_matches,
    classifier_tag_evidence,
)


def detect_lolbin_credential_theft(tags: object) -> object:
    """Score credential chains while requiring distinct roots for correlations."""
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    rules = (
        ((frozenset({"browser_profile_access", "browser_extraction"}),), 10.0, "browser credential/profile access"),
        ((frozenset({"dpapi_access"}), frozenset({"browser_profile_access", "browser_extraction"})), 12.0, "DPAPI browser credential access"),
        ((frozenset({"lsass_access", "credential_dump_attempt"}),), 12.0, "LSASS/credential dump behavior"),
        ((frozenset({"credential_memory_access"}),), 10.0, "credential memory access chain"),
        ((frozenset({"keylogging_behavior", "input_capture"}),), 10.0, "keylogging/input capture behavior"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    return classifier_result(contributions)


__all__ = ("detect_lolbin_credential_theft",)
