"""Provenance-aware execution classifiers over canonical tag evidence."""

from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    add_classifier_contribution,
    add_classifier_root_contributions,
    classifier_result,
    classifier_root_matches,
    classifier_rule_matches,
    classifier_tag_evidence,
    classifier_tagset,
    ClassifierEvidenceResult,
)

_BYTECODE_TAGS = frozenset({
    "bytecode_exec", "bytecode_eval", "bytecode_subprocess", "bytecode_os.system",
    "bytecode_socket", "rpa_automation_execution", "rpa_opcode_execution",
    "rpa_pickle_usage", "rpa_opcode_exec",
})
_DOTNET_TAGS = frozenset({
    "dotnet", "dotnet_pe", "dotnet_x64", "clr_runtime_present",
    "dotnet_obfuscated_or_packed",
})
_SCRIPT_HOSTS = frozenset({
    "powershell_exec", "mshta_exec", "wscript_exec", "script_execution",
})
_DECODED_EXEC_CONTEXT = frozenset({
    "payload_decode_confirmed",
    "encoded_powershell", "script_execution", "process_exec", "fileless_execution",
    "in_memory_execution", "assembly_load",
})
_PACKED_TAGS = frozenset({
    "packed_or_obfuscated", "high_entropy_packed", "very_high_entropy",
    "low_string_visibility", "packer_marker", "dotnet_obfuscated_or_packed",
})


def classify_bytecode_and_script(tags: object) -> object:
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    add_classifier_root_contributions(
        contributions, classifier_root_matches(bundle, _BYTECODE_TAGS), 5.0,
    )
    rules = (
        ((frozenset({"bytecode_eval"}), frozenset({"network_activity"})), 8.0, "dynamic eval with network behavior"),
        ((frozenset({"bytecode_subprocess", "bytecode_os.system"}),), 12.0, "bytecode process execution"),
        ((frozenset({"rpa_pickle_usage"}), frozenset({"rpa_opcode_execution"})), 9.0, "RPA deserialization execution"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    return classifier_result(contributions)


def classify_dotnet_behavior(tags: object) -> object:
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    add_classifier_root_contributions(
        contributions, classifier_root_matches(bundle, _DOTNET_TAGS), 3.0,
    )
    rules = (
        ((frozenset({"dotnet_obfuscated_or_packed"}),), 12.0, ".NET obfuscated or packed"),
        ((frozenset({"clr_runtime_present"}), frozenset({"process_injection"})), 8.0, ".NET injection behavior"),
        ((frozenset({"dotnet_pe"}), frozenset({"credential_access"})), 7.0, ".NET credential access behavior"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    return classifier_result(contributions)


def classify_fileless_loader(tags: object) -> object:
    bundle = classifier_tag_evidence(tags)
    tagset = classifier_tagset(bundle)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    rules = (
        ((_SCRIPT_HOSTS,), 8.0, "script host execution"),
        ((frozenset({"encoded_powershell"}),), 14.0, "encoded powershell"),
        ((frozenset({"payload_decode_candidate"}), _DECODED_EXEC_CONTEXT), 10.0, "payload decode execution stage"),
        ((frozenset({"memory_allocate"}), frozenset({"memory_write"}), frozenset({"thread_execution"})), 18.0, "memory-only payload execution"),
        ((frozenset({"amsi_bypass_attempt"}),), 12.0, "AMSI bypass"),
        ((frozenset({"etw_bypass_attempt"}),), 12.0, "ETW bypass"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    if "file_write" not in tagset:
        add_classifier_contribution(
            contributions,
            classifier_rule_matches(
                bundle,
                (frozenset({"network_download"}), frozenset({"process_exec"})),
            ),
            14.0,
            "downloaded payload execution without disk write",
        )
    result = classifier_result(contributions)
    if (
        not ({"payload_decode_candidate"} & tagset and _DECODED_EXEC_CONTEXT & tagset)
        and {"decoded_base64_blob", "base64_blob_detected"} & tagset
    ):
        return ClassifierEvidenceResult(
            result.contributions,
            informational_hits=("base64 data observed; no standalone score",),
        )
    return result


def classify_packed_dropper(tags: object) -> object:
    bundle = classifier_tag_evidence(tags)
    contributions: dict[tuple[str, ...], tuple[float, str]] = {}
    rules = (
        ((_PACKED_TAGS,), 10.0, "packed binary indicators"),
        ((frozenset({"memory_allocate"}), frozenset({"memory_write"}), frozenset({"memory_protect"})), 16.0, "runtime unpacking chain"),
        ((frozenset({"thread_execution", "process_injection"}),), 10.0, "payload launch after unpack"),
        ((frozenset({"network_download"}), frozenset({"file_write"})), 12.0, "download then write payload"),
        ((frozenset({"file_write"}), frozenset({"process_exec"})), 12.0, "write then execute payload"),
        ((frozenset({"registry_mod"}), frozenset({"process_exec"})), 8.0, "dropper persistence"),
    )
    for groups, points, label in rules:
        add_classifier_contribution(contributions, classifier_rule_matches(bundle, groups), points, label)
    return classifier_result(contributions)


__all__ = (
    "classify_bytecode_and_script",
    "classify_dotnet_behavior",
    "classify_fileless_loader",
    "classify_packed_dropper",
)
