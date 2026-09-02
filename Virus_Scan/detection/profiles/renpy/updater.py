from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.detection.profiles.renpy.updater_abuse_rules import (
    C2_TERMS,
    PAYLOAD_WRITE_TERMS,
    PERSISTENCE_TERMS,
    STAGING_AREA_TERMS,
    has_suspicious_endpoint,
    suspicious_executable_refs,
    updater_behavior_context,
)
from Virus_Scan.detection.profiles.renpy.updater_constants import (
    BROAD_UNVALIDATED_TAGS,
    PICKLE_GRAPH_PROOF_TAGS,
    RENPY_CONTEXT_TAGS,
    RENPY_FAILSAFE_ONLY_MAX_SCORE,
    RENPY_FAILSAFE_ONLY_TAGS,
    RENPY_UPDATER_HARD_ANCHOR_TAGS,
    RENPY_UPDATER_HARD_ANCHOR_TEXT,
    RENPY_UPDATER_REPLACEMENTS,
    RENPY_UPDATER_SUPPRESS_TAGS,
    RPYC_HIGH_RISK_TAGS,
)
from Virus_Scan.detection.profiles.renpy.updater_identity import is_renpy_official_updater_path
from Virus_Scan.detection.profiles.renpy.updater_text import (
    has_any_text,
    high_gate_norm,
    is_renpy_bytecode_path,
    profile_text_or_empty,
    profile_tuple_or_empty,
)
from Virus_Scan.utils.reference_url_policy import suppress_reference_url_false_positives
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.utils.text_validation import tag_validation_text


def _renpy_updater_score_value(score: object, *, reason: str) -> tuple[float, str]:
    """Materialize Ren'Py updater scores without caller-owned numeric hooks."""
    return no_hook_finite_float(
        score,
        default=0.0,
        minimum=0.0,
        reason=reason,
        non_finite_reason="renpy_updater_score_non_finite",
    )


def _append_reason(reasons: list[str], reason: str) -> list[str]:
    if reason != "":
        return [reason, *reasons]
    return reasons


def _score_unavailable_evidence(name: str, reason: str, score: float) -> dict[str, object] | None:
    if reason == "":
        return None
    return {
        "name": name,
        "reason": reason,
        "old_score": score,
        "new_score": score,
        "confidence_degraded": True,
        "json_record_required": True,
        "replay_record_required": True,
    }


def renpy_updater_behavior_abuse_tags(path: object = None, strings_blob: object = "") -> list[str]:
    """Detect malicious behavior inside official Ren'Py updater files."""
    tags = []
    if not is_renpy_official_updater_path(path, strings_blob):
        return tags
    text = tag_validation_text(strings_blob)
    if not text:
        return tags

    context = updater_behavior_context(text)
    shell_abuse = context["shell_abuse"]
    has_subprocess = context["has_subprocess"]
    suspicious_exec_refs = suspicious_executable_refs(text)
    executable_payload_ref = bool(suspicious_exec_refs)

    if shell_abuse:
        tags.extend(["renpy_updater_external_process_abuse", "process_exec", "script_execution"])
        if has_any_text(text, ["powershell", "encodedcommand", "-enc"]):
            tags.extend(["powershell_exec", "encoded_powershell", "encoded_powershell"])
        if has_any_text(text, ["cmd.exe /c", "cmd /c"]):
            tags.append("cmd_exec")
    if has_subprocess and not context["normal_zsync"]:
        tags.extend(["renpy_updater_external_process_abuse", "process_exec"])

    writes_staging_area = has_any_text(text, STAGING_AREA_TERMS)
    explicit_payload_write = executable_payload_ref and has_any_text(text, PAYLOAD_WRITE_TERMS)
    if context["has_fetch"] and executable_payload_ref:
        tags.extend(["renpy_updater_payload_staging_abuse", "remote_payload_download", "network_download"])
    if context["has_fetch"] and executable_payload_ref and (has_subprocess or shell_abuse):
        tags.extend(["renpy_updater_download_exec_abuse", "network_download", "process_exec"])
    if (writes_staging_area or explicit_payload_write) and executable_payload_ref and (context["has_fetch"] or has_subprocess):
        tags.extend(["renpy_updater_payload_staging_abuse", "file_write"])
    if has_any_text(text, PERSISTENCE_TERMS) and (shell_abuse or executable_payload_ref or has_any_text(text, ["autorun", "runonce"])):
        tags.extend(["renpy_updater_persistence_abuse", "persistence", "autorun_persistence"])
    if has_suspicious_endpoint(text):
        tags.extend(["renpy_updater_suspicious_endpoint", "suspicious_ip_url", "network_activity"])
    if has_any_text(text, C2_TERMS):
        tags.extend(["remote_command_channel", "network_c2", "backdoor_or_c2"])
    if tags:
        tags.extend(["renpy_official_updater", "renpy_updater_hard_proof_bypass"])
    return ordered_unique_tags(tags)


def renpy_updater_has_hard_anchor(tags: object = None, strings_blob: object = "", path: object = None) -> bool:
    tagset = {profile_text_or_empty(t).lower() for t in profile_tuple_or_empty(tags) if profile_text_or_empty(t) != ""}
    if tagset & RENPY_UPDATER_HARD_ANCHOR_TAGS:
        return True
    path_text = profile_text_or_empty(path)
    if path_text and renpy_updater_behavior_abuse_tags(path=path_text, strings_blob=strings_blob):
        return True
    return bool(has_any_text(tag_validation_text(strings_blob), RENPY_UPDATER_HARD_ANCHOR_TEXT))


def apply_renpy_updater_baseline(tags: object, path: object = None, strings_blob: object = "") -> list[str]:
    """Rewrite official Ren'Py updater behavior into capability tags unless hard proof exists."""
    if not is_renpy_official_updater_path(path, strings_blob):
        return ordered_unique_tags(tags)
    abuse_tags = renpy_updater_behavior_abuse_tags(path=path, strings_blob=strings_blob)
    if abuse_tags or renpy_updater_has_hard_anchor(tags, strings_blob, path=path):
        return ordered_unique_tags(list(profile_tuple_or_empty(tags)) + list(profile_tuple_or_empty(abuse_tags)) + ["renpy_official_updater", "renpy_updater_hard_proof_bypass"])

    cleaned = []
    extras = [
        "renpy_official_updater",
        "renpy_update_download_capability",
        "renpy_update_archive_apply_capability",
        "renpy_zsync_process_capability",
        "persistent_update_state",
        "renpy_updater_baseline_v1",
    ]
    suppressed = False
    for tag in profile_tuple_or_empty(tags):
        low = profile_text_or_empty(tag).lower()
        if low in RENPY_UPDATER_SUPPRESS_TAGS:
            suppressed = True
            continue
        repl = RENPY_UPDATER_REPLACEMENTS.get(low)
        if repl:
            extras.append(repl)
            suppressed = True
            continue
        cleaned.append(tag)
    if suppressed:
        extras.append("renpy_updater_dropper_chain_suppressed")
    return ordered_unique_tags(cleaned + extras)


def renpy_updater_score_cap(score: object, tags: object = None, path: object = None, strings_blob: object = "") -> tuple[float, list[str]]:
    """Cap official Ren'Py updater files unless hard malicious proof exists."""
    score, score_reason = _renpy_updater_score_value(
        score,
        reason="renpy_updater_score_unavailable",
    )
    if not is_renpy_official_updater_path(path, strings_blob):
        return score, _append_reason([], score_reason)
    if renpy_updater_has_hard_anchor(tags, strings_blob, path=path):
        return score, _append_reason(["renpy_updater_cap_bypass_hard_proof"], score_reason)
    return min(score, 22.0), _append_reason(["renpy_official_updater_cap_score"], score_reason)


def apply_renpy_failsafe_only_cap(score: object, tags: object = None, path: object = None) -> tuple[float, dict[str, object] | None]:
    del path
    old, score_reason = _renpy_updater_score_value(
        score,
        reason="renpy_failsafe_score_unavailable",
    )
    unavailable_evidence = _score_unavailable_evidence(
        "renpy_failsafe_score_unavailable",
        score_reason,
        old,
    )
    norm = high_gate_norm(tags)
    if not (norm & RENPY_CONTEXT_TAGS):
        return old, unavailable_evidence
    allowed_noise = RENPY_CONTEXT_TAGS | RENPY_FAILSAFE_ONLY_TAGS
    if norm and norm <= allowed_noise:
        new = min(old, RENPY_FAILSAFE_ONLY_MAX_SCORE)
        if new < old:
            evidence = {"name": "renpy_failsafe_only_low_cap", "old_score": old, "new_score": new, "reason": "renpy_bytecode_or_failsafe_entropy_without_attack_anchor", "hits": sorted(norm)}
            if score_reason != "":
                evidence["score_unavailable_reason"] = score_reason
                evidence["confidence_degraded"] = True
                evidence["json_record_required"] = True
                evidence["replay_record_required"] = True
            return new, evidence
    return old, unavailable_evidence


def suppress_renpy_bytecode_noise(tags: object, path: object = None, strings_blob: object = "") -> list[str]:
    """Remove scary behavior tags from .rpyc unless real execution/API context is present."""
    if not is_renpy_bytecode_path(path):
        return ordered_unique_tags(tags)
    text = tag_validation_text(strings_blob)
    strong_exec = has_any_text(text, [
        "subprocess", "os.system", "popen(", "createprocess", "shellexecute", "cmd.exe",
        "powershell", "wmic process call create", "win32_process.create", "invoke-wmimethod",
        "writeprocessmemory", "createremotethread", "virtualprotect", "mimikatz", "sekurlsa",
        "minidumpwritedump", "cryptunprotectdata", "net use", "\\admin$", "impacket",
    ])
    tagset = {profile_text_or_empty(t).lower() for t in profile_tuple_or_empty(tags) if profile_text_or_empty(t) != ""}
    pickle_graph_proven = bool(
        "pickle_opcode_graph_analyzed" in tagset
        and tagset & {"pickle_dangerous_global", "pickle_callable_reference"}
        and "pickle_reduce_opcode" in tagset
    )
    if strong_exec or pickle_graph_proven:
        return ordered_unique_tags(tags)

    cleaned = []
    suppressed_behavior = False
    for tag in profile_tuple_or_empty(tags):
        low = profile_text_or_empty(tag).lower()
        if low in RPYC_HIGH_RISK_TAGS or low in BROAD_UNVALIDATED_TAGS:
            suppressed_behavior = True
            continue
        if low in {"actual_stage_binary", "observed_stage_binary", "claimed_stage_runtime", "extension_mismatch"}:
            continue
        cleaned.append(tag)
    if suppressed_behavior:
        cleaned.append("renpy_bytecode_noise_suppressed")
    return ordered_unique_tags(cleaned)


__all__ = (
    'apply_renpy_failsafe_only_cap',
    'apply_renpy_updater_baseline',
    'renpy_updater_behavior_abuse_tags',
    'renpy_updater_has_hard_anchor',
    'renpy_updater_score_cap',
    'suppress_reference_url_false_positives',
    'suppress_renpy_bytecode_noise',
)
