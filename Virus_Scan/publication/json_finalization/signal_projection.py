"""Scanner/model signal projection helpers for compact final JSON."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_list,
    bounded_signal_value,
    canonical_text_list,
    contains_non_finite_float,
)
from Virus_Scan.publication.json_finalization.record_fields import record_errors
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_type_name,
)
from Virus_Scan.publication.json_finalization.base_projection_boundaries import (
    projection_text_result,
    projection_unavailable_text,
)


from Virus_Scan.publication.json_finalization.truthiness import (
    boolean_field_true,
    first_present_value,
    signal_present,
)


PLR2004N32 = 32


def model_signal_projection_failure(source_field: str, reason: str = "non_finite_model_signal_value", value: object | None = None) -> dict[str, object]:
    evidence: dict[str, object] = {
        "model_signal_projection_failed": True,
        "reason": reason,
        "source_field": source_field,
    }
    if value is not None:
        evidence["value_type"] = final_json_type_name(value)
    return evidence


def _text_or_marker(value: object, *, width: int = 512) -> str:
    text, reason = projection_text_result(value)
    if reason:
        return projection_unavailable_text(value, reason)[:width]
    return text[:width]


def _text_or_empty(value: object) -> str:
    text, reason = projection_text_result(value)
    return "" if reason else text.strip()


def _missing_signal_reason(primary: str) -> str:
    if primary in ("temporal_signals", "temporal_features"):
        return "temporal_support_insufficient"
    if primary in ("markov_sequence_signals", "markov_features"):
        return "markov_support_insufficient"
    if primary in ("clustering_signals", "cluster_features", "clustering_features"):
        return "clustering_unassigned"
    if primary in ("graph_signals", "graph_features"):
        return "graph_unavailable"
    return "model_signal_unavailable"


def signal_summary(record: Mapping[str, object], primary: str, *alternates: str) -> object:
    """Preserve subsystem signal evidence without collapsing list-shaped records.

    Temporal, Markov, clustering, graph, YARA, entropy, and archive analyzers do
    not all emit the same container type. Earlier compact finalization only kept
    dict-shaped signals through an older mapping-only helper. List-shaped signal
    payloads were silently reduced to ``{}``, and later stringified dict entries
    into Python repr text. Preserve bounded JSON-native evidence so model output remains
    auditable and reloadable.
    """
    for key in (primary, *tuple(alternates)):
        value = final_json_mapping_get(record, key)
        if value is None:
            continue
        if contains_non_finite_float(value):
            return model_signal_projection_failure(key)
        if isinstance(value, dict):
            return bounded_dict(value, 16)
        if isinstance(value, (list, tuple, set)):
            return bounded_signal_value(value)
        return model_signal_projection_failure(key, "unsupported_model_signal_value", value)
    return model_signal_projection_failure(primary, _missing_signal_reason(primary))


def contextual_signal_frame(record: Mapping[str, object], **signals: object) -> dict[str, object]:
    """Return an audit frame tying subsystem evidence to contextual routing.

    This is not an alternate route; it is a compact JSON audit view built
    from the canonical routing fields already attached to the
    result record. It lets validation prove that model evidence and baseline
    context survived finalization together.
    """
    presence: dict[str, bool] = {}
    frame: dict[str, object] = {
        "container_engine": final_json_mapping_get(record, "container_engine"),
        "artifact_engine": final_json_mapping_get(record, "artifact_engine"),
        "effective_analysis_engine": final_json_mapping_get(record, "effective_analysis_engine"),
        "declared_extension": final_json_mapping_get(record, "declared_extension"),
        "sniffed_type": final_json_mapping_get(record, "sniffed_type"),
        "baseline_key": final_json_mapping_get(record, "baseline_key"),
        "contextual_baseline": final_json_mapping_get(record, "contextual_baseline"),
        "learning_allowed": boolean_field_true(final_json_mapping_get(record, "learning_allowed", False)),
        "signal_presence": presence,
    }
    signal_items = dict.items(signals)
    for name, value in signal_items:
        presence[name] = signal_present(value)
    return frame


def tag_signals(tags: list[object], markers: tuple[str, ...], limit: int = 32) -> list[str]:
    out: list[str] = []
    for tag in tags:
        text = _text_or_marker(tag, width=256)
        low = text.lower()
        if any(marker in low for marker in markers):
            out.append(text[:256])
        if len(out) >= limit:
            break
    return out


def decoded_evidence(record: Mapping[str, object], reasons: list[object]) -> list[str]:
    evidence = first_present_value(record, "decoded_evidence_snippets", "decoded_evidence")
    if evidence is not None:
        normalized_evidence = canonical_text_list(evidence, 32, width=512)
        if len(normalized_evidence) > 0:
            return normalized_evidence
    selected: list[str] = []
    for reason in reasons:
        text = _text_or_marker(reason)
        low = text.lower()
        if any(marker in low for marker in ("url:", "decoded", "powershell", "pickle", "script:", "download:", "base64", "http://", "https://")):
            selected.append(text[:512])
        if len(selected) >= PLR2004N32:
            break
    return canonical_text_list(selected, 32, width=512)


def audit_evidence_snippets(record: Mapping[str, object], reasons: list[object], decoded_evidence_snippets: list[str], tags: list[object]) -> list[str]:
    """Return compact evidence that explains medium/high/malicious verdicts.

    ``decoded_evidence_snippets`` intentionally contains only decoded or extracted
    payload text.  JSON evidence audits also require a general evidence field for
    verdict explanation.  Build that projection at the final reporting boundary
    from canonical explanation reasons and high-signal forensic tags, without
    changing detector scoring or creating an alternate detection path.
    """
    explicit = final_json_mapping_get(record, "evidence_snippets")
    if signal_present(explicit):
        return canonical_text_list(explicit, 32, width=512)
    out: list[str] = list(decoded_evidence_snippets)
    for reason in reasons:
        text = _text_or_empty(reason)
        if text:
            out.append(text[:512])
    if not out:
        for error in record_errors(record):
            text = _text_or_empty(error)
            if text:
                out.append(text[:512])
    if not out:
        markers = (
            "embedded", "polyglot", "archive", "yara", "entropy", "encoded",
            "pickle", "powershell", "download", "execution", "mismatch",
            "dotnet", "ilspy", "dncil", "stego", "malformed", "graph",
        )
        for tag in tags:
            text = _text_or_empty(tag)
            if text and any(marker in text.lower() for marker in markers):
                out.append(text[:256])
            if len(out) >= PLR2004N32:
                break
    return canonical_text_list(out, 32, width=512)


def functional_tag_findings(tags: list[object], markers: tuple[str, ...], *, limit: int = 32) -> list[str]:
    findings: list[str] = []
    for tag in tags:
        text = _text_or_empty(tag)
        low = text.lower()
        if text and any(marker in low for marker in markers) and text not in findings:
            findings.append(text[:256])
        if len(findings) >= limit:
            break
    return findings


def dotnet_record_active(record: Mapping[str, object], tags: list[object]) -> bool:
    sniffed_value = final_json_mapping_get(record, "sniffed_type")
    effective_value = final_json_mapping_get(record, "effective_analysis_engine")
    declared_value = first_present_value(record, "declared_extension", "extension")
    sniffed = _text_or_empty(sniffed_value).lower()
    effective = _text_or_empty(effective_value).lower()
    declared = _text_or_empty(declared_value).lower()
    if sniffed == "mono_dotnet_assembly" or effective in {"unity_dotnet", "dotnet", "mono_dotnet_assembly"}:
        return True
    if declared in {".dll", "dll", ".exe", "exe", ".bytes", "bytes", ".dat", "dat", ".bin", "bin"}:
        tagset = {_text_or_empty(tag).lower() for tag in tags}
        return bool(tagset & {"unity_dotnet", "assembly_load", "reflection", "dynamic_loader", "pe_file", "native_pe"})
    return False


def functional_findings(record: Mapping[str, object], tags: list[object], decoded_evidence_snippets: list[str]) -> dict[str, list[str]]:
    evidence = [_text_or_marker(item) for item in decoded_evidence_snippets]
    binary_failover = functional_tag_findings(tags, ("binary_failover", "scan_failsafe", "extension_mismatch", "magic_type", "declared_"))
    stego = functional_tag_findings(tags, ("stego", "polyglot", "embedded_pe", "embedded_zip", "appended", "image_decode", "png_invalid", "entropy"))
    dotnet = functional_tag_findings(tags, ("dotnet", "assembly_load", "reflection", "dynamic_loader", "methodinfo", "process_exec", "powershell", "webclient", "download"))
    if dotnet_record_active(record, tags) and not dotnet:
        dotnet.append("dotnet_candidate_static_metadata")
    ilspy: list[str] = []
    raw_ilspy = final_json_mapping_get(record, "ilspy_findings")
    if raw_ilspy is not None:
        ilspy.extend(_text_or_marker(item, width=256) for item in bounded_list(raw_ilspy, 16))
    if dotnet_record_active(record, tags) and not ilspy:
        warning_values = final_json_mapping_get(record, "warnings")
        warnings = [_text_or_empty(item).lower() for item in bounded_list(warning_values, 16)]
        if any("ilspy" in warning for warning in warnings):
            ilspy.extend(
                _text_or_marker(item, width=256)
                for item in bounded_list(warning_values, 16)
                if "ilspy" in _text_or_empty(item).lower()
            )
        else:
            ilspy.append("ilspy_not_available_static_metadata_used")
    dncil = functional_tag_findings(tags, ("pseudo_dncil", "il_op_", "assembly_load", "reflection", "dynamic_loader", "methodinfo", "download_execute", "process_exec", "powershell"))
    if dotnet_record_active(record, tags) and not dncil:
        dncil.append("dncil_static_metadata_scan_completed")
    if len(evidence) > 0:
        if any("powershell" in item.lower() or "download" in item.lower() or "process" in item.lower() for item in evidence):
            if "decoded_behavior_evidence" not in dotnet:
                dotnet.append("decoded_behavior_evidence")
    return {
        "binary_failover_tags": binary_failover,
        "stego_findings": stego,
        "dotnet_findings": dotnet,
        "ilspy_findings": ilspy,
        "dncil_findings": dncil,
    }


def functional_diagnostic_warnings(record: Mapping[str, object], tags: list[object]) -> list[str]:
    """Return explicit diagnostics for degraded functional scanner coverage.

    Truncated or metadata-poor PE-like inputs are common hostile corpus members.
    They must not be indistinguishable from clean controls in compact JSON; when
    the scanner can prove PE-like magic but cannot prove CLR/.NET metadata or a
    stronger behavior chain, expose that coverage boundary as a warning.
    """
    warnings = [
        _text_or_marker(item)
        for item in bounded_list(final_json_mapping_get(record, "warnings"), 16)
    ]
    tagset = {_text_or_empty(tag).lower() for tag in tags}
    sniffed_value = final_json_mapping_get(record, "sniffed_type")
    declared_value = first_present_value(record, "declared_extension", "extension")
    sniffed = _text_or_empty(sniffed_value).lower()
    declared = _text_or_empty(declared_value).lower()
    pe_like = sniffed in {"pe", "pe_mz", "native_pe"} or "magic_type_pe_mz" in tagset or "pe_file" in tagset
    declared_binary = declared in {".dll", "dll", ".exe", "exe", ".bin", "bin", ".dat", "dat", ".bytes", "bytes", ".asset", "asset"}
    proved_dotnet = sniffed == "mono_dotnet_assembly" or len(tagset & {"unity_dotnet", "assembly_load", "reflection", "dynamic_loader"}) > 0
    if pe_like and declared_binary and not proved_dotnet:
        diagnostic = "malformed_or_non_dotnet_pe_static_metadata_only"
        if diagnostic not in warnings:
            warnings.append(diagnostic)
    return canonical_text_list(warnings, 16, width=512)


__all__ = (
    'audit_evidence_snippets',
    'contextual_signal_frame',
    'decoded_evidence',
    'dotnet_record_active',
    'functional_diagnostic_warnings',
    'functional_findings',
    'functional_tag_findings',
    'model_signal_projection_failure',
    'signal_summary',
    'tag_signals',
)
