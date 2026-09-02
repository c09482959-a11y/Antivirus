"""Detection-owned decoded-payload semantic interpretation.

Scanner owns payload decoding.  Detection only consumes scanner-observed decoded
payload records or text views and turns those observations into semantic tags.
"""


from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.strings.contextual import scan as contextual_scan_runtime
from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict
from Virus_Scan.detection.enrichment.text_boundary import detection_enrichment_text_or_empty
from Virus_Scan.detection.enrichment.strings.boundaries import enrichment_sequence
from Virus_Scan.utils.tagging import ordered_unique_tags

_EXECUTION_TAGS = frozenset((
    "process_exec", "script_execution", "powershell_exec", "cmd_exec",
    "payload_execution", "fileless_execution", "in_memory_execution",
    "process_injection", "dynamic_execution", "bytecode_exec", "bytecode_eval",
))
_NETWORK_TAGS = frozenset((
    "network_download", "remote_payload_download", "network_c2",
    "c2_beacon", "c2_connection", "http_upload", "network_exfiltration",
    "suspicious_url_endpoint", "url_present",
))


def _record_value(record: object, name: str, replacement: object = "") -> object:
    if type(record) is dict:
        return dict.get(record, name, replacement)
    data = no_hook_plain_instance_dict(record)
    if data is not None:
        return dict.get(data, name, replacement)
    return replacement


def _record_text(record: object, name: str, replacement: str = "") -> str:
    return detection_enrichment_text_or_empty(_record_value(record, name, replacement), default=replacement)


def _lowered_sequence_text(value: object) -> str:
    parts = []
    for item in enrichment_sequence(value):
        text = detection_enrichment_text_or_empty(item)
        if text:
            parts.append(text.lower())
    return " ".join(parts)


def _decoded_tag(name: str, suffix: str) -> str:
    return "decoded_" + name + suffix


def _coerce_records(decoded_payloads: object=None) -> object:
    if decoded_payloads is None:
        return ()
    if isinstance(decoded_payloads, (list, tuple)):
        return tuple(decoded_payloads)
    return (decoded_payloads,)


def _semantic_behavior_tags(record: object, contextual_tags: object) -> object:
    tags = []
    enc = _record_text(record, "encoding", "encoded") or "encoded"
    chain = _lowered_sequence_text(_record_value(record, "decode_chain", ()))
    low = _record_text(record, "text").lower()
    dtset = {text.lower() for text in (detection_enrichment_text_or_empty(tag) for tag in enrichment_sequence(contextual_tags)) if text}
    is_base64 = "base64" in enc.lower() or "base64" in chain
    if is_base64:
        tags.extend(["decoded_base64_blob", "decoded_base64_data"])
    if _record_value(record, "binary_magic", ""):
        magic = _record_text(record, "binary_magic", "binary") or "binary"
        tags.extend(["payload_decode_candidate", "decoded_binary_payload", _decoded_tag(magic, "_payload")])
        if is_base64:
            tags.extend(["encoded_payload", "decoded_base64_binary_payload", "payload_decode_confirmed"])
    if low:
        tags.extend(["payload_decode_candidate", _decoded_tag(enc, "_payload"), "decoded_payload_rescanned"])
    exec_needles = (
        "subprocess", "os.system", "createprocess", "shellexecute",
        "start-process", "powershell", "cmd.exe", "iex", "invoke-expression",
        "eval(", "exec(", "assembly.load", "virtualalloc",
        "writeprocessmemory", "createremotethread", "child_process",
    )
    if dtset & _EXECUTION_TAGS or any(needle in low for needle in exec_needles):
        tags.extend([
            "encoded_payload", "script_execution",
            "payload_decode_confirmed", "encoded_payload_candidate",
            "process_exec", "payload_decode_candidate",
            "embedded_base64_payload",
        ])
    net_needles = (
        "http://", "https://", "downloadstring", "downloadfile",
        "invoke-webrequest", "urlopen", "requests.post", "webhook",
        "api.telegram.org", "socket.create_connection", "fetch(",
    )
    if dtset & _NETWORK_TAGS or any(needle in low for needle in net_needles):
        tags.extend(["network_download", "network_activity"])
    if "script_execution" in tags and "network_download" in tags:
        tags.extend(["remote_payload_download", "payload_execution"])
    return tags


def decoded_payload_tags(strings_blob: object, path: object=None, *, finalize: object=True, decoded_payloads: object=None) -> object:
    """Interpret scanner-observed decoded payload records.

    ``strings_blob`` is treated as an already-observed text view.  Raw payload
    decoding must occur in scanners and be supplied through ``decoded_payloads``.
    """
    tags = []
    try:
        records = _coerce_records(decoded_payloads)
        observed_text = detection_enrichment_text_or_empty(strings_blob)
        if not records and observed_text:
            records = ({"text": observed_text, "encoding": "observed_text", "decode_chain": ()},)
        for rec in records:
            if _record_value(rec, "failure_tags", ()):
                tags.extend(["decoded_payload_failure_evidence", "detection_stage_degraded"])
                continue
            text = _record_text(rec, "text")
            if not text:
                continue
            enc = _record_text(rec, "encoding", "encoded") or "encoded"
            dtags = contextual_scan_runtime.contextual_tag_scan(
                contextual_scan_runtime.ContextualTagScanRequest(
                    strings_blob=text,
                    path=path,
                    source="payload_decode_candidate",
                    finalize=finalize,
                )
            )
            behavior_tags = _semantic_behavior_tags(rec, dtags)
            tags.extend(behavior_tags)
            if dtags:
                tags.extend(["payload_decode_candidate", _decoded_tag(enc, "_payload"), "decoded_payload_rescanned"])
                tags.extend(dtags)
                dtset = {text.lower() for text in (detection_enrichment_text_or_empty(t) for t in enrichment_sequence(dtags)) if text}
                if dtset & _EXECUTION_TAGS:
                    tags.extend(["encoded_payload", "encoded_payload_candidate", "payload_decode_confirmed"])
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        tags.extend(["decoded_payload_failure_evidence", "detection_stage_degraded"])
    if finalize:
        return ordered_unique_tags(tags)
    return list(tags or [])


__all__ = ("decoded_payload_tags",)
