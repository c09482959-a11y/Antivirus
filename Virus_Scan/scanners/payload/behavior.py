"""Decoded payload behavior tag projection."""
from __future__ import annotations


from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.scanners.contracts import scanner_failure_evidence_tags

def decoded_payload_behavior_tags(rec: dict[str, object], dtags: list[str] | tuple[str, ...] | set[str] | None = None) -> list[str]:
    """Classify bounded decoded payload records into behavior tags.

    The payload decoder owns this classification because the inputs are decoder
    records, not scanner text state. Base64 presence remains weak unless the
    decoded record contains script, execution, network, or binary payload
    evidence.
    """
    tags: list[str] = []
    try:
        record = rec or {}
        enc = str(record.get("encoding", "")).lower()
        chain = " ".join(str(item).lower() for item in record.get("decode_chain") or [])
        is_b64 = "base64" in enc or "base64" in chain
        if not is_b64:
            return tags
        low = str(record.get("text", "")).lower()
        detected = {str(tag).lower() for tag in dtags or []}
        tags.extend(["decoded_base64_blob", "decoded_base64_data"])
        if record.get("binary_magic"):
            tags.extend(["encoded_payload", "decoded_base64_binary_payload", "payload_decode_candidate", "payload_decode_confirmed"])
        script_needles = (
            "#!/", "import ", "def ", "function ", "var ", "const ", "class ",
            "powershell", "cmd.exe", "subprocess", "os.system", "eval(", "exec(",
            "assembly.load", "frombase64string", "child_process",
        )
        script_tags = {
            "script_execution", "powershell_exec", "cmd_exec", "python_exec",
            "javascript_execution", "bytecode_exec", "bytecode_eval",
        }
        if any(needle in low for needle in script_needles) or detected & script_tags:
            tags.extend(["decoded_base64_script", "decoded_payload_observed", "decoded_payload_rescanned"])
        exec_tags = {
            "process_exec", "cmd_exec", "powershell_exec", "script_execution",
            "payload_execution", "fileless_execution", "in_memory_execution",
            "assembly_load", "reflection", "mshta_exec", "wscript_exec", "cscript_exec",
            "rundll32_exec", "regsvr32_exec", "certutil_exec", "bytecode_exec",
            "bytecode_eval", "dynamic_execution", "process_injection",
        }
        exec_needles = (
            "subprocess", "os.system", "createprocess", "shellexecute",
            "start-process", "powershell", "cmd.exe", "iex", "invoke-expression",
            "eval(", "exec(", "assembly.load", "virtualalloc",
            "writeprocessmemory", "createremotethread", "child_process",
        )
        if detected & exec_tags or any(needle in low for needle in exec_needles):
            tags.extend([
                "encoded_payload", "script_execution",
                "payload_decode_confirmed", "encoded_payload_candidate",
                "process_exec", "payload_decode_candidate",
                "embedded_base64_payload",
            ])
        net_tags = {
            "network_download", "remote_payload_download", "network_c2", "c2_beacon",
            "c2_connection", "http_upload", "network_exfiltration",
            "suspicious_url_endpoint",
        }
        net_needles = (
            "http://", "https://", "downloadstring", "downloadfile",
            "invoke-webrequest", "urlopen", "requests.post", "webhook",
            "api.telegram.org", "socket.create_connection", "fetch(",
        )
        if detected & net_tags or any(needle in low for needle in net_needles):
            tags.extend(["network_download", "network_activity"])
    except SCAN_CONTENT_ERRORS as exc:
        return scanner_failure_evidence_tags(
            "payload_decode",
            "decoded_payload_behavior",
            exc,
            [*tags, 'decoded_payload_behavior_error'],
            error_category="payload_decode_failure",
        )
    return tags

__all__ = ("decoded_payload_behavior_tags",)
