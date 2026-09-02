"""Static rule tables for compact evidence line extraction."""

DECODE_TAGS = frozenset({
    "payload_decode_candidate",
    "decoded_payload_observed",
    "payload_decode",
    "base64_decode",
    "base64_blob",
    "encoded_content",
    "encoded_payload_candidate",
    "payload_decode_confirmed",
    "evidence_link:decode_observed",
    "evidence_link:decoded_payload_to_execution",
    "evidence_link:decoded_payload_to_network",
    "js_decoded_payload_rescanned",
})

EMBEDDED_PAYLOAD_TAGS = frozenset({
    "embedded_gzip_payload",
    "embedded_zlib_payload",
    "embedded_archive_payload",
    "embedded_pe_payload",
    "embedded_executable_marker",
    "asset_embedded_archive_marker",
    "archive_dropper",
    "dropper_behavior",
})

PICKLE_TAGS = frozenset({
    "pickle_opcode_graph_analyzed",
    "pickle_dangerous_global",
    "pickle_callable_reference",
    "pickle_reduce_opcode",
    "pickle_stack_global",
    "pickle_external_executable_reference",
    "pickle_external_script_reference",
    "pickle_deserialization_context",
    "pickle_fast_exec_context",
    "pickle_fast_text_hint",
})

PICKLE_OBSERVATION_NAMES = (
    "pickle_dangerous_global",
    "pickle_callable_reference",
    "pickle_reduce_opcode",
    "pickle_stack_global",
    "pickle_external_executable_reference",
    "pickle_external_script_reference",
    "pickle_opcode_graph_analyzed",
)


PICKLE_PATTERNS = (
    "(?:os|posix|nt)\\s*[\\.\\n]\\s*(?:system|popen|spawn|execl)[^\\r\\n]{0,120}",
    "subprocess\\s*[\\.\\n]\\s*(?:popen|call|run|check_output)[^\\r\\n]{0,120}",
    "builtins\\s*[\\.\\n]\\s*(?:eval|exec)[^\\r\\n]{0,120}",
    "GLOBAL\\s+[^\\r\\n]{1,100}",
    "(?:REDUCE|STACK_GLOBAL|OBJ|INST)[^\\r\\n]{0,100}",
)

EVIDENCE_RULES = (
    ("Script", frozenset({"script_execution", "powershell_exec", "encoded_powershell", "cmd_exec", "wscript_exec", "cscript_exec", "mshta_exec", "lolbin_execution", "process_exec", "code_execution", "bytecode_exec", "bytecode_eval"}), (r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|subprocess\.(?:popen|run|call)|os\.system|eval\s*\(|exec\s*\()[^\r\n\x00]{0,240}",)),
    ("PowerShell", frozenset({"powershell_exec", "encoded_powershell", "powershell_encoded_command"}), (r"powershell(?:\.exe)?[^\r\n\x00]{0,260}", r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}")),
    ("Command", frozenset({"cmd_exec", "process_exec", "shell_exec"}), (r"cmd(?:\.exe)?\s*/[cq][^\r\n\x00]{0,220}", r"(?:/bin/sh|/bin/bash|sh\s+-c|bash\s+-c)[^\r\n\x00]{0,220}")),
    ("LOLBin", frozenset({"lolbin_execution", "certutil_exec", "bitsadmin_exec", "rundll32_exec", "regsvr32_exec", "mshta_exec", "wmic_exec"}), (r"(?:certutil|bitsadmin|rundll32|regsvr32|mshta|wmic)(?:\.exe)?[^\r\n\x00]{0,240}",)),
    ("Registry", frozenset({"registry_persistence", "run_key_persistence", "registry_run_key", "persistence"}), (r"(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)\\[^\r\n\x00]{0,240}", r"Software\\Microsoft\\Windows\\CurrentVersion\\Run[^\r\n\x00]{0,200}")),
    ("ScheduledTask", frozenset({"scheduled_task", "schtasks_create", "persistence_schtasks"}), (r"schtasks(?:\.exe)?[^\r\n\x00]{0,260}",)),
    ("Injection", frozenset({"process_injection", "pe_injection_api", "remote_thread", "memory_write_exec"}), (r"(?:VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|QueueUserAPC|VirtualProtect|NtWriteVirtualMemory|SetThreadContext)[^\r\n\x00]{0,160}",)),
    ("Credential", frozenset({"credential_access", "lsass_dump", "comsvcs_lsass_dump", "credential_dumping"}), (r"(?:lsass|comsvcs\.dll|MiniDump|MiniDumpWriteDump|sekurlsa|mimikatz)[^\r\n\x00]{0,220}",)),
    ("Crypto", frozenset({"crypto_wallet", "ethereum", "wallet_access", "token_theft", "browser_token_access"}), (r"(?:ethereum|bitcoin|wallet|metamask|exodus|electrum|tokens?|local storage|Login Data)[^\r\n\x00]{0,220}",)),
    ("Download", frozenset({"network_download", "remote_resource_fetch", "asset_resource_fetch", "browser_xhr_fetch"}), (r"(?:download|string|fetch|XMLHttpRequest|xhr|requests\.get|urllib\.request|WebClient|curl|wget)[^\r\n\x00]{0,220}", r"https?://[^\s'\"<>\)\]}]{3,220}")),
    ("FileWrite", frozenset({"file_drop", "dropper_behavior", "archive_dropper", "writes_executable", "external_file_reference"}), (r"(?:write|open|extract|drop|copyfile|CreateFile|File\.WriteAllBytes)[^\r\n\x00]{0,220}",)),
    ("Eval", frozenset({"eval_exec", "dynamic_eval", "javascript_eval", "bytecode_eval", "code_execution"}), (r"(?:eval\s*\(|exec\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\()[^\r\n\x00]{0,220}",)),
)
