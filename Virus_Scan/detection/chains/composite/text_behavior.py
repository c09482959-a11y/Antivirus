"""Canonical detection classification owner for chain text behavior predicates."""

from Virus_Scan.detection.contracts.string_predicates import context_regex as _ctx_re
from Virus_Scan.detection.contracts.string_predicates import has_any_text as _has_any_text, has_command_exec_behavior as _has_command_exec_behavior, has_lolbin_script_behavior as _has_lolbin_script_behavior
from Virus_Scan.detection.registries.chain_registry import (
    ARCHIVE_DROPPER_TERMS,
    C2_TASKING_TERMS,
    REMOTE_PAYLOAD_DOWNLOAD_TERMS,
    REMOTE_PAYLOAD_FILE_TERMS,
)


def has_c2_behavior(text: object) -> object:
    """Return whether text contains a validated command-and-control behavior pattern."""
    has_channel = bool(
        _ctx_re(r"\b(?:https?|ftp|ws|wss)://", text)
        or _ctx_re(r"\b(?:socket\.connect|tcpclient|recv\(|send\()", text)
    )
    tasking = _has_any_text(text, C2_TASKING_TERMS) or (
        _has_any_text(text, ["recv(", "send("])
        and _has_any_text(text, ["command", "cmd", "task", "shell", "beacon", "implant"])
    )
    webhook_exfil = _has_any_text(text, ["discord.com/api/webhooks", "api.telegram.org"]) and _has_any_text(
        text, ["token", "password", "cookie", "wallet", "authorization"]
    )
    return bool((has_channel and tasking) or webhook_exfil)


def has_archive_dropper_behavior(text: object) -> object:
    """Return whether text contains archive extraction followed by execution/drop behavior."""
    return bool(
        _has_any_text(text, ARCHIVE_DROPPER_TERMS)
        and (_has_command_exec_behavior(text) or _has_any_text(text, ["extractall", "writefile", "open(", "temp", "appdata"]))
    )


def has_payload_download_behavior(text: object) -> object:
    """Return whether text contains payload download behavior with payload or execution context."""
    has_url = bool(_ctx_re(r"\b(?:https?|ftp)://", text))
    if not has_url:
        return False
    fetch_tool = _has_any_text(text, REMOTE_PAYLOAD_DOWNLOAD_TERMS) or _ctx_re(
        r"\b(?:urlopen|internetopenurl|urldownloadtofile|winhttpopenrequest)\b", text
    )
    payload_name = _has_any_text(text, REMOTE_PAYLOAD_FILE_TERMS)
    exec_after = _has_command_exec_behavior(text) or _has_lolbin_script_behavior(text)
    return (fetch_tool is True) and ((payload_name is True) or (exec_after is True))
