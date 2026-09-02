"""RPA member behavior text-to-tag projection with no caller hooks."""

from __future__ import annotations

from Virus_Scan.scanners.archives.rpa_member_no_hook import rpa_member_owned_text
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE

_FAILURE_TEXT_MARKERS = frozenset({
    "rpa_member_text_decode_failure",
    "rpa_pickle_payload_record_failure",
    "rpa_embedded_payload_record_failure",
    "rpa_member_record_text_unsafe",
    "rpa_member_record_failure_tags_unsafe",
    "rpa_member_record_unsupported",
    "rpa_member_payload_unsafe",
    "rpa_member_name_unsafe",
    "rpa_member_meta_unsafe",
    "rpa_member_subkind_unsafe",
    "rpa_member_view_sequence_unsafe",
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    DETECTION_STAGE_DEGRADED_TAG,
})


def _append_payload_behavior_tags(tags: list[str], text: str) -> None:
    if "exec(" in text and (
        "zlib.decompress" in text
        or "base64.b64decode" in text
        or "marshal.loads" in text
    ):
        tags.extend([
            "embedded_payload_execution",
            "encoded_payload_execution",
            "script_execution",
            "payload_decode_confirmed",
        ])
    if "appdata" in text and "renpy" in text and "tokens" in text:
        tags.extend(["appdata_token_dropper", "token_drop_path", "persistence_marker"])
    if "zipfile" in text and ("extractall" in text or ".extract" in text):
        tags.extend(["archive_extract_and_execute", "dropper_behavior"])


def _append_network_behavior_tags(tags: list[str], text: str) -> None:
    if "ethereum" in text or "sepolia" in text or "eth_call" in text or "jsonrpc" in text:
        tags.extend(["blockchain_c2", "ethereum_rpc_c2", "network_activity"])
    has_download_api = (
        "urlopen" in text
        or "urlretrieve" in text
        or "requests.get" in text
        or "urllib.request" in text
    )
    has_download_target = ".zip" in text or ".exe" in text or "eth_call" in text or "http" in text
    if has_download_api and has_download_target:
        tags.extend(["remote_payload_download", "network_download_execute"])


def _append_process_behavior_tags(tags: list[str], text: str) -> None:
    if (
        "subprocess.popen" in text
        or "creationflags=0x00000008" in text
        or "create_no_window" in text
    ):
        tags.extend(["process_exec", "hidden_process_exec", "dropper_behavior"])
    if "time.sleep" in text or "threading.thread" in text:
        tags.extend(["delayed_execution", "background_thread_execution"])
    if "os.remove" in text or "shutil.rmtree" in text:
        tags.extend(["cleanup_behavior", "dropper_cleanup"])


def append_behavior_tags(tags: list[str], text: str) -> None:
    low, reason = rpa_member_owned_text(text, "rpa_member_behavior_text_unsafe")
    if reason:
        tags.extend([reason, "rpa_failure_evidence_recorded", "archive_final_json_must_record"])
        return
    low = low.lower()
    if not low:
        return
    if low in _FAILURE_TEXT_MARKERS or low.startswith("scanner_failure_evidence:") or low.endswith("_final_json_must_record"):
        tags.extend([low, "rpa_failure_evidence_recorded", "archive_final_json_must_record"])
        return
    _append_payload_behavior_tags(tags, low)
    _append_network_behavior_tags(tags, low)
    _append_process_behavior_tags(tags, low)


__all__ = ("append_behavior_tags",)
