from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
# Real module split from v27c for scanners/rpgm.py.
# Functionality lives here; shared state is synchronized through this subsystem state module.
from pathlib import Path
import re

# Stage 27 explicit bootstrap-safe dependencies; scanners no longer rely on
# init_runtime injecting these callables into module globals.
from Virus_Scan.runtime.api import log_error, read_file_bytes, record_detector_error
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.utils.tagging import ordered_unique_tags

from Virus_Scan.runtime.api import is_programmer_error, scanner_failure_tags
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.rpgm_json import queue_read_json_file

from Virus_Scan.heuristics import evaluate_game_engine_threats
from Virus_Scan.utils.fast_assets import recover_rpgm_encrypted_sample
from Virus_Scan.scanners.binary_appended_payload import scan_appended_payload
from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot

_ENGINE_POLICY = load_engine_policy_snapshot()

def _global_raw_rpgm_js_ast_header(path: object) -> object:
    p = Path(path)
    norm_path = str(p).replace("\\", "/").lower()
    tags = []
    if p.suffix.lower() == ".js":
        tags.append("javascript_file")
    if "/www/js/plugins/" in norm_path or "/plugins/" in norm_path:
        tags += ["rpgm_plugin_js", "rpgm_javascript"]
    return {"tags": tags}


def _queue_read_json_file(path: object, default: object = None) -> object:
    """Queue-specific JSON reader; explicit name documents that retries are expected."""
    return queue_read_json_file(path, default=default)


def _append_rpgm_engine_verdict(
    tags: list[object],
    text: str,
    path: object,
    engine_threat_evaluator: object,
    error_source: str,
) -> None:
    try:
        verdict = engine_threat_evaluator(text, path=str(path), engine="rpgm")
        tags.extend(verdict.get("tags") or [])
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        record_detector_error("rpgm_" + error_source, exc, path=path)
        tags.extend(scanner_failure_tags("scan_rpgm_file." + error_source, exc, tags))


def _append_decrypted_rpgm_sample_tags(
    tags: list[object],
    sample: bytes,
    path: object,
    engine_threat_evaluator: object,
) -> None:
    sample_low = sample.lower()
    sample_text = sample.decode("latin1", errors="ignore")
    if any(
        marker.encode("latin1", errors="ignore") in sample_low
        for marker in _ENGINE_POLICY.rpgm_encrypted_media_url_markers
    ):
        tags.extend(["rpgm_decrypted_media_url_reference", "asset_metadata_reference"])
    if any(
        token.encode("latin1", errors="ignore") in sample_low
        for token in _ENGINE_POLICY.rpgm_decrypted_media_suspicious_tokens
    ):
        tags.extend([
            "rpgm_decrypted_media_suspicious_string",
            "asset_deep_scan_escalated",
            "embedded_command_or_url",
        ])
    try:
        payload_tags: list[object] = []
        scan_appended_payload(sample, payload_tags)
        if payload_tags:
            tags.extend(["rpgm_decrypted_media_payload_checked", *payload_tags])
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        record_detector_error("rpgm_decrypted_media_payload", exc, path=path)
        tags.extend(scanner_failure_tags("scan_rpgm_file.decrypted_media_payload", exc, tags))
    _append_rpgm_engine_verdict(
        tags,
        sample_text,
        path,
        engine_threat_evaluator,
        "decrypted_game_engine_threats",
    )


def _append_encrypted_rpgm_tags(
    tags: list[object],
    data: bytes,
    path: object,
    engine_threat_evaluator: object,
) -> None:
    recovered = recover_rpgm_encrypted_sample(
        path,
        header=data[:64],
        ext=get_scan_extension(path),
    )
    tags.extend(recovered.get("tags") or [])
    probe = recovered.get("probe") or {}
    tags.extend(probe.get("tags") or [])
    sample = bytes(recovered.get("sample") or b"")
    if sample:
        _append_decrypted_rpgm_sample_tags(tags, sample, path, engine_threat_evaluator)


def _append_rpgm_semantic_tags(tags: list[object], data: bytes, text: str) -> None:
    if b"rgss" in data.lower():
        tags.append("rgss_runtime")
    semantic_text = re.sub(
        r"\b(?:no|not|without|never)\s+(?:[a-z0-9_./\\-]+\s+){0,3}(?:eval|function|child_process)",
        " ",
        text,
        flags=re.IGNORECASE,
    )
    semantic_low = semantic_text.lower().encode("latin1", errors="ignore")
    if b"eval(" in semantic_low or b"function(" in semantic_low or b"new function" in semantic_low:
        tags.append("script_eval")
    if b"child_process" in semantic_low:
        tags.append("rpgm_nwjs_process_exec")


def scan_rpgm_file(path: object, *, engine_threat_evaluator: object = evaluate_game_engine_threats, read_bytes: object = read_file_bytes) -> object:
    """Scan RPGM/NW.js files with runtime markers plus malicious-chain semantics."""
    tags: list[object] = ["rpgm"]
    try:
        data = read_bytes(path)
    except SCAN_CONTENT_ERRORS as exc:
        if is_programmer_error(exc):
            raise
        log_error(scanner_contract_join('scan_rpgm_file input read failed: ', scanner_contract_error_message(exc)))
        return ordered_unique_tags(scanner_failure_tags("scan_rpgm_file.read", exc, tags))

    text = data.decode("latin1", errors="ignore")
    if data.startswith((b"RPGMV", b"RPGMZ")):
        _append_encrypted_rpgm_tags(tags, data, path, engine_threat_evaluator)
    _append_rpgm_semantic_tags(tags, data, text)
    _append_rpgm_engine_verdict(
        tags,
        text,
        path,
        engine_threat_evaluator,
        "game_engine_threats",
    )
    return ordered_unique_tags(tags)


def global_raw_rpgm_js_ast_header(path: object) -> object:
    """Public RPGM-scanner contract for raw JavaScript AST header extraction."""
    return _global_raw_rpgm_js_ast_header(path)
