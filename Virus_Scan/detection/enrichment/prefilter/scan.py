"""Strict raw fast-prefilter scan owner.

Owns the pre-expensive-scan raw text prefilter only. Suspicious evidence is
returned to force the canonical full detection pipeline instead of hiding it.
"""
from __future__ import annotations

import re
from pathlib import Path
from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.utils.text_validation import text_boundary_value
from Virus_Scan.utils.entropy import strict_fast_entropy
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.prefilter.game_engine_terminal import terminal_prefilter_result
from Virus_Scan.detection.enrichment.prefilter.state import append_prefilter_failure, new_prefilter_info
from Virus_Scan.detection.models.detection_result import build_fast_benign_detection_result
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.tags.heuristics.strict_prefilter_policy import STRICT_FAST_PREFILTER_TAG_MAP
from Virus_Scan.detection.registries.prefilter_defaults import (
    STRICT_FAST_BENIGN_BINARY_MAGIC,
    STRICT_FAST_BENIGN_BYPASS_VERSION,
    STRICT_FAST_BENIGN_DENY_TOKENS,
    STRICT_FAST_BENIGN_EXTENSIONS,
    STRICT_FAST_BENIGN_MAX_BYTES,
)
from Virus_Scan.detection.attack.api import official_attack_fast_path_policy
from Virus_Scan.utils.stages import normalize_stage


PLR2004N0_97 = 0.97
PLR2004N126 = 126
PLR2004N240 = 240
PLR2004N32 = 32
PLR2004N5_2 = 5.2


class _PrefilterReadFailure:
    """Typed sentinel for explicit prefilter read failure evidence."""


class _TerminalPrefilterFailure:
    """Typed sentinel for explicit terminal prefilter failure evidence."""


PREFILTER_READ_FAILED = _PrefilterReadFailure()
TERMINAL_PREFILTER_FAILED = _TerminalPrefilterFailure()


def _record_failure(info: dict, *, stage_name: str, error_source: str, error: BaseException, path: object) -> None:
    path_text = text_boundary_value(path, unsupported="") or ""
    append_prefilter_failure(
        info,
        stage_name=stage_name,
        error_source=error_source,
        error=error,
        affected_context=path_text,
    )


def _read_prefilter_text(
    path: object,
    ext: str,
    info: dict,
    *,
    artifact_read_snapshot: object,
    entropy_func: object=strict_fast_entropy,
) -> bytes | None | _PrefilterReadFailure:
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    size = snapshot.size if snapshot.complete else 0
    info["meta"]["size"] = size
    if size <= 0 or size > STRICT_FAST_BENIGN_MAX_BYTES:
        return None
    data = snapshot.read_prefix(STRICT_FAST_BENIGN_MAX_BYTES + 1)
    if not data or len(data) > STRICT_FAST_BENIGN_MAX_BYTES:
        return None
    if ext not in STRICT_FAST_BENIGN_EXTENSIONS:
        return data
    if any(data.startswith(marker) for marker in STRICT_FAST_BENIGN_BINARY_MAGIC):
        return None
    nul_ratio = data.count(b"\x00") / max(1, len(data))
    info["meta"]["nul_ratio"] = round(float(nul_ratio), 5)
    if nul_ratio > 0.0:
        return None
    printable = sum(1 for byte in data if byte in (9, 10, 13) or PLR2004N32 <= byte <= PLR2004N126)
    printable_ratio = printable / max(1, len(data))
    info["meta"]["printable_ratio"] = round(float(printable_ratio), 5)
    if printable_ratio < PLR2004N0_97:
        return None
    entropy = entropy_func(data)
    info["meta"]["entropy"] = round(float(entropy), 4)
    if entropy >= PLR2004N5_2:
        return None
    return data


def _apply_terminal_prefilter(
    path: object,
    text: str,
    info: dict,
    *,
    reason: str,
    version: str,
    confidence: float,
    attack_hit: str,
    stage_name: str,
    terminal_func: object=terminal_prefilter_result,
) -> bool | _TerminalPrefilterFailure:
    try:
        fast_result = terminal_func(
            path=path,
            text=text,
            meta=info["meta"],
            reason=reason,
            version=version,
            confidence=confidence,
            attack_hit=attack_hit,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        _record_failure(info, stage_name=stage_name, error_source="evaluate_game_engine_threats", error=error, path=path)
        return TERMINAL_PREFILTER_FAILED
    if fast_result is None:
        return False
    info["fast_result"] = fast_result
    return True


def _collect_deny_hits(text: str, info: dict) -> list[str]:
    low = text.lower()
    hits = [token for token in STRICT_FAST_BENIGN_DENY_TOKENS if token in low]
    if re.search(r"[A-Za-z0-9+/]{80,}={0,2}", text):
        hits.append("encoded_blob")
        info["tags"].append("encoded_content")
    if re.search(r"(?:\\x[0-9a-fA-F]{2}){8,}", text):
        hits.append("hex_escape_blob")
        info["tags"].append("encoded_content")
    return hits


def strict_fast_prefilter(
    path: object,
    compiled_rules: object = None,
    *,
    artifact_read_snapshot: object,
    entropy_func: object = strict_fast_entropy,
) -> object:
    """
    Minimal raw-string prefilter used before the expensive full pipeline.

    It is still strict: it only returns a fast benign result when the raw file is
    boring text AND no suspicious deny tokens/encoded blobs/binary markers exist.
    If suspicious tokens are present, it returns tags/hits that force full scan.
    """
    require_artifact_read_snapshot(artifact_read_snapshot, path)
    info = new_prefilter_info()
    try:
        if compiled_rules is not None:
            return info
        fast_path_allowed, fast_path_model_evidence = official_attack_fast_path_policy()
        if not fast_path_allowed:
            info["meta"]["mitre_full_pipeline_required"] = True
            return info
        path_text = text_boundary_value(path, unsupported="") or ""
        if not path_text:
            info["meta"]["extension"] = ""
            _record_failure(
                info,
                stage_name="strict_fast_prefilter_path",
                error_source="strict_fast_prefilter.path",
                error=ValueError("strict_fast_prefilter_path_rejected"),
                path=path,
            )
            return info
        file_path = Path(path_text)
        ext = file_path.suffix.lower()
        info["meta"]["extension"] = ext
        data = _read_prefilter_text(
            path,
            ext,
            info,
            artifact_read_snapshot=artifact_read_snapshot,
            entropy_func=entropy_func,
        )
        if not isinstance(data, bytes):
            return info
        text = data.decode("utf-8", errors="ignore") or data.decode("latin1", errors="ignore")
        if not text:
            return info
        if ext not in STRICT_FAST_BENIGN_EXTENSIONS:
            _apply_terminal_prefilter(
                path,
                text,
                info,
                reason="stage34_explicit_game_engine_malicious_chain",
                version="stage34_game_engine_terminal_prefilter",
                confidence=0.88,
                attack_hit="stage34_explicit_game_engine_chain",
                stage_name="prefilter_non_strict_game_engine_terminal",
            )
            return info
        terminal_status = _apply_terminal_prefilter(
            path,
            text,
            info,
            reason="stage24_explicit_game_engine_malicious_chain",
            version="stage24_game_engine_terminal_prefilter",
            confidence=0.86,
            attack_hit="stage24_explicit_game_engine_chain",
            stage_name="prefilter_game_engine_terminal",
        )
        if terminal_status is TERMINAL_PREFILTER_FAILED:
            return info
        if terminal_status:
            return info
        hits = _collect_deny_hits(text, info)
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if lines and max(len(line) for line in lines) > PLR2004N240:
            info["meta"]["long_line"] = max(len(line) for line in lines)
            return info
        if hits:
            info["hits"] = sorted(set(hits))
            tag_accum = []
            for hit in info["hits"]:
                tag_accum.extend(STRICT_FAST_PREFILTER_TAG_MAP.get(hit, []))
            info["tags"] = normalize_tags(sorted(set(info["tags"] + tag_accum + ["strict_fast_prefilter_hit"])))
            return info
        current_stage = normalize_stage(ext)
        info["fast_result"] = build_fast_benign_detection_result(
            path=path,
            score=3.0,
            confidence=0.2,
            tags=normalize_tags(["strict_fast_benign_bypass", f"router_stage_{current_stage}", "fast_path_non_learning"]),
            prefilter_tags=[],
            effective_stage=current_stage,
            reason="strict_fast_prefilter_boring_text",
            version=STRICT_FAST_BENIGN_BYPASS_VERSION,
            constraints=dict(info["meta"], yara_active=False, prefilter=True),
            model_evidence=fast_path_model_evidence,
            yaralight_active=False,
        )
        info["force_full"] = False
        return info
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        _record_failure(info, stage_name="strict_fast_prefilter", error_source="strict_fast_prefilter", error=error, path=path)
        return info


__all__ = ("strict_fast_prefilter",)
