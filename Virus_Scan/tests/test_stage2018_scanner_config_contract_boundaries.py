from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.config.loader_paths import _config_load_failure
from Virus_Scan.scanners.contracts.binary_result import (
    BinaryAnalysisResult,
    BinaryMalformedRequest,
)
from Virus_Scan.scanners.contracts.payload_result import (
    PayloadDecodeResult,
    PayloadFailureRequest,
)
from Virus_Scan.scanners.contracts.scanner_evidence import ScannerFailureEvidence
from Virus_Scan.scanners.dotnet_identity import dotnet_behavior_tags, dotnet_extension_tags, dotnet_metadata_present
from Virus_Scan.scanners.engine_context import infer_engine_context, merge_engine_context_with_runtime_hint
from Virus_Scan.scanners.entropy import _entropy_exception_result
from Virus_Scan.scanners.il_pipeline import analyze_il_pipeline, extract_il_patterns


class HostileValue:
    def __str__(self):  # pragma: no cover - must not run
        raise AssertionError("__str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not run
        raise AssertionError("__repr__ hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not run
        raise AssertionError("__format__ hook executed")

    def __bool__(self):  # pragma: no cover - must not run
        raise AssertionError("__bool__ hook executed")

    def __iter__(self):  # pragma: no cover - must not run
        raise AssertionError("__iter__ hook executed")


class HostileException(Exception):
    def __str__(self):  # pragma: no cover - must not run
        raise AssertionError("exception __str__ hook executed")

    def __repr__(self):  # pragma: no cover - must not run
        raise AssertionError("exception __repr__ hook executed")


_REPAIRED_SNIPPETS = (
    'error_source=f"scanner_config.{config_name}_loader",',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("binary_policy", str(path or _DEFAULT_BINARY_POLICY), "unknown binary policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("archive_policy", str(path or _DEFAULT_ARCHIVE_POLICY), "unknown archive policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("scanner_limits_policy", str(path or _DEFAULT_SCANNER_LIMITS_POLICY), "unknown scanner limits policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("payload_policy", str(path or _DEFAULT_PAYLOAD_POLICY), "unknown payload policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("pickle_policy", str(path or _DEFAULT_PICKLE_POLICY), "unknown pickle policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("raw_chunk_policy", str(path or _DEFAULT_RAW_CHUNK_POLICY), "unknown raw chunk policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("text_policy", str(path or _DEFAULT_TEXT_POLICY), "unknown text policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("filetype_policy", str(path or _DEFAULT_FILETYPE_POLICY), "unknown filetype policy failure"))',
    'raise ScannerConfigError(result.failure or ScannerConfigFailure("engine_policy", str(path or _DEFAULT_ENGINE_POLICY), "unknown engine policy failure"))',
    'object.__setattr__(self, "scanner_name", str(self.scanner_name or "binary"))',
    'object.__setattr__(self, "encoding", str(self.encoding or "payload"))',
    'for key, item in dict.items(value)',
    'key_text = f"{key_text}#{index}"',
    'scanner_name=str(scanner_name or "scanner"),',
    'stage_tag = f"{str(stage or \'scanner\').strip().lower()}_scan_error"',
    'evidence_tag = f"scanner_failure_evidence:{str(scanner_name or \'scanner\').strip().lower()}:{str(stage or \'unknown\').strip().lower()}"',
    "logger(f'scan_unity_dotnet_layered_file failed for {path}: {e}')",
    "low = str(blob or '').lower()",
    "if str(ext or '').lower() in DOTNET_EXTENSION_MISMATCH_EXTENSIONS:",
    'return frozenset(str(item).lower() for item in values or ())',
    'total = sum(scores.values()) + 1e-06',
    'return {key: safe_clamp(float(value) / total, 0.0, 1.0) for key, value in scores.items()}',
    'blob_l = str(strings_blob or "").lower()',
    'path_l = str(file_structure or "").lower().replace("\\\\", "/")',
    'for engine, raw_cues in dict(_ENGINE_POLICY.engine_file_context_cues).items():',
    'ctx = dict(engine_context or {})',
    'hint_ctx = dict(snapshot.scan_engine_hint_context or {})',
    'hint = str(snapshot.scan_engine_hint or "auto").lower()',
    "'score': safe_clamp(score),",
    "reasons.append(f'high entropy {entropy_value:.2f}')",
    "reasons.append(f'very high entropy {entropy_value:.2f}')",
    "'reasons': [f\"packer marker {marker.decode(errors='ignore')}\"],",
    "binary_log_message(f'packer entropy anomaly failed: {exc}')",
    'text = str(strings_blob or "")',
    'for tag, weight in _BEHAVIOR_TAG_WEIGHTS.items():',
    '"path": str(path or ""),',
)

_REPAIRED_FILES = (
    Path("Virus_Scan/scanners/config/loader_paths.py"),
    Path("Virus_Scan/scanners/config/loader_policy_binary_archive.py"),
    Path("Virus_Scan/scanners/config/loader_policy_core.py"),
    Path("Virus_Scan/scanners/contracts/binary_result.py"),
    Path("Virus_Scan/scanners/contracts/payload_result.py"),
    Path("Virus_Scan/scanners/contracts/scanner_evidence.py"),
    Path("Virus_Scan/scanners/dotnet.py"),
    Path("Virus_Scan/scanners/dotnet_identity.py"),
    Path("Virus_Scan/scanners/engine_context.py"),
    Path("Virus_Scan/scanners/entropy.py"),
    Path("Virus_Scan/scanners/il_pipeline.py"),
)


def test_stage2018_repaired_scanner_backlog_snippets_are_absent():
    combined = "\n".join(path.read_text(encoding="utf-8") for path in _REPAIRED_FILES)
    still_present = [snippet for snippet in _REPAIRED_SNIPPETS if snippet in combined]
    assert still_present == []


def test_stage2018_repaired_scanner_files_do_not_reintroduce_fstrings():
    offenders = []
    for path in _REPAIRED_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        offenders.extend((str(path), node.lineno) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr))
    assert offenders == []


def test_stage2018_scanner_config_failure_rejects_hostile_text_hooks():
    failure = _config_load_failure(HostileValue(), HostileValue(), HostileException("hidden"))
    assert failure.config_name == "scanner_config"
    assert failure.source == "unsafe_scanner_config_source"
    assert failure.reason == "exception:HostileException"
    assert failure.failure_evidence[0]["message"] == "exception:HostileException"


def test_stage2018_binary_payload_evidence_contracts_reject_hostile_hooks():
    binary_result = BinaryAnalysisResult.malformed(BinaryMalformedRequest(HostileValue(), HostileValue(), HostileException("hidden"), input_path=HostileValue()))
    assert binary_result.scanner_name == "binary"
    assert binary_result.stage == "binary"
    assert binary_result.reason == "exception:HostileException"
    assert "binary_parse_failed" in binary_result.failure_tags

    payload_result = PayloadDecodeResult.failure(PayloadFailureRequest(HostileValue(), HostileValue(), HostileException("hidden"), depth=HostileValue()))
    assert payload_result.encoding == "payload"
    assert payload_result.reason == "exception:HostileException"
    record = payload_result.to_failure_record(depth=HostileValue())
    assert record["depth"] == 0
    assert record["evidence_id"] == "payload_decode_failure:payload"

    evidence = ScannerFailureEvidence.from_exception(
        scanner_name=HostileValue(),
        stage=HostileValue(),
        error=HostileException("hidden"),
        input_path=HostileValue(),
        state=HostileValue(),
        error_category=HostileValue(),
        error_source=HostileValue(),
        policy_config_source=HostileValue(),
        file_type=HostileValue(),
        truncation_status=HostileValue(),
        fatal=HostileValue(),
    )
    assert evidence.scanner_name == "scanner"
    assert evidence.scanner_stage == "unknown"
    assert evidence.message == "exception:HostileException"
    assert evidence.fatal is False


def test_stage2018_scanner_dotnet_engine_il_entropy_boundaries_reject_hostile_hooks():
    assert dotnet_metadata_present(HostileValue()) is False
    assert dotnet_behavior_tags(HostileValue()) == []
    assert dotnet_extension_tags(HostileValue()) == []

    context = infer_engine_context(HostileValue(), file_structure=HostileValue(), strings_blob=HostileValue())
    assert set(context) <= {"unity", "renpy", "rpgm", "media", "unknown"}
    assert merge_engine_context_with_runtime_hint(HostileValue()) == {}

    assert extract_il_patterns(HostileValue()) == []
    il_result = analyze_il_pipeline(HostileValue(), tags=HostileValue(), strings_blob=HostileValue())
    assert il_result["path"] == ""
    assert il_result["il_ops"] == []

    entropy_result = _entropy_exception_result(HostileValue(), HostileException("hidden"))
    assert entropy_result["reasons"] == ["exception:HostileException"]
    assert entropy_result["scanner_failure_evidence"][0]["message"] == "exception:HostileException"
