from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.publication.json_finalization import compact_record, normalization, partial_results, streaming


class HostileFinalJsonValue:
    touched = 0

    def _touch(self) -> None:
        type(self).touched += 1
        raise AssertionError("final JSON boundary touched caller-owned hook")

    def __str__(self):  # pragma: no cover - failure proves the boundary regressed
        self._touch()

    def __repr__(self):  # pragma: no cover
        self._touch()

    def __format__(self, _spec):  # pragma: no cover
        self._touch()

    def __bool__(self):  # pragma: no cover
        self._touch()

    def __iter__(self):  # pragma: no cover
        self._touch()


class HostileDict(dict):
    touched = 0

    def items(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("final JSON boundary called caller-owned items")

    def keys(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("final JSON boundary called caller-owned keys")

    def get(self, *_args, **_kwargs):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("final JSON boundary called caller-owned get")

    def __iter__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("final JSON boundary called caller-owned iter")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("final JSON boundary truth-tested caller mapping")


class HostileOSError(OSError):
    touched = 0

    def __str__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("streaming failure called exception __str__")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("streaming failure called exception __repr__")

    def __format__(self, _spec):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("streaming failure called exception __format__")


def _reset() -> None:
    HostileFinalJsonValue.touched = 0
    HostileDict.touched = 0
    HostileOSError.touched = 0


def test_stage2005_compact_keys_values_and_sort_fallback_are_no_hook() -> None:
    _reset()
    hostile_key = HostileFinalJsonValue()
    hostile_value = HostileFinalJsonValue()
    source = HostileDict({1: "int-key", "1": "text-key", hostile_key: hostile_value})

    compact = compact_record.compact_json_serializable_record(source)

    def fail_materialization(_value):
        raise TypeError("forced compact sort failure")

    original_make_json_safe = compact_record.make_json_safe
    try:
        compact_record.make_json_safe = fail_materialization
        sort_key = compact_record._compact_sort_key(hostile_value)
    finally:
        compact_record.make_json_safe = original_make_json_safe

    assert compact["1"] == "int-key"
    assert compact["1#1"] == "text-key"
    assert compact["_unavailable_key_2"]["key_unavailable_reason"] == "final_json_key_text_unavailable"
    assert compact["_unavailable_key_2"]["value"]["reason"] == "compact_value_unavailable"
    assert sort_key == "compact_sort_unavailable:HostileFinalJsonValue"
    assert HostileDict.touched == 0
    assert HostileFinalJsonValue.touched == 0


def test_stage2005_normalization_and_partial_snapshots_dedupe_without_fallback_hooks(
) -> None:
    _reset()
    hostile_key = HostileFinalJsonValue()
    source = HostileDict({1: "one", "1": "two", hostile_key: "rejected-key"})

    normalized_snapshot = normalization._compact_outer_record_snapshot(source)
    partial_snapshot = partial_results._partial_results_snapshot(source, "scan_results.json")

    assert normalized_snapshot is not None
    assert normalized_snapshot["1"] == "one"
    assert normalized_snapshot["1#1"] == "two"
    assert normalized_snapshot["_unavailable_key_2"]["reason"] == "final_json_key_text_unavailable"
    assert partial_snapshot["1"] == "one"
    assert partial_snapshot["1#1"] == "two"
    assert partial_snapshot["_unavailable_key_2"][partial_results.PARTIAL_RECOVERY_EVIDENCE_KEY]["value_type"] == "HostileFinalJsonValue"

    calls = []
    hostile_normalized = HostileFinalJsonValue()

    def fake_normalize(*args, **kwargs):
        calls.append((args, kwargs))
        return hostile_normalized

    original_normalize_result_record = normalization.normalize_result_record
    try:
        normalization.normalize_result_record = fake_normalize
        failure = normalization.normalize_compact_result_record(HostileFinalJsonValue())
    finally:
        normalization.normalize_result_record = original_normalize_result_record

    assert len(calls) == 1
    assert failure["_finalizer_raw_errors"][0] == {
        "final_json_projection_failed": True,
        "reason": "result_record_normalization_failed",
        "value_type": "HostileFinalJsonValue",
    }
    assert HostileDict.touched == 0
    assert HostileFinalJsonValue.touched == 0


def test_stage2005_streaming_failure_messages_do_not_format_exceptions(
    tmp_path: Path,
) -> None:
    _reset()
    output = tmp_path / "scan_results.json"
    failure = streaming.stream_write_failure(str(output), HostileOSError())

    assert "final_json_stream_write_failed" in str(failure)
    assert "OSError" in str(failure)
    assert HostileOSError.touched == 0


def test_stage2005_publication_json_finalization_source_guard() -> None:
    forbidden_by_file = {
        "Virus_Scan/publication/json_finalization/compact_record.py": (
            'return f"compact_sort_unavailable:{final_json_type_name(item)}"',
            "key_text, key_reason = safe_json_key_text(key, index)",
            'key_text = f"{key_text}#{index}"',
        ),
        "Virus_Scan/publication/json_finalization/normalization.py": (
            'fallback = normalize_result_record(normalized, source="finalizer_compact")',
            "key_text, key_reason = safe_json_key_text(key, index)",
            'key_text = f"{key_text}#{index}"',
        ),
        "Virus_Scan/publication/json_finalization/model_metric_projection.py": (
            "name = safe_projection_text(key)[0].strip().lower()",
            "lambda pair: safe_projection_sort_key(pair[0])",
            'out[f"{out_key}_unavailable_reason"] = reason',
        ),
        "Virus_Scan/publication/json_finalization/streaming.py": (
            'raise OSError(f"final result fsync failed for {tmp}: {exc}") from exc',
            'raise RuntimeError(f"final scan_results.json write failed for {path}: {exc}") from exc',
            'safe_unlink(path + ".partial")',
            "safe_unlink(tmp)",
        ),
        "Virus_Scan/publication/json_finalization/signal_projection.py": (
            'return f"<{final_json_type_name(value)} {reason}>"[:width]',
            "for name, value in signals.items():",
            "legacy dict-only helper",
        ),
        "Virus_Scan/publication/json_finalization/success_fields.py": (
            "safe_bounded_text_value(r, 512)",
        ),
        "Virus_Scan/publication/json_finalization/error_fields.py": (
            'errors.append(f"compact_record_error:{type(exc).__name__}")',
            'error_tag = f"compact_record_error:{type(exc).__name__}"',
        ),
        "Virus_Scan/publication/json_finalization/extension_mismatch.py": (
            'evidence.append(f"declared_{declared}_sniffs_as_{sniffed}")',
        ),
    }
    for filename, snippets in forbidden_by_file.items():
        source = Path(filename).read_text(encoding="utf-8")
        for snippet in snippets:
            assert snippet not in source
