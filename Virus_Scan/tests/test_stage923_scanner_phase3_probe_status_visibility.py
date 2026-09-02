import pytest

from Virus_Scan.scanners import pipeline, raw_chunk_core, text, text_validation_gates


class BadIterable:
    def __iter__(self):
        raise TypeError("bad scanner anchor iterable")


class BadPath:
    def __str__(self):
        raise TypeError("bad scanner path")


def test_pipeline_context_regex_failure_is_status_not_fail_open_true():
    assert pipeline._ctx_re_status("[", "anything") == "probe_error"
    with pytest.raises(ValueError):
        pipeline._ctx_re("[", "anything")


def test_text_renpy_bytecode_path_probe_error_is_not_fail_open_true():
    assert text._renpy_bytecode_path_status(BadPath()) == "probe_error"
    assert text._is_renpy_bytecode_path(BadPath()) is False


def test_raw_chunk_anchor_boundary_has_explicit_status_and_report():
    reported = []

    def report(label, exc, **kwargs):
        reported.append((label, type(exc).__name__))

    assert raw_chunk_core.context_anchor_status(BadIterable())[0] == "anchor_probe_error"
    assert raw_chunk_core.should_context_scan("powershell", context_anchors=BadIterable(), report=report) is True
    assert ("raw_context_anchor_boundary_failed", "TypeError") in reported


def test_raw_chunk_decode_anchor_boundary_has_explicit_status_and_report():
    reported = []

    def report(label, exc, **kwargs):
        reported.append((label, type(exc).__name__))

    assert raw_chunk_core.decode_anchor_status(BadIterable())[0] == "anchor_probe_error"
    assert raw_chunk_core.should_decode_scan("A" * 96, decode_anchors=BadIterable(), report=report) is True
    assert ("raw_decode_anchor_boundary_failed", "TypeError") in reported


def test_text_library_baseline_hard_proof_status_exposes_probe_error():
    def bad_validation(_value=''):
        raise TypeError('bad library baseline text')

    assert text_validation_gates.library_baseline_hard_proof_status([], 'broken', validation_text=bad_validation)[0] == 'probe_error'
    assert text_validation_gates.library_baseline_has_hard_proof([], 'broken', validation_text=bad_validation) is True


def test_pipeline_retry_max_status_exposes_parse_error():
    env_reader = lambda name, default=None: 'not-an-int' if name == 'UMIGE_RAW_RETRY_MAX' else default
    assert pipeline._umige_retry_max_status('raw', env_reader=env_reader) == ('parse_error', 1)
    assert pipeline._umige_retry_max('raw', env_reader=env_reader) == 1


class BadBytes:
    def __len__(self):
        return 16
    def find(self, *_args, **_kwargs):
        raise TypeError('bad cstring buffer')


def test_pipeline_cstring_decode_failure_uses_status_instead_of_sentinel():
    status, value = pipeline._umige_cstr_status(BadBytes(), 0)
    assert status == 'decode_error'
    assert isinstance(value, TypeError)
    with pytest.raises(ValueError):
        pipeline._umige_cstr(BadBytes(), 0)
