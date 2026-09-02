from Virus_Scan.scanners.text_context import (
    _engine_hint_to_context,
    _filetype_claim_matches_actual,
    _game_engine_context,
)


class HostileContextValue:
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile context hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()

    def __fspath__(self):
        return self._touch()

    def __bool__(self):
        return self._touch()

    def __iter__(self):
        return self._touch()

    def __float__(self):
        return self._touch()

    def __int__(self):
        return self._touch()


class HostileContextException(RuntimeError):
    touched = 0

    @classmethod
    def reset(cls):
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("hostile exception hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()


def test_stage1597_scanner_text_context_helpers_reject_hostile_inputs_without_hooks():
    HostileContextValue.reset()
    hostile = HostileContextValue()

    context = _engine_hint_to_context(hostile)
    assert context["context_unavailable_reason"] == "unsafe_context_engine_hint_rejected"
    assert _filetype_claim_matches_actual(hostile, "text", "zip") is False
    assert _game_engine_context(hostile) is False

    assert HostileContextValue.touched == 0


from Virus_Scan.scanners.binary_integrity import binary_degraded_scan_integrity
from Virus_Scan.scanners.binary_pe_headers import global_raw_pure_pe_header


def test_stage1597_binary_integrity_rejects_hostile_error_without_string_hooks():
    HostileContextValue.reset()
    integrity = binary_degraded_scan_integrity(HostileContextValue(), scanner="binary")

    assert integrity["file_failed"] is True
    assert integrity["had_degraded_stage"] is True
    assert integrity["allow_learning"] is False
    assert integrity["error_unavailable_reason"] == "unsafe_binary_integrity_error_rejected"
    assert integrity["error_type"] == "HostileContextValue"
    assert integrity["scanner"] == "binary"
    assert HostileContextValue.touched == 0


def test_stage1597_pure_pe_header_rejects_hostile_path_without_fspath_or_string_hooks():
    HostileContextValue.reset()
    result = global_raw_pure_pe_header(HostileContextValue())

    assert "pure_pe_scan_error" in result["tags"]
    assert "binary_final_json_must_record" in result["tags"]
    assert result["meta"]["scanner_degraded"] is True
    assert result["meta"]["binary_final_json_must_record"] is True
    assert result["meta"]["path_unavailable_reason"] == "unsafe_binary_pe_path_rejected"
    assert result["meta"]["path_type"] == "HostileContextValue"
    assert HostileContextValue.touched == 0
