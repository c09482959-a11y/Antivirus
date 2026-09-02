from __future__ import annotations

from Virus_Scan.scanners.pickle.text_evidence import (
    _has_any_text,
    _has_command_exec_behavior,
    _has_pickle_exec_behavior,
    _pickle_bytes_to_text_views,
    _pickle_decode_interesting_text,
    pickle_decode_interesting_text_status,
)


class HostilePickleText:
    str_calls = 0
    repr_calls = 0
    bool_calls = 0

    def __bool__(self):  # pragma: no cover - failure proves regression
        type(self).bool_calls += 1
        raise AssertionError("pickle text boundary used caller-owned truthiness")

    def __str__(self):  # pragma: no cover - failure proves regression
        type(self).str_calls += 1
        raise AssertionError("pickle text boundary invoked __str__")

    def __repr__(self):  # pragma: no cover - failure proves regression
        type(self).repr_calls += 1
        raise AssertionError("pickle text boundary invoked __repr__")


class HostilePickleTerms:
    iter_calls = 0
    bool_calls = 0

    def __bool__(self):  # pragma: no cover - failure proves regression
        type(self).bool_calls += 1
        raise AssertionError("pickle terms boundary used caller-owned truthiness")

    def __iter__(self):  # pragma: no cover - failure proves regression
        type(self).iter_calls += 1
        raise AssertionError("pickle terms boundary invoked __iter__")


class HostileRawBytes:
    bool_calls = 0
    getitem_calls = 0

    def __bool__(self):  # pragma: no cover - failure proves regression
        type(self).bool_calls += 1
        raise AssertionError("pickle raw boundary used caller-owned truthiness")

    def __getitem__(self, item):  # pragma: no cover - failure proves regression
        type(self).getitem_calls += 1
        raise AssertionError("pickle raw boundary indexed caller-owned bytes-like object")

    def startswith(self, prefix):  # pragma: no cover - failure proves regression
        raise AssertionError("pickle raw boundary called caller-owned startswith")


def _reset_hostile_counts() -> None:
    HostilePickleText.str_calls = 0
    HostilePickleText.repr_calls = 0
    HostilePickleText.bool_calls = 0
    HostilePickleTerms.iter_calls = 0
    HostilePickleTerms.bool_calls = 0
    HostileRawBytes.bool_calls = 0
    HostileRawBytes.getitem_calls = 0


def test_stage1687_pickle_text_predicates_reject_hostile_text_without_hooks():
    _reset_hostile_counts()
    hostile = HostilePickleText()

    assert _has_any_text(hostile, ["powershell"]) is False
    assert _has_command_exec_behavior(hostile) is False
    assert _has_pickle_exec_behavior(hostile) is False
    assert pickle_decode_interesting_text_status(hostile) == "probe_error"
    assert _pickle_decode_interesting_text(hostile) is False

    assert HostilePickleText.str_calls == 0
    assert HostilePickleText.repr_calls == 0
    assert HostilePickleText.bool_calls == 0


def test_stage1687_pickle_text_terms_reject_hostile_iterables_without_hooks():
    _reset_hostile_counts()

    assert _has_any_text("powershell", HostilePickleTerms()) is False

    assert HostilePickleTerms.iter_calls == 0
    assert HostilePickleTerms.bool_calls == 0


def test_stage1687_pickle_raw_bytes_rejects_hostile_bytes_like_without_hooks():
    _reset_hostile_counts()
    raw = HostileRawBytes()

    assert pickle_decode_interesting_text_status("ordinary", raw=raw) == "ordinary"
    assert _pickle_bytes_to_text_views(raw) == []

    assert HostileRawBytes.bool_calls == 0
    assert HostileRawBytes.getitem_calls == 0


def test_stage1687_pickle_text_exact_primitives_preserve_behavior():
    assert _has_any_text("PowerShell -EncodedCommand", ["powershell"])
    assert _has_command_exec_behavior("cmd.exe /c powershell")
    assert _has_pickle_exec_behavior("pickle.loads subprocess\npopen")
    assert pickle_decode_interesting_text_status("hello pickle.loads") == "interesting"
    assert pickle_decode_interesting_text_status("plain text") == "ordinary"
    assert pickle_decode_interesting_text_status("plain text", raw=b"MZ") == "interesting"
    assert _pickle_decode_interesting_text("pickle.loads") is True
    assert "abc" in _pickle_bytes_to_text_views(b"abc")
