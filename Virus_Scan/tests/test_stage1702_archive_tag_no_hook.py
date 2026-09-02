"""Stage1702 archive tag-classification no-hook regressions."""
from __future__ import annotations

import inspect

from Virus_Scan.scanners.archives import payloads, rpa


class HostileTag:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned archive tag hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()

    def __bool__(self):
        return self._touch()


class HostileTagContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned archive tag container bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned archive tag container iter executed")



def test_stage1702_archive_payload_failure_tag_rejects_hostile_tag_without_hooks():
    HostileTag.reset()

    assert payloads._has_failure_evidence_tag([HostileTag()]) is True

    assert HostileTag.touched == 0



def test_stage1702_archive_payload_suspicious_tag_rejects_hostile_container_without_hooks():
    HostileTagContainer.reset()

    assert payloads._has_suspicious_tag(
        HostileTagContainer(),
        frozenset({"payload_decode_confirmed"}),
    ) is False
    assert payloads._has_failure_evidence_tag(HostileTagContainer()) is True

    assert HostileTagContainer.touched == 0



def test_stage1702_rpa_degraded_tags_reject_hostile_tag_without_hooks():
    HostileTag.reset()

    assert rpa._rpa_degraded_or_failure_tags([HostileTag()]) is True

    assert HostileTag.touched == 0



def test_stage1702_archive_tag_helpers_preserve_exact_tags():
    assert payloads._has_suspicious_tag(
        ["payload_decode_confirmed"],
        frozenset({"payload_decode_confirmed"}),
    ) is True
    assert payloads._has_failure_evidence_tag(["scanner_failure_evidence:archive:stage"]) is True
    assert payloads._has_failure_evidence_tag(["archive_final_json_must_record"]) is True
    assert rpa._rpa_degraded_or_failure_tags(["rpa_failure_evidence_recorded"]) is True
    assert rpa._rpa_degraded_or_failure_tags(["scanner_failure_evidence:archive:rpa"]) is True



def test_stage1702_archive_tag_helper_sources_have_no_unsafe_tag_stringification():
    helper_sources = "\n".join(
        (
            inspect.getsource(payloads._has_suspicious_tag),
            inspect.getsource(payloads._has_failure_evidence_tag),
            inspect.getsource(rpa._rpa_degraded_or_failure_tags),
        )
    )

    forbidden = (
        "str(tag)",
        "tags or []",
        "values or []",
    )
    for pattern in forbidden:
        assert pattern not in helper_sources
