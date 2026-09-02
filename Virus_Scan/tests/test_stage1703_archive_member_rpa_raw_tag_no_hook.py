import inspect

from Virus_Scan.scanners.archives import member_scan, rpa_raw


class HostileTag:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned archive member tag hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
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


def test_stage1703_archive_member_string_tags_reject_hostile_tag_without_hooks():
    HostileTag.reset()

    assert member_scan._string_tags_are_suspicious([HostileTag()]) is False

    assert HostileTag.touched == 0


def test_stage1703_archive_member_string_tags_reject_hostile_container_without_hooks():
    HostileTagContainer.reset()

    assert member_scan._string_tags_are_suspicious(HostileTagContainer()) is False

    assert HostileTagContainer.touched == 0


def test_stage1703_rpa_raw_tags_reject_hostile_tag_without_hooks():
    HostileTag.reset()

    assert rpa_raw._rpa_raw_tags_are_suspicious([HostileTag()]) is False

    assert HostileTag.touched == 0


def test_stage1703_rpa_raw_tags_reject_hostile_container_without_hooks():
    HostileTagContainer.reset()

    assert rpa_raw._rpa_raw_tags_are_suspicious(HostileTagContainer()) is False

    assert HostileTagContainer.touched == 0


def test_stage1703_archive_member_and_rpa_raw_preserve_exact_suspicious_tags():
    assert member_scan._string_tags_are_suspicious(["process_exec"]) is True
    assert member_scan._string_tags_are_suspicious(["benign_payload_marker"]) is True
    assert member_scan._string_tags_are_suspicious(["ordinary_tag"]) is False
    assert rpa_raw._rpa_raw_tags_are_suspicious(["process_exec"]) is True
    assert rpa_raw._rpa_raw_tags_are_suspicious(["ordinary_tag"]) is False


def test_stage1703_archive_member_and_rpa_raw_helper_sources_have_no_unsafe_tag_stringification():
    helper_sources = "\n".join(
        (
            inspect.getsource(member_scan._string_tags_are_suspicious),
            inspect.getsource(rpa_raw._rpa_raw_tags_are_suspicious),
        )
    )

    forbidden = (
        "str(tag)",
        "values or []",
        "string_tags or []",
    )
    for token in forbidden:
        assert token not in helper_sources
