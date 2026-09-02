import inspect

from Virus_Scan.scanners.archives import rpa_member_behavior, rpa_member_text_tags


class HostileBytes:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned bytes hook executed")

    def __bool__(self):
        return self._touch()

    def __bytes__(self):
        return self._touch()

    def __iter__(self):
        return self._touch()


class HostileText:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def _touch(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned text hook executed")

    def __str__(self):
        return self._touch()

    def __repr__(self):
        return self._touch()

    def __format__(self, spec):
        return self._touch()


class HostileContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container bool executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container iter executed")


def test_stage1704_public_rpa_member_behavior_rejects_hostile_data_without_hooks():
    HostileBytes.reset()

    tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(HostileBytes(), path="sample.rpa")

    assert HostileBytes.touched == 0
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1704_iter_member_views_rejects_hostile_member_name_without_string_hooks():
    HostileText.reset()

    def fake_members(_blob, path=None):
        return [(HostileText(), b"exec(zlib.decompress(base64.b64decode('x')))" , {})]

    original_members = rpa_member_behavior.iter_renpy_rpa_members
    rpa_member_behavior.iter_renpy_rpa_members = fake_members
    try:
        tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(b"RPA-3.0\n", path="sample.rpa")
    finally:
        rpa_member_behavior.iter_renpy_rpa_members = original_members

    assert HostileText.touched == 0
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1704_payload_records_reject_hostile_text_and_failure_tags_without_hooks():
    HostileText.reset()
    HostileContainer.reset()

    def fake_members(_blob, path=None):
        return [("member.txt", b"plain", {})]

    def fake_pickle_records(_payload):
        return [{"text": HostileText()}]

    def fake_embedded_records(_payload, **_kwargs):
        return [{"failure_tags": HostileContainer()}]

    original_members = rpa_member_behavior.iter_renpy_rpa_members
    original_pickle_records = rpa_member_behavior.iter_pickle_payload_records
    original_embedded_records = rpa_member_behavior.embedded_payload_records_from_bytes
    rpa_member_behavior.iter_renpy_rpa_members = fake_members
    rpa_member_behavior.iter_pickle_payload_records = fake_pickle_records
    rpa_member_behavior.embedded_payload_records_from_bytes = fake_embedded_records
    try:
        tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(b"RPA-3.0\n", path="sample.rpa")
    finally:
        rpa_member_behavior.iter_renpy_rpa_members = original_members
        rpa_member_behavior.iter_pickle_payload_records = original_pickle_records
        rpa_member_behavior.embedded_payload_records_from_bytes = original_embedded_records

    assert HostileText.touched == 0
    assert HostileContainer.touched == 0
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1704_rpa_member_behavior_preserves_exact_payload_behavior():
    def fake_members(_blob, path=None):
        return [("member.txt", b"exec(zlib.decompress(base64.b64decode('x')))" , {})]

    original_members = rpa_member_behavior.iter_renpy_rpa_members
    rpa_member_behavior.iter_renpy_rpa_members = fake_members
    try:
        tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(b"RPA-3.0\n", path="sample.rpa")
    finally:
        rpa_member_behavior.iter_renpy_rpa_members = original_members

    assert "embedded_payload_execution" in tags
    assert "encoded_payload_execution" in tags
    assert "payload_decode_confirmed" in tags


def test_stage1704_rpa_member_behavior_sources_have_no_unsafe_boundary_conversions():
    sources = "\n".join(
        (
            inspect.getsource(rpa_member_behavior._iter_member_views),
            inspect.getsource(rpa_member_behavior._payload_text_views),
            inspect.getsource(rpa_member_text_tags.append_behavior_tags),
            inspect.getsource(rpa_member_behavior.rpa_decoded_member_behavior_tags),
        )
    )
    forbidden = (
        "str(member_name)",
        "str(sub_kind)",
        "str(tag)",
        "str(rec.get",
        "dict(meta or {})",
        "data or b''",
        "path or ''",
    )
    for token in forbidden:
        assert token not in sources
