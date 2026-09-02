from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.scanners.archives import rpa_member_behavior
from Virus_Scan.scanners.archives.rpa_member_no_hook import (
    rpa_member_exact_limited_items,
    rpa_member_input_path,
    rpa_member_payload_bytes,
)



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

    def __format__(self, _spec):
        return self._touch()


class HostileBytes:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __bytes__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned bytes hook executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned bytes iter hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned bytes bool hook executed")


class HostileContainer:
    touched = 0

    @classmethod
    def reset(cls) -> None:
        cls.touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container iter hook executed")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned container bool hook executed")


def test_stage1994_rpa_member_path_and_payload_boundaries_reject_hostile_values_without_hooks() -> None:
    HostileText.reset()
    HostileBytes.reset()

    path_text, path_reason = rpa_member_input_path(HostileText())
    payload, payload_reason = rpa_member_payload_bytes(HostileBytes(), "rpa_member_payload_unsafe")

    assert path_text == ""
    assert path_reason == "rpa_member_path_unsafe"
    assert payload == b""
    assert payload_reason == "rpa_member_payload_unsafe"
    assert HostileText.touched == 0
    assert HostileBytes.touched == 0


def test_stage1994_rpa_member_public_path_boundary_records_failure_without_path_hooks() -> None:
    HostileText.reset()

    tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(b"RPA-3.0\n", path=HostileText())

    assert HostileText.touched == 0
    assert "scanner_failure_evidence:archive_rpa:rpa_member_path" in tags
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1994_rpa_member_sequence_boundary_rejects_hostile_member_sequence_without_iteration_hooks() -> None:
    HostileContainer.reset()

    def fake_members(_blob, path=None):
        return HostileContainer()

    original_members = rpa_member_behavior.iter_renpy_rpa_members
    rpa_member_behavior.iter_renpy_rpa_members = fake_members
    try:
        tags = rpa_member_behavior.rpa_decoded_member_behavior_tags(b"RPA-3.0\n", path="sample.rpa")
    finally:
        rpa_member_behavior.iter_renpy_rpa_members = original_members

    assert HostileContainer.touched == 0
    assert rpa_member_exact_limited_items(HostileContainer(), limit=4) is None
    assert "scanner_failure_evidence:archive_rpa:rpa_member_parse" in tags
    assert "rpa_failure_evidence_recorded" in tags


def test_stage1994_payload_record_sequence_boundaries_reject_hostile_records_without_iteration_hooks() -> None:
    HostileContainer.reset()

    def fake_members(_blob, path=None):
        return [("member.txt", b"plain", {})]

    def fake_pickle_records(_payload):
        return HostileContainer()

    def fake_embedded_records(_payload, **_kwargs):
        return HostileContainer()

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

    assert HostileContainer.touched == 0
    assert "rpa_pickle_payload_record_failure" in tags
    assert "rpa_embedded_payload_record_failure" in tags
    assert "rpa_failure_evidence_recorded" in tags
    assert "archive_final_json_must_record" in tags


def test_stage1994_rpa_member_behavior_source_snippets_are_removed() -> None:
    behavior = read_python_file(Path("Virus_Scan/scanners/archives/rpa_member_behavior.py"))
    no_hook = read_python_file(Path("Virus_Scan/scanners/archives/rpa_member_no_hook.py"))
    removed = (
        'input_path=safe_input_path(path), error_category="rpa_member_boundary_failure",',
        'members = safe_limited_items(iter_renpy_rpa_members(blob, path=path), limit=96)',
        'payload_blob, payload_reason = safe_payload_bytes(payload, "rpa_member_payload_unsafe")',
        'sub_views = safe_limited_items(iter_rpyc_pickle_byte_views(payload_blob, path=safe_member), limit=32)',
        'sub_blob, sub_payload_reason = safe_payload_bytes(sub_payload, "rpa_member_subpayload_unsafe")',
        'records = safe_limited_items(iter_pickle_payload_records(payload), limit=16)',
        'records = safe_limited_items(embedded_payload_records_from_bytes(payload, encoding_hint="renpy_rpa_member", max_offsets=16), limit=16)',
        'blob, blob_reason = safe_payload_bytes(data, "rpa_member_input_unsafe")',
        'for _kind, payload, meta in _iter_member_views(blob, safe_input_path(path)):',
        'def safe_input_path(path: object) -> str:',
        'def safe_payload_bytes(value: object, reason: str) -> tuple[bytes, str]:',
        'def safe_limited_items(value: object, *, limit: int) -> tuple[Any, ...] | None:',
    )
    combined = behavior + no_hook
    for snippet in removed:
        assert snippet not in combined
