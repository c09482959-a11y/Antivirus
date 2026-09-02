import json
from collections.abc import Mapping

from Virus_Scan.core import jsonio


class HostileTextValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not getitem")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")


class HostileList(list):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len")


def test_stage1685_core_make_json_safe_rejects_unknown_without_text_hooks():
    HostileTextValue.touched = 0
    payload = jsonio.make_json_safe({"bad": HostileTextValue()})

    assert HostileTextValue.touched == 0
    assert payload["bad"]["unavailable_reason"] == "unsupported_jsonio_value"
    assert payload["bad"]["value_type"] == "HostileTextValue"
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_stage1685_core_make_json_safe_rejects_mapping_like_without_mapping_hooks():
    HostileMapping.touched = 0
    payload = jsonio.make_json_safe({"bad": HostileMapping()})

    assert HostileMapping.touched == 0
    assert payload["bad"]["unavailable_reason"] == "unsupported_jsonio_value"
    assert payload["bad"]["value_type"] == "HostileMapping"
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_stage1685_core_make_json_safe_rejects_list_subclass_without_iteration_hooks():
    HostileList.touched = 0
    payload = jsonio.make_json_safe({"bad": HostileList(("x", "y"))})

    assert HostileList.touched == 0
    assert payload["bad"]["unavailable_reason"] == "unsupported_jsonio_value"
    assert payload["bad"]["value_type"] == "HostileList"
    json.dumps(payload, sort_keys=True, allow_nan=False)


def test_stage1685_queue_failure_info_rejects_hostile_fields_and_extra_without_hooks():
    HostileTextValue.touched = 0
    HostileMapping.touched = 0

    info = jsonio._jsonio_queue_failure_info(
        HostileTextValue(),
        exception_type=HostileTextValue(),
        error=HostileTextValue(),
        extra=HostileMapping(),
    )

    assert HostileTextValue.touched == 0
    assert HostileMapping.touched == 0
    assert info["stage"] == "queue_failed"
    assert info["exception_type"] == "QueueFailure"
    assert info["error"] == "queue job failed"
    assert info["extra_unavailable"]["unavailable_reason"] == "unsupported_queue_failure_extra"
    assert info["extra_unavailable"]["value_type"] == "HostileMapping"
    json.dumps(info, sort_keys=True, allow_nan=False)
