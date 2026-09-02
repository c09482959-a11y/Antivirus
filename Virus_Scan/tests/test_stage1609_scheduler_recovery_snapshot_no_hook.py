from collections.abc import Mapping

from Virus_Scan.scheduler.queue.recovery_snapshot import deterministic_recovery_snapshot


class HostileRecoveryMapping(Mapping):
    touched = 0

    def __getitem__(self, key):
        HostileRecoveryMapping.touched += 1
        raise RuntimeError("do not index")

    def __iter__(self):
        HostileRecoveryMapping.touched += 1
        raise RuntimeError("do not iterate")

    def __len__(self):
        HostileRecoveryMapping.touched += 1
        raise RuntimeError("do not len")

    def items(self):
        HostileRecoveryMapping.touched += 1
        raise RuntimeError("do not items")


class HostileRecoveryKey:
    touched = 0

    def __str__(self):
        HostileRecoveryKey.touched += 1
        raise RuntimeError("do not stringify key")

    def __repr__(self):
        HostileRecoveryKey.touched += 1
        raise RuntimeError("do not repr key")

    def __format__(self, spec):
        HostileRecoveryKey.touched += 1
        raise RuntimeError("do not format key")


class HostileRecoveryValue:
    touched = 0

    def __iter__(self):
        HostileRecoveryValue.touched += 1
        raise RuntimeError("do not iterate value")

    def __str__(self):
        HostileRecoveryValue.touched += 1
        raise RuntimeError("do not stringify value")

    def __repr__(self):
        HostileRecoveryValue.touched += 1
        raise RuntimeError("do not repr value")


class HostileSetItem:
    touched = 0

    def __str__(self):
        HostileSetItem.touched += 1
        raise RuntimeError("do not stringify set item")

    def __repr__(self):
        HostileSetItem.touched += 1
        raise RuntimeError("do not repr set item")


def test_stage1609_recovery_snapshot_rejects_mapping_like_object_without_hooks():
    HostileRecoveryMapping.touched = 0

    snapshot = deterministic_recovery_snapshot(HostileRecoveryMapping())

    assert HostileRecoveryMapping.touched == 0
    assert snapshot["scheduler_recovery_snapshot_unavailable"] is True
    assert snapshot["unsupported_scheduler_value"] is True
    assert snapshot["field_name"] == "recovery_snapshot"
    assert snapshot["final_json_must_record"] is True
    assert snapshot["replay_must_record"] is True


def test_stage1609_recovery_snapshot_rejects_unsafe_keys_without_stringifying():
    HostileRecoveryKey.touched = 0
    key = HostileRecoveryKey()

    snapshot = deterministic_recovery_snapshot({key: "value", "safe": "kept"})

    assert HostileRecoveryKey.touched == 0
    assert snapshot["safe"] == "kept"
    rejected = snapshot["recovery_snapshot_key_0"]
    assert rejected["unsupported_scheduler_value"] is True
    assert rejected["field_name"] == "recovery_snapshot_key_0"
    assert rejected["final_json_must_record"] is True


def test_stage1609_recovery_snapshot_rejects_nested_values_without_hooks():
    HostileRecoveryValue.touched = 0
    value = HostileRecoveryValue()

    snapshot = deterministic_recovery_snapshot({"nested": {"value": value}})

    assert HostileRecoveryValue.touched == 0
    rejected = snapshot["nested"]["value"]
    assert rejected["unsupported_scheduler_value"] is True
    assert rejected["field_name"] == "value"
    assert rejected["replay_must_record"] is True


def test_stage1609_recovery_snapshot_sorts_sets_without_stringifying_items():
    HostileSetItem.touched = 0

    snapshot = deterministic_recovery_snapshot({"items": {HostileSetItem(), "safe"}})

    assert HostileSetItem.touched == 0
    assert snapshot["items"][0] == "safe" or snapshot["items"][1] == "safe"
    assert any(type(item) is dict and item.get("unsupported_scheduler_value") is True for item in snapshot["items"])
