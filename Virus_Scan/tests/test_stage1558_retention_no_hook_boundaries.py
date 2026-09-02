from __future__ import annotations

from Virus_Scan.models import retention as retention_module
from Virus_Scan.models.retention import (
    prune_counter_map,
    prune_engine_profile_for_retention,
    prune_staged_benign_store,
)


class HostileLimit:
    touched = 0

    def __int__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __int__")

    def __float__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __bool__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")


class HostilePrefer:
    touched = 0

    def __bool__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __bool__")


class HostileInt(int):
    touched = 0

    def __new__(cls, value: int):
        return int.__new__(cls, value)

    def __float__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __float__")

    def __int__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __int__")


class HostileTuple(tuple):
    touched = 0

    def __new__(cls, values):
        return tuple.__new__(cls, values)

    def __iter__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __iter__")


class HostileDict(dict):
    touched = 0

    def get(self, *args, **kwargs):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def items(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def values(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call values")

    def __len__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __len__")


class HostilePathLike:
    touched = 0

    def __fspath__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __fspath__")

    def __str__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __str__")

    def __repr__(self):  # pragma: no cover - must not be reached
        type(self).touched += 1
        raise RuntimeError("do not call __repr__")


def _reset() -> None:
    for cls in (HostileLimit, HostilePrefer, HostileInt, HostileTuple, HostileDict, HostilePathLike):
        cls.touched = 0


def test_stage1558_retention_prune_rejects_hostile_limit_and_prefer_truthiness() -> None:
    _reset()
    counter = {"a": 1, "b": 2}

    returned = prune_counter_map(counter, HostileLimit(), prefer_high=HostilePrefer())

    assert returned is counter
    assert counter == {"a": 1, "b": 2}
    assert HostileLimit.touched == 0
    assert HostilePrefer.touched == 0


def test_stage1558_retention_counter_numeric_subclasses_do_not_invoke_numeric_hooks() -> None:
    _reset()
    counter = {"hostile": HostileInt(9), "safe": 1, "other": 2}

    returned = prune_counter_map(counter, 1, prefer_high=True)

    assert returned is counter
    assert list(counter) == ["other"]
    assert HostileInt.touched == 0


def test_stage1558_retention_key_sequence_subclasses_use_builtin_iteration_only() -> None:
    _reset()
    key = HostileTuple(("z", "a"))
    counter = {key: 5, "safe": 1}

    returned = prune_counter_map(counter, 1, prefer_high=True)

    assert returned is counter
    assert list(counter) == [key]
    assert HostileTuple.touched == 0


def test_stage1558_retention_profile_dict_subclass_methods_are_not_invoked() -> None:
    _reset()
    original_limit = retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE
    retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = 1
    hostile_ext = HostilePathLike()
    try:
        profile = HostileDict({
            "extension_baselines": HostileDict({
                ".low": HostileDict({"files": 1, "updated": 1.0, "tags": {}}),
                hostile_ext: HostileDict({"files": 7, "updated": 7.0, "tags": {}}),
            })
        })

        returned = prune_engine_profile_for_retention(profile)

        assert returned is profile
        assert list(dict.keys(dict.__getitem__(profile, "extension_baselines"))) == [hostile_ext]
        assert HostileDict.touched == 0
        assert HostilePathLike.touched == 0
    finally:
        retention_module.MAX_EXTENSION_BASELINES_PER_ENGINE = original_limit


def test_stage1558_staged_benign_store_dict_subclass_methods_are_not_invoked() -> None:
    _reset()
    original_limit = retention_module.MAX_STAGED_BENIGN_CANDIDATES
    retention_module.MAX_STAGED_BENIGN_CANDIDATES = 1
    try:
        hostile_key = HostilePathLike()
        store = HostileDict({
            "candidates": HostileDict({
                "old": HostileDict({"clean_observations": 1, "last_seen": 1.0}),
                hostile_key: HostileDict({"clean_observations": 3, "last_seen": 3.0}),
            })
        })

        returned = prune_staged_benign_store(store)

        assert returned is store
        assert list(dict.keys(dict.__getitem__(store, "candidates"))) == [hostile_key]
        assert HostileDict.touched == 0
        assert HostilePathLike.touched == 0
    finally:
        retention_module.MAX_STAGED_BENIGN_CANDIDATES = original_limit
