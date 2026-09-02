import gc
import inspect
from collections.abc import Mapping

import pytest

from Virus_Scan.contracts.scan_evidence_cache_publication import freeze_scan_evidence_cache_items
from Virus_Scan.detection.evidence.artifacts import scan_cache as detection_scan_cache
from Virus_Scan.detection.evidence.artifacts.scan_cache import remember_scan_evidence as detection_remember
from Virus_Scan.scanners import binary_scan_cache, image_evidence_cache
from Virus_Scan.scanners.binary_scan_cache import remember_scan_evidence as binary_remember
from Virus_Scan.scanners.image_evidence_cache import remember_scan_evidence as image_remember


class HostileValue:
    touched = False

    def __str__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __str__ touched")

    def __repr__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __repr__ touched")

    def __bool__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __bool__ touched")

    def __int__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __int__ touched")

    def __float__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __float__ touched")

    def __iter__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile __iter__ touched")


class HostileDict(dict):
    touched = False

    def items(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile items touched")

    def keys(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile keys touched")

    def values(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile values touched")

    def get(self, key, default=None):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile get touched")

    def __iter__(self):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile iter touched")

    def __getitem__(self, key):  # pragma: no cover - must not run
        type(self).touched = True
        raise AssertionError("hostile getitem touched")


def _contains_identity(root, target_id, *, max_nodes=5000):
    seen = set()
    stack = [root]
    while stack and len(seen) < max_nodes:
        obj = stack.pop()
        obj_id = id(obj)
        if obj_id == target_id:
            return True
        if obj_id in seen:
            continue
        seen.add(obj_id)
        try:
            stack.extend(gc.get_referents(obj))
        except Exception:
            continue
    return False


def test_stage1576_scan_cache_publication_freezes_nested_source_without_mutation_leak():
    source = {"nested": {"tags": ["a", "b"]}, "raw_sample": bytearray(b"abc")}
    frozen = freeze_scan_evidence_cache_items(source)
    source["nested"]["tags"].append("mutated")
    source["raw_sample"][0] = ord("z")

    assert tuple(frozen["nested"]["tags"]) == ("a", "b")
    assert frozen["raw_sample"] == b"abc"


def test_stage1576_scan_cache_publication_rejects_hostile_value_without_hooks_or_retention():
    HostileValue.touched = False
    hostile = HostileValue()
    result = binary_remember("sample.bin", metadata=hostile)

    assert result["ok"] is True
    evidence = result["cache_publication_request"]["items"]["metadata"]
    assert isinstance(evidence, Mapping)
    assert evidence["unavailable_reason"] == "unsupported_scan_cache_publication_value"
    assert HostileValue.touched is False
    assert not _contains_identity(evidence, id(hostile))


def test_stage1576_scan_cache_publication_rejects_hostile_mapping_without_mapping_hooks():
    HostileDict.touched = False
    hostile = HostileDict({"x": "y"})

    frozen = freeze_scan_evidence_cache_items(hostile)

    assert "scan_cache_items_unavailable" in frozen
    assert frozen["scan_cache_items_unavailable"]["unavailable_reason"] == "unsupported_scan_cache_items_mapping"
    assert HostileDict.touched is False


@pytest.mark.parametrize("remember", [binary_remember, image_remember, detection_remember])
def test_stage1576_scan_cache_publication_records_use_frozen_items_and_deterministic_keys(remember):
    result = remember("sample.dat", strings_blob="x" * 10, raw_sample=b"abc", tags={"b", "a"})

    assert result["ok"] is True
    request = result["cache_publication_request"]
    assert request["kind"] == "scan_evidence_cache_write"
    assert request["keys"] == ["raw_sample", "strings_blob", "tags"]
    assert request["items"]["strings_blob"] == "x" * 10
    assert request["items"]["raw_sample"] == b"abc"
    assert tuple(request["items"]["tags"]) == ("a", "b")


@pytest.mark.parametrize("remember", [binary_remember, image_remember, detection_remember])
def test_stage1576_scan_cache_publication_rejects_hostile_path_without_str_hook(remember):
    HostileValue.touched = False
    hostile_path = HostileValue()

    result = remember(hostile_path, metadata={"ok": True})

    assert result["ok"] is True
    request = result["cache_publication_request"]
    assert request["path"].endswith("__unsupported_scan_cache_path__")
    evidence = request["items"]["path_evidence"]
    assert evidence["unavailable_reason"] == "unsupported_scan_cache_path"
    assert HostileValue.touched is False
    assert not _contains_identity(evidence, id(hostile_path))


def test_stage1576_scan_cache_publication_producers_use_canonical_path_owner():
    for module in (detection_scan_cache, binary_scan_cache, image_evidence_cache):
        source = inspect.getsource(module.remember_scan_evidence)
        assert "scan_evidence_cache_path_text(path)" in source
        assert "str(path)" not in source
        assert "os.path.abspath(str" not in source
        assert "freeze_scan_evidence_cache_items" in source
