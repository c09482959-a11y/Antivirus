from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.contracts.path_identity import PathIdentity, ScanPathPolicySnapshot, get_scan_extension
from Virus_Scan.contracts.result_record import (
    ResultEvidenceSnapshot,
    make_terminal_asset_result,
    make_timeout_result,
    make_worker_error_result,
    normalize_result_record,
    validate_evidence_object_invariants,
)


class HostileText:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError("do not format")


class HostileInt:
    touched = 0

    def __int__(self):
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth test")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate mapping")

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError("do not len mapping")

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError("do not index mapping")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not get mapping")

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not items mapping")


class HostilePathLike:
    touched = 0

    def __fspath__(self):
        type(self).touched += 1
        raise RuntimeError("do not fspath")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify path")


def _reset() -> None:
    HostileText.touched = 0
    HostileInt.touched = 0
    HostileIterable.touched = 0
    HostileMapping.touched = 0
    HostilePathLike.touched = 0


def test_result_error_timeout_and_terminal_helpers_do_not_call_text_path_or_numeric_hooks() -> None:
    _reset()

    normalized = normalize_result_record(HostileMapping(), file_path=HostileText())
    worker_error = make_worker_error_result(HostilePathLike(), HostileText())
    timeout = make_timeout_result(HostilePathLike(), HostileInt())
    terminal = make_terminal_asset_result(HostilePathLike(), HostileIterable(), curr_stage=HostileText())

    assert normalized["classification"] == "error"
    assert worker_error["error"] == "worker_error_unavailable"
    assert worker_error["file"] == ""
    assert timeout["scan_integrity"]["timeout_seconds"] == 0
    assert terminal["file"] == ""
    assert HostileText.touched == HostileInt.touched == HostileIterable.touched == HostileMapping.touched == HostilePathLike.touched == 0


def test_result_evidence_validation_rejects_unknown_mapping_without_mapping_hooks() -> None:
    _reset()

    with pytest.raises(ValueError, match="unsupported mapping"):
        validate_evidence_object_invariants(
            {"file": "sample.exe", "class": "malicious", "score": 99.0, "evidence": HostileMapping()},
            context="unit",
        )

    assert HostileMapping.touched == 0


def test_result_snapshot_rejects_unknown_iterables_without_iter_or_truth_hooks() -> None:
    _reset()

    snapshot = ResultEvidenceSnapshot.from_record(
        {
            "file": "sample.exe",
            "class": "malicious",
            "score": HostileInt(),
            "tags": HostileIterable(),
            "yara_hits": HostileIterable(),
            "decoded_payloads": HostileIterable(),
            "explanation": HostileIterable(),
        }
    )

    assert snapshot.score == 0.0
    assert snapshot.tags == ("tag_text_unavailable",)
    assert snapshot.yara_count == 1
    assert snapshot.decoded_count == 1
    assert snapshot.explanation_present is True
    assert HostileInt.touched == HostileIterable.touched == 0


def test_path_identity_rejects_unknown_path_and_policy_iterables_without_hooks() -> None:
    _reset()

    assert get_scan_extension(HostilePathLike()) == ""
    policy = ScanPathPolicySnapshot.canonical(excluded_dirs=HostileIterable())
    assert policy.excluded_dirs
    identity = PathIdentity(raw="root/sample.exe", name="sample.exe", suffix=".exe", parts=("root", "sample.exe"))
    assert policy.allows_relative(identity, relative_parts=HostileIterable()) is True

    assert HostilePathLike.touched == HostileIterable.touched == 0
