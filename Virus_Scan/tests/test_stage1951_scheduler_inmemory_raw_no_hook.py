"""Stage1951 scheduler in-memory raw no-hook closure."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from Virus_Scan.detection.tags.evidence_generation import finalize_tag_evidence_generation
from Virus_Scan.scheduler.workers.inmemory_raw_failure import record_inmemory_raw_scan_failure
from Virus_Scan.scheduler.workers.inmemory_raw_finalization import finalize_inmemory_raw_scan_result
from Virus_Scan.scheduler.workers.inmemory_raw_plan import build_inmemory_raw_plan
from Virus_Scan.scheduler.workers.inmemory_raw_scan import scan_file_inmemory_raw


class HostileValue:
    touched = 0

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("str hook executed")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("repr hook executed")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("format hook executed")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("int hook executed")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("float hook executed")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("bool hook executed")

    def __iter__(self):
        HostileValue.touched += 1
        raise RuntimeError("iter hook executed")


class HostileException(RuntimeError):
    touched = 0

    def __str__(self):
        HostileException.touched += 1
        raise RuntimeError("exception str hook executed")

    def __repr__(self):
        HostileException.touched += 1
        raise RuntimeError("exception repr hook executed")


class HostileMapping(dict):
    touched = 0

    def get(self, *_args, **_kwargs):
        HostileMapping.touched += 1
        raise RuntimeError("mapping get hook executed")

    def __getitem__(self, _key):
        HostileMapping.touched += 1
        raise RuntimeError("mapping getitem hook executed")

    def __bool__(self):
        HostileMapping.touched += 1
        raise RuntimeError("mapping bool hook executed")


class HostileTags:
    touched = 0

    def __bool__(self):
        HostileTags.touched += 1
        raise RuntimeError("tags bool hook executed")

    def __iter__(self):
        HostileTags.touched += 1
        raise RuntimeError("tags iter hook executed")

    def __len__(self):
        HostileTags.touched += 1
        raise RuntimeError("tags len hook executed")


@dataclass(frozen=True)
class RawDeps:
    calls: list[Any]
    recoverable_exceptions: tuple[type[BaseException], ...] = (RuntimeError, ValueError, TypeError, OSError, UnicodeError)

    def record_issue(self, stage, exc, **kwargs):
        self.calls.append(("record_issue", stage, type(exc).__name__, kwargs))

    def log_error(self, message):
        self.calls.append(("log_error", message))

    def set_scan_integrity(self, path, integrity):
        self.calls.append(("integrity", integrity))

    def scanner_degraded_tags(self):
        return ["scanner_failure"]

    def normalize_tags(self, tags):
        return list(dict.fromkeys(list(tags)))

    def normalize_yara_hits(self, hits):
        return list(hits)

    def deep_scan_thorough(self):
        return False

    def sniff_file_identity(self, path):
        return {"tags": ["identity"]}

    def get_scan_extension(self, path):
        return ".bin"

    def runtime_value(self, _name, default=None):
        return default

    def normalize_stage(self, ext):
        return "binary"

    def choose_effective_stage(self, _ext_stage, _identity):
        return "binary"

    def global_raw_eligible(self, *_args, **_kwargs):
        return True

    def global_raw_file_id(self, _path):
        return "fid"

    def build_raw_stage_jobs(self, *_args, **_kwargs):
        return ({"seq": 1}, {"seq": 2})

    def raw_stage_job_build_dependencies(self):
        return None

    def execute_stage_job(self, _job):
        return {"tags": ["raw"]}

    def scheduler_thread_pool(self, *_args, **_kwargs):
        return None

    def environ_get(self, _name, default=None):
        return default

    def finalize_tag_evidence_generation(self, tags, **kwargs):
        return finalize_tag_evidence_generation(tags, **kwargs)

    def staged_enrichment_score(self, *_args, **_kwargs):
        return 0.0, []

    def record_suppressed(self, label, exc):
        self.calls.append(("suppressed", label, type(exc).__name__))

    def remember_scan_evidence(self, path, **evidence):
        self.calls.append(("evidence", evidence))

    def apply_integrity_tags(self, tags, integrity, marker):
        if integrity.get("had_degraded_stage"):
            return list(tags) + [marker]
        return list(tags)

    def now(self):
        return 10.0


def test_stage1951_raw_failure_logging_uses_path_and_exception_projection_without_hooks():
    calls: list[Any] = []
    deps = RawDeps(calls)
    HostileValue.touched = 0
    HostileException.touched = 0

    record_inmemory_raw_scan_failure(path=HostileValue(), exc=HostileException("hidden"), deps=deps)

    assert HostileValue.touched == 0
    assert HostileException.touched == 0
    assert calls[0][0:3] == ("record_issue", "inmemory_raw_scan_failed", "HostileException")
    assert "scheduler_path_rejected" in calls[1][1]


def test_stage1951_raw_plan_rejects_hostile_pretriage_and_timeout_without_hooks():
    calls: list[Any] = []
    deps = RawDeps(calls)
    HostileTags.touched = 0
    HostileValue.touched = 0

    plan = build_inmemory_raw_plan(
        path="sample.bin",
        timeout_sec=HostileValue(),
        pretriage_tags=HostileTags(),
        pretriage_suspicious=HostileValue(),
        pretriage_stage=HostileValue(),
        deps=deps,
    )

    assert plan is None
    assert HostileTags.touched == 0
    assert HostileValue.touched == 0


def test_stage1951_raw_finalization_reads_exact_mapping_without_get_bool_or_repr_hooks():
    calls: list[Any] = []
    deps = RawDeps(calls)
    HostileValue.touched = 0

    result = finalize_inmemory_raw_scan_result(
        path="sample.bin",
        pretriage_tags=["pre"],
        raw_results=[{"tags": ["raw"], "suspicious": True, "errors": ["err"], "unused": HostileValue()}],
        plan=type("Plan", (), {"identity": {"tags": ["id"]}, "effective_stage": "binary", "jobs": ({"seq": 1},), "file_id": "fid"})(),
        deps=deps,
    )

    assert HostileValue.touched == 0
    assert result["suspicious"] is True
    assert "router_stage_binary" in result["tags"]
    assert "err" in result["errors"]


def test_stage1951_raw_scan_outer_exception_returns_degraded_evidence_not_clean_none():
    calls: list[Any] = []
    deps = RawDeps(calls)
    HostileException.touched = 0

    class FailingDeps(RawDeps):
        def sniff_file_identity(self, path):
            raise HostileException("hidden")

    result = scan_file_inmemory_raw(
        "sample.bin",
        timeout_sec=1,
        pretriage_tags=["force"],
        pretriage_suspicious=True,
        deps=FailingDeps(calls),
    )

    assert result is not None
    assert result["scan_integrity"]["scan_incomplete"] is True
    assert result["suspicious"] is True
    assert HostileException.touched == 0
