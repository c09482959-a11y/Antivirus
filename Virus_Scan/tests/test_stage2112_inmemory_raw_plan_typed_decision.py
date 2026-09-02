from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from Virus_Scan.scheduler.workers.inmemory_raw_plan import (
    InMemoryRawPlanDecision,
    build_inmemory_raw_plan,
    build_inmemory_raw_plan_decision,
)


class RawPlanDeps:
    def __init__(
        self,
        *,
        ext: str = ".bin",
        eligible: bool = True,
        jobs: tuple[dict[str, Any], ...] | None = None,
    ) -> None:
        self.ext = ext
        self.eligible = eligible
        self.jobs = ({"seq": 1}, {"seq": 2}) if jobs is None else jobs

    def deep_scan_thorough(self) -> bool:
        return False

    def sniff_file_identity(self, _path: Any) -> dict[str, tuple[str, ...]]:
        return {"tags": ("identity",)}

    def get_scan_extension(self, _path: Any) -> str:
        return self.ext

    def runtime_value(self, _name: str, default: Any = None) -> Any:
        return default

    def normalize_stage(self, _ext: str) -> str:
        return "binary"

    def choose_effective_stage(self, _ext_stage: str, _identity: Any) -> str:
        return "binary"

    def global_raw_eligible(self, *_args: Any, **_kwargs: Any) -> bool:
        return self.eligible

    def global_raw_file_id(self, _path: Any) -> str:
        return "fid"

    def build_raw_stage_jobs(self, *_args: Any, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
        return self.jobs

    def raw_stage_job_build_dependencies(self) -> None:
        return None

    def environ_get(self, _name: str, default: Any = None) -> Any:
        return default

    def now(self) -> float:
        return 10.0


def _decision(*, tags: Any = ("force",), deps: RawPlanDeps | None = None) -> InMemoryRawPlanDecision:
    return build_inmemory_raw_plan_decision(
        path="sample.bin",
        timeout_sec=1,
        pretriage_tags=tags,
        pretriage_suspicious=False,
        pretriage_stage=None,
        deps=RawPlanDeps() if deps is None else deps,
    )


def test_stage2112_inmemory_raw_plan_records_replayable_no_plan_reasons() -> None:
    assert _decision(tags=()).reason == "inmemory_raw_plan_not_requested"
    assert _decision(deps=RawPlanDeps(ext=".rpa")).reason == "inmemory_raw_plan_rpa_disabled"
    assert _decision(deps=RawPlanDeps(eligible=False)).reason == "inmemory_raw_plan_not_eligible"
    assert _decision(deps=RawPlanDeps(jobs=({"seq": 1},))).reason == "inmemory_raw_plan_insufficient_jobs"


def test_stage2112_inmemory_raw_public_contract_preserves_plan_or_none() -> None:
    accepted = _decision()
    assert accepted.reason == "inmemory_raw_plan_available"
    assert accepted.plan is not None
    assert build_inmemory_raw_plan(
        path="sample.bin",
        timeout_sec=1,
        pretriage_tags=("force",),
        pretriage_suspicious=False,
        pretriage_stage=None,
        deps=RawPlanDeps(),
    ) == accepted.plan
    assert build_inmemory_raw_plan(
        path="sample.bin",
        timeout_sec=1,
        pretriage_tags=(),
        pretriage_suspicious=False,
        pretriage_stage=None,
        deps=RawPlanDeps(),
    ) is None


def test_stage2112_inmemory_raw_plan_source_removed_hidden_none_returns() -> None:
    source = Path("Virus_Scan/scheduler/workers/inmemory_raw_plan.py").read_text()
    tree = ast.parse(source)
    public_function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "build_inmemory_raw_plan"
    )
    returns = [
        ast.unparse(node.value)
        for node in ast.walk(public_function)
        if isinstance(node, ast.Return)
    ]
    assert returns == [
        "build_inmemory_raw_plan_decision("
        "path=path, "
        "timeout_sec=timeout_sec, "
        "pretriage_tags=pretriage_tags, "
        "pretriage_suspicious=pretriage_suspicious, "
        "pretriage_stage=pretriage_stage, "
        "deps=deps).plan"
    ]
