import ast
from pathlib import Path

from Virus_Scan.stress import corpus_builder
from Virus_Scan.stress.corpus_builder import coverage_summary
from Virus_Scan.stress.corpus_types import JsonPersistenceContract, SyntheticCorpusPlan, SyntheticStressCase


class HostileStressValue:
    touched = []

    @classmethod
    def reset(cls):
        cls.touched.clear()

    def __str__(self):
        type(self).touched.append("__str__")
        return "hostile"

    def __repr__(self):
        type(self).touched.append("__repr__")
        return "hostile"

    def __format__(self, spec):
        type(self).touched.append("__format__")
        return "hostile"

    def __bool__(self):
        type(self).touched.append("__bool__")
        return True

    def __iter__(self):
        type(self).touched.append("__iter__")
        return iter(())

    def __hash__(self):
        type(self).touched.append("__hash__")
        return 1

    def __eq__(self, other):
        type(self).touched.append("__eq__")
        return False

    def __lt__(self, other):
        type(self).touched.append("__lt__")
        return False


class HostileStressMapping:
    def items(self):
        HostileStressValue.touched.append("mapping.items")
        return (("unsafe", HostileStressValue()),)

    def values(self):
        HostileStressValue.touched.append("mapping.values")
        return (HostileStressValue(),)

    def get(self, key, default=None):
        HostileStressValue.touched.append("mapping.get")
        return default

    def __bool__(self):
        HostileStressValue.touched.append("mapping.__bool__")
        return True


def test_stage2022_stress_policy_extensions_reject_hostile_values_without_hooks():
    saved = corpus_builder.ENGINE_SPECIFIC_FILETYPE_BUCKETS
    hostile = HostileStressValue()
    corpus_builder.ENGINE_SPECIFIC_FILETYPE_BUCKETS = {
        "safe_engine": {
            "safe_bucket": {
                "execution_capability": hostile,
                "extensions": (hostile, "ok"),
            },
        },
    }
    HostileStressValue.reset()

    try:
        contracts = corpus_builder.engine_file_type_contracts()
    finally:
        corpus_builder.ENGINE_SPECIFIC_FILETYPE_BUCKETS = saved

    assert [(contract.engine, contract.bucket, contract.extension, contract.execution_capability) for contract in contracts] == [
        ("safe_engine", "safe_bucket", ".ok", "unknown"),
    ]
    assert HostileStressValue.touched == []


def test_stage2022_stress_summary_rejects_hostile_mappings_without_hooks():
    case = SyntheticStressCase(
        index=0,
        sample_id="synthetic-benign-00000",
        classification="benign",
        family="script",
        engine="generic",
        file_type="script",
        extension=".py",
        relative_path="generic/script/sample_00000.py",
        expected_fast_path=True,
        expected_deep_scan=True,
        worker_matrix=(),
        queue_depth_matrix=(),
        restart_point_matrix=(),
        timeout_pressure_matrix=(),
        archive_depth_matrix=(),
        scan_order_matrix=(),
    )
    plan = SyntheticCorpusPlan(
        total_samples=1,
        benign_samples=1,
        malicious_samples=0,
        engine_file_types=(),
        cases=(case,),
        fast_path_configuration=HostileStressMapping(),
        deep_scan_configuration=HostileStressMapping(),
        json_persistence_contract=JsonPersistenceContract((), (), (), (), HostileStressMapping()),
    )
    HostileStressValue.reset()

    summary = coverage_summary(plan)

    assert summary["fast_path_configuration"] == ()
    assert summary["deep_scan_configuration"] == ()
    assert summary["zero_loss_requirements"] == ()
    assert HostileStressValue.touched == []


def test_stage2022_stress_sources_have_no_repaired_hookable_patterns():
    path = Path("Virus_Scan/stress/corpus_builder.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    assert [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)] == []
    for snippet in (
        ".{extension}",
        ".{family}",
        "engine_anchor__{anchor_key}",
        "synthetic-{classification}-{index:05d}",
        ".items()",
        ".values()",
    ):
        assert snippet not in source
