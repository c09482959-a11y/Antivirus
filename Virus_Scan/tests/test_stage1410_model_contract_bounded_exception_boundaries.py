import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("iter unavailable")

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise RuntimeError("getitem unavailable")

    def keys(self):
        raise RuntimeError("keys unavailable")

    def get(self, key, default=None):
        raise RuntimeError("get unavailable")


class HostileText:
    def __str__(self):
        raise RuntimeError("str unavailable")

    def __repr__(self):
        raise RuntimeError("repr unavailable")


def test_stage1410_probability_record_uses_bounded_exception_contracts_only():
    for path in (
        Path("Virus_Scan/models/contracts/probability_record.py"),
        Path("Virus_Scan/publication/model_evidence_projection/api.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        broad_handlers = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            is_broad = node.type is None or (
                isinstance(node.type, ast.Name) and node.type.id in {"Exception", "BaseException"}
            )
            if is_broad:
                broad_handlers.append(node.lineno)
        assert broad_handlers == []


def test_stage1410_probability_materializer_keeps_unreadable_mapping_as_unavailable_evidence():
    materialized = materialize_probability_record(HostileMapping())

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "unreadable_probability_record"
    assert materialized["reason"] == "unreadable_probability_record"


def test_stage1410_publication_contract_projection_handles_hostile_contract_keys_and_values():
    fields = build_model_evidence_final_json_fields(
        {
            "model_evidence": {
                "probability_record": HostileMapping(),
                HostileText(): {"feature_probabilities": {HostileText(): 0.7}},
            }
        }
    )

    evidence = fields["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["unavailable_reasons"]["probability_record.probability"] == "missing_probability_record_field"
    assert any(
        failure["reason"] == "missing_probability_record_field"
        for failure in evidence["model_failures"]
    )
