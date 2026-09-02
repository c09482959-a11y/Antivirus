from types import MappingProxyType

from Virus_Scan.models.contracts.model_evidence import make_model_evidence_record, materialize_model_evidence_record
from Virus_Scan.models.contracts.model_failure import make_cold_start_record, make_model_failure_record, materialize_model_failure_record
from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle, materialize_model_feature_bundle
from Virus_Scan.models.contracts.model_snapshot import make_model_snapshot, make_replay_model_comparison_record, materialize_model_snapshot
from Virus_Scan.models.contracts.probability_record import make_probability_record, materialize_probability_record


class HostileText(str):
    def __str__(self):
        return self

    def strip(self, *args, **kwargs):
        raise AssertionError("caller-owned strip executed")

    def __bool__(self):
        raise AssertionError("caller-owned truthiness executed")


def h(value: str) -> HostileText:
    return HostileText(value)


def assert_exact_text(value, expected: str) -> None:
    assert type(value) is str
    assert value == expected


def test_probability_contract_detaches_hostile_text_fields_without_strip_or_bool():
    record = make_probability_record(
        ready=True,
        probability=0.75,
        support=3,
        count=2,
        vocab=4,
        smoothing=h("laplace"),
        reason=h("trained_support"),
        source=h("extract"),
        target=h("score"),
        flow=[h("extract"), h("score")],
        model_version=h("probability_vx"),
    )

    assert isinstance(record, MappingProxyType)
    assert_exact_text(record["smoothing"], "laplace")
    assert_exact_text(record["reason"], "trained_support")
    assert_exact_text(record["source"], "extract")
    assert_exact_text(record["target"], "score")
    assert all(type(item) is str for item in record["flow"])

    materialized = materialize_probability_record(record)
    assert_exact_text(materialized["model_version"], "probability_vx")
    assert_exact_text(materialized["reason"], "trained_support")


def test_failure_and_cold_start_contracts_detach_hostile_text_and_nested_details():
    failure = make_model_failure_record(
        model_name=h("markov"),
        failure_type=h("computation_failure"),
        reason=h("bad_snapshot"),
        affected_fields=[h("probability"), h("support")],
        details={h("source"): h("snapshot"), h("items"): [h("a"), h("b")]},
        model_version=h("failure_vx"),
    )
    materialized = materialize_model_failure_record(failure)

    assert_exact_text(materialized["model_name"], "markov")
    assert_exact_text(materialized["failure_type"], "computation_failure")
    assert_exact_text(materialized["reason"], "bad_snapshot")
    assert all(type(item) is str for item in materialized["affected_fields"])
    assert_exact_text(materialized["details"]["source"], "snapshot")
    assert all(type(item) is str for item in materialized["details"]["items"])

    cold = make_cold_start_record(
        model_name=h("temporal"),
        reason=h("insufficient_history"),
        affected_fields=[h("stage_probability")],
        model_version=h("cold_vx"),
    )
    cold_materialized = materialize_model_failure_record(cold)
    assert_exact_text(cold_materialized["model_name"], "temporal")
    assert_exact_text(cold_materialized["reason"], "insufficient_history")
    assert all(type(item) is str for item in cold_materialized["affected_fields"])


def test_feature_and_evidence_contracts_do_not_return_hostile_string_subclasses():
    bundle = make_model_feature_bundle(
        {h("score"): h("high"), h("items"): [h("one"), h("two")]},
        model_version=h("bundle_vx"),
    )
    bundle_materialized = materialize_model_feature_bundle(bundle)
    assert_exact_text(bundle_materialized["score"], "high")
    assert all(type(item) is str for item in bundle_materialized["items"])
    assert_exact_text(bundle_materialized["model_version"], "bundle_vx")

    evidence = make_model_evidence_record(
        {h("status"): h("degraded"), h("nested"): {h("reason"): h("cold_start")}},
        model_name=h("profile"),
        evidence_type=h("profile_evidence"),
        model_version=h("evidence_vx"),
    )
    evidence_materialized = materialize_model_evidence_record(evidence)
    assert_exact_text(evidence_materialized["status"], "degraded")
    assert_exact_text(evidence_materialized["nested"]["reason"], "cold_start")
    assert_exact_text(evidence_materialized["model_name"], "profile")


def test_snapshot_and_replay_contracts_detach_hostile_text_across_values_and_reasons():
    snapshot = make_model_snapshot(
        {h("transition"): h("extract->score")},
        model_name=h("markov"),
        snapshot_type=h("runtime_counts"),
        model_version=h("snapshot_vx"),
        ready=False,
        degraded=True,
        reason=h("cold_start"),
        failures=[{h("reason"): h("missing_counts")}],
    )
    materialized = materialize_model_snapshot(snapshot)

    assert_exact_text(materialized["model_name"], "markov")
    assert_exact_text(materialized["snapshot_type"], "runtime_counts")
    assert_exact_text(materialized["reason"], "cold_start")
    assert_exact_text(materialized["values"]["transition"], "extract->score")
    assert_exact_text(materialized["failures"][0]["reason"], "missing_counts")

    replay = make_replay_model_comparison_record(
        model_name=h("graph"),
        expected={h("risk"): h("high")},
        actual={h("risk"): h("low")},
        matched=False,
        mismatch_fields=[h("risk")],
        reason=h("model_evidence_mismatch"),
        model_version=h("replay_vx"),
    )
    replay_materialized = materialize_model_snapshot(replay)
    assert_exact_text(replay_materialized["model_name"], "graph")
    assert_exact_text(replay_materialized["expected"]["risk"], "high")
    assert_exact_text(replay_materialized["actual"]["risk"], "low")
    assert all(type(item) is str for item in replay_materialized["mismatch_fields"])
