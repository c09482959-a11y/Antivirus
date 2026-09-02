from Virus_Scan.tests.support.adaptive_chain_fixtures import adaptive_chain_evidence_fixture
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping

from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    model_adaptive_markov_signal,
    model_behavior_flow,
)
from Virus_Scan.detection.scoring.adaptive.layer_weights import learn_adaptive_layer_weights
from Virus_Scan.detection.scoring.adaptive.log_odds_fusion import calibrated_log_odds_score_100
from Virus_Scan.detection.scoring.adaptive.model_score import build_probability_features
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


class HostileIterable(Iterable):
    def __init__(self, values):
        self._values = tuple(values)

    def __iter__(self):
        return iter(self._values)

    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("caller-owned iterable truthiness was consulted")


class HostileMapping(Mapping):
    def __init__(self, values=None):
        self._values = dict(values or {})

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __getitem__(self, key):
        return self._values[key]

    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("caller-owned mapping truthiness was consulted")


class HostileText:
    def __init__(self, value):
        self._value = value

    def __str__(self):
        return self._value

    def __bool__(self):  # pragma: no cover - exercised by boundary code
        raise RuntimeError("caller-owned text truthiness was consulted")


def test_stage1480_adaptive_markov_boundary_does_not_truthiness_probe_events():
    _reset_markov_state()
    events = HostileIterable(("api_download", "api_exec"))

    assert model_behavior_flow(events) == ()

    signal = model_adaptive_markov_signal("archive", "runtime", events)

    assert "markov_ready" in signal
    assert "markov_unavailable_reason" in signal


def test_stage1480_probability_features_freeze_hostile_public_inputs():
    _reset_markov_state()
    features = build_probability_features(
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=evaluate_chain_evidence(),
        tags=HostileIterable(("process_exec", "network_download")),
        yara_hits=HostileIterable(()),
        node=None,
        prev_stage=HostileText("archive"),
        curr_stage=HostileText("runtime"),
        file_structure=HostileText("sample.py"),
        strings_blob=HostileText("subprocess.Popen(cmd)"),
        api_calls=HostileIterable(("CreateProcessW",)),
        ordered_events=HostileIterable(("api_download", "api_exec")),
    )

    assert features["model_version"] == "adaptive_probability_features_v2"
    assert features["p_markov"] == 0.0
    assert features["p_markov_unavailable_reason"]
    assert features["p_graph_unavailable_reason"] == "graph_node_not_provided"


def test_stage1480_log_odds_uses_safe_owned_inputs_before_fusion():
    _reset_markov_state()
    score, meta = calibrated_log_odds_score_100(
        32.0,
        attack_mapping_result=unavailable_attack_mapping_fixture(),
        chain_evidence=adaptive_chain_evidence_fixture(tags=HostileIterable(("process_exec",)), api_calls=HostileIterable(()), ordered_events=HostileIterable(("process_exec",))),
        tags=HostileIterable(("process_exec",)),
        yara_hits=HostileIterable(()),
        node=None,
        prev_stage=HostileText("archive"),
        curr_stage=HostileText("runtime"),
        active_layers=HostileText("2"),
        layers=HostileMapping(),
        adaptive_learning=HostileMapping(
            {
                "markov": HostileMapping({"markov_unavailable_reason": "cold_start"}),
                "bucket_vector": HostileMapping(
                    {
                        "bucket_validation": HostileMapping({"unavailable_reason": "cold_start"}),
                        "vector_validation": HostileMapping({"unavailable_reason": "cold_start"}),
                        "timeline_validation": HostileMapping({"unavailable_reason": "cold_start"}),
                    }
                ),
            }
        ),
        strings_blob=HostileText(""),
        api_calls=HostileIterable(()),
        ordered_events=HostileIterable(("process_exec",)),
    )

    assert 0.0 <= score <= 100.0
    assert meta["feature_probabilities"]["markov_unavailable_reason"]


def test_stage1480_layer_weight_learning_freezes_hostile_sequences():
    _reset_markov_state()
    weights = learn_adaptive_layer_weights(
        node="sample.py",
        tags=HostileIterable(("process_exec",)),
        
        quick={"score": 0.2},
        stage={"score": 0.2},
        graph={"score": 0.0, "graph_unavailable_reason": "graph_not_ready"},
        intel={"score": 0.1},
        prev_stage=HostileText("archive"),
        curr_stage=HostileText("runtime"),
        strings_blob=HostileText(""),
        api_calls=HostileIterable(()),
        ordered_events=HostileIterable(("process_exec",)),
    )

    learned_weights, meta = weights

    assert meta["version"] == "adaptive_weight_v1"
    assert abs(sum(learned_weights.values()) - 1.0) < 1e-9
