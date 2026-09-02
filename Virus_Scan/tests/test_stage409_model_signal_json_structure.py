from Virus_Scan.publication.json_writer import compact_result_record


def test_stage409_model_signal_lists_preserve_json_native_dicts():
    compact = compact_result_record({
        "path": "sample.rpy",
        "classification": "medium",
        "score": 35.0,
        "tags": ["temporal_anomaly"],
        "temporal_signals": [{"sequence": "open-write-exec", "count": 2}],
        "markov_sequence_signals": ({"transition": "decode->exec", "probability": 0.01},),
        "clustering_signals": [{"cluster": "outlier", "distance": 4.2}],
        "graph_signals": [{"edge": "script->payload", "weight": 1}],
    })

    assert compact["temporal_signals"] == [{"count": 2, "sequence": "open-write-exec"}]
    assert compact["temporal"] == compact["temporal_signals"]
    assert compact["markov_sequence_signals"] == [{"probability": 0.01, "transition": "decode->exec"}]
    assert compact["markov"] == compact["markov_sequence_signals"]
    assert compact["clustering_signals"] == [{"cluster": "outlier", "distance": 4.2}]
    assert compact["graph_signals"] == [{"edge": "script->payload", "weight": 1}]
    assert isinstance(compact["temporal_signals"][0], dict)
    assert compact["contextual_signal_frame"]["signal_presence"]["temporal_signals"] is True
