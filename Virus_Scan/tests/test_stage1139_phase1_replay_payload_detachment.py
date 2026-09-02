from Virus_Scan.models.replay.api import result_learning_payload


def _sample_result():
    return {
        "file": "game/script.rpy",
        "classification": "suspicious",
        "score": 42.0,
        "tags": ["network_download", "process_exec"],
        "yara_hits": [{"rule": "suspicious_rule", "meta": {"families": ["loader"]}}],
        "api": {"api_calls": [{"name": "CreateFile", "args": ["payload.bin"]}]},
        "ordered_events": [
            {"tag": "network_download", "meta": {"parts": ["url"]}},
            {"tag": "process_exec", "meta": {"parts": ["run"]}},
        ],
        "behavior_flow": ["network_download", "process_exec"],
        "feature_vector": [0.1, 0.2, 0.3],
        "engine_context": {"renpy": 0.9, "metadata": {"weights": [1]}},
        "scan_integrity": {"allow_learning": True, "evidence": {"markers": ["ok"]}},
    }


def test_stage1139_parent_replay_payload_detaches_source_result_fields():
    source = _sample_result()

    payload = result_learning_payload(source)
    assert payload is not None

    source["tags"].append("mutated_tag")
    source["yara_hits"][0]["meta"]["families"].append("mutated_family")
    source["api"]["api_calls"][0]["args"].append("mutated_arg")
    source["ordered_events"][0]["meta"]["parts"].append("mutated_event")
    source["behavior_flow"].append("mutated_flow")
    source["feature_vector"].append(9.9)
    source["engine_context"]["metadata"]["weights"].append(99)
    source["scan_integrity"]["evidence"]["markers"].append("mutated_integrity")

    assert payload["tags"] == ["network_download", "process_exec"]
    assert payload["yara_hits"][0]["meta"]["families"] == ["loader"]
    assert payload["api_calls"][0]["args"] == ["payload.bin"]
    assert payload["ordered_events"][0]["meta"]["parts"] == ["url"]
    assert payload["behavior_flow"] == ["network_download", "process_exec"]
    assert "vector" not in payload
    assert payload["engine_context"]["metadata"]["weights"] == [1]
    assert payload["integrity"]["evidence"]["markers"] == ["ok"]


def test_stage1139_parent_replay_payload_returned_mutation_does_not_reach_source():
    source = _sample_result()

    payload = result_learning_payload(source)
    assert payload is not None

    payload["tags"].append("payload_mutation")
    payload["ordered_events"][0]["meta"]["parts"].append("payload_mutation")
    assert "vector" not in payload
    payload["engine_context"]["metadata"]["weights"].append(2)

    assert source["tags"] == ["network_download", "process_exec"]
    assert source["ordered_events"][0]["meta"]["parts"] == ["url"]
    assert source["feature_vector"] == [0.1, 0.2, 0.3]
    assert source["engine_context"]["metadata"]["weights"] == [1]
