from Virus_Scan.detection.scoring.adaptive import model_score


def test_stage1172_adaptive_scoring_uses_learned_model_terms():
    confidence = model_score.adaptive_learned_model_confidence(
        profile_signal={"profile_ready": True, "profile_anomaly": 0.6},
        markov_signal={"markov_anomaly": 0.4},
        cluster_signal={"cluster_signal": 0.2},
        vector_signal=0.3,
        bucket_signal=0.5,
    )
    weights = model_score.adaptive_learned_model_weight_from_confidence(
        confidence,
        concrete_count=2,
        profile_files_seen=model_score.ADAPTIVE_WEIGHT_MIN_HISTORY,
        static_anchor_score=15.0,
    )

    assert 0.0 <= confidence <= 1.0
    assert "learned_model_weight" in weights
    assert "neural_model_weight" not in weights
    assert 0.0 <= weights["learned_model_weight"] <= 1.0


def test_stage1172_hybrid_features_do_not_publish_neural_terms():
    features = {
        "p_yara": 0.7,
        "p_mitre": 0.1,
        "p_chain": 0.3,
        "p_evasion": 0.1,
        "p_behavior": 0.5,
        "p_exec": 0.0,
        "p_entropy": 0.2,
        "p_graph": 0.1,
        "p_graph_chain": 0.1,
        "p_attention": 0.1,
        "p_cluster": 0.0,
        "p_markov": 0.0,
        "p_temporal": 0.0,
        "p_profile": 0.0,
        "p_bucket": 0.0,
        "p_vector": 0.0,
        "p_engine": 0.0,
    }
    model_score.hybrid_static_model_evidence_fusion(features)

    assert "p_adaptive_learned_model_confidence" in features
    assert "p_adaptive_learned_model_weight" in features
    assert "p_adaptive_neural_confidence" not in features
    assert "p_adaptive_neural_weight" not in features
