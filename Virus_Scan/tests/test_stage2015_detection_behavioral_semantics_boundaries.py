import ast
from pathlib import Path

from Virus_Scan.detection.evidence.behavioral import probabilistic_semantics
from Virus_Scan.detection.evidence.behavioral import semantics
from Virus_Scan.detection.evidence.behavioral.semantics import _semantic_sequence_texts


ROOT = Path(__file__).resolve().parents[2]
PROBABILISTIC = ROOT / "Virus_Scan" / "detection" / "evidence" / "behavioral" / "probabilistic_semantics.py"
SEMANTICS = ROOT / "Virus_Scan" / "detection" / "evidence" / "behavioral" / "semantics.py"
FAILURE_TAGS = ROOT / "Virus_Scan" / "detection" / "evidence" / "failure_tags.py"
CONTEXTUAL_IDENTITY = ROOT / "Virus_Scan" / "detection" / "evidence" / "indicators" / "contextual_identity.py"
NORMALIZATION = ROOT / "Virus_Scan" / "detection" / "evidence" / "normalization.py"
STAGE_COLLECTOR_MERGE = ROOT / "Virus_Scan" / "detection" / "evidence" / "relationships" / "stage_collector_merge.py"
EVASION_SIGNALS = ROOT / "Virus_Scan" / "detection" / "explainability" / "evasion_signals.py"
DOWNLOADER = ROOT / "Virus_Scan" / "detection" / "heuristics" / "downloader.py"
GAME_ENGINE_CORE = ROOT / "Virus_Scan" / "detection" / "heuristics" / "game_engine_core.py"
GAME_ENGINE_ENGINE_RULES = ROOT / "Virus_Scan" / "detection" / "heuristics" / "game_engine_engine_rules.py"
GAME_ENGINE_THREATS = ROOT / "Virus_Scan" / "detection" / "heuristics" / "game_engine_threats.py"
SCRIPT_EXECUTION = ROOT / "Virus_Scan" / "heuristics" / "script_exec.py"
ENRICHED_STAGE_OUTPUTS = ROOT / "Virus_Scan" / "detection" / "models" / "enriched_stage_outputs.py"
DETECTION_EVIDENCE = ROOT / "Virus_Scan" / "detection" / "models" / "evidence.py"
INPUT_STAGE_OUTPUTS = ROOT / "Virus_Scan" / "detection" / "models" / "input_stage_outputs.py"


class HostileContext:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify context")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr context")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test context")


class HostileIterable:
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


class HostileNumber:
    touched = 0

    def __float__(self):
        type(self).touched += 1
        raise RuntimeError("do not float")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


class HostileMappingLike:
    touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("do not call items")

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError("do not call get")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")


def _joined_str_lines(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [node.lineno for node in ast.walk(tree) if isinstance(node, ast.JoinedStr)]


def test_stage2015_behavioral_semantics_source_no_repaired_snippets_or_fstrings() -> None:
    probabilistic_source = PROBABILISTIC.read_text(encoding="utf-8")
    semantics_source = SEMANTICS.read_text(encoding="utf-8")
    forbidden = (
        'return safe_clamp(minimum, minimum, maximum), metric_reason',
        'return safe_clamp(metric, minimum, maximum), ""',
        "rel_num = safe_clamp(RELIABILITY_TO_NUMERIC.get",
        "like = safe_clamp(max(base_like, raw * 0.85))",
        "posterior = safe_clamp(odds / (1.0 + odds))",
        "posterior = safe_clamp(posterior * rel_num + raw * (1.0 - rel_num) * 0.25)",
        "uncertainty = safe_clamp(1.0 - rel_num)",
        'return (), (f"{context}_sequence_rejected",)',
        'missing_reason=f"missing_{context}_text",',
        'unsupported_reason=f"unsafe_{context}_text_rejected",',
        'return 0.0, f"{reason_prefix}_mapping_rejected"',
        'reason=f"unsafe_{reason_prefix}_confidence_rejected",',
        'non_finite_reason=f"nonfinite_{reason_prefix}_confidence",',
        '"probability": safe_clamp(count / files),',
        "'risk': safe_clamp(risk / 10.0),",
        "return {'confidence': safe_clamp(conf)}",
        "'risk': safe_clamp(risk_value / 100.0),",
        "'yara_confidence': safe_clamp(_owned_mapping_value(yara_ev, 'confidence', 0.0)),",
        "'oddity_confidence': safe_clamp(oddity_conf),",
        "'markov_surprise_confidence': safe_clamp(markov_conf),",
        "'graph_context_confidence': safe_clamp(graph_conf),",
        "density_signal = sum(vector.values()) / max(1, len(vector))",
        "'vector': {k: round(v, 4) for k, v in vector.items()},",
        "'confidence': round(safe_clamp(density_signal), 4),",
        "high_authority = bool(raw in HIGH_GATE_SINGLE_ANCHOR_TAGS or canon in HIGH_GATE_SINGLE_ANCHOR_TAGS)",
        "'suppressible_noise_candidate': bool((raw in STRUCTURAL_NOISE_TAGS or bucket in CONTEXTUAL_WEAK_NOISE_BUCKETS) and (not high_authority)),",
        "def _slug_exact_text(value: Any, *, fallback: str) -> tuple[str, str | None]:",
        "raw = fallback",
        "reason = f\"unsafe_{fallback}_tag_text_rejected\"",
        "return text or fallback, reason",
        "return text or fallback, None",
        "fallback=\"recoverable_detection_failure\"",
        "fallback=\"detection_stage\"",
        "Some legacy enrichment/tag functions can only return tag lists.",
        "replay without adding a fallback execution path.",
        "f\"{stage}_degraded\",",
        "f\"{stage}_{category}\",",
        "tags.append(f\"cross_engine_{_sanitize_tag_part(container)}_contains_{_sanitize_tag_part(artifact)}\")",
        "tags.append(f\"declared_{_sanitize_tag_part(declared.lstrip('.'))}_sniffs_as_{_sanitize_tag_part(sniffed)}\")",
        "tags.append(f\"embedded_{_sanitize_tag_part(item)}_payload\")",
        "for family, members in EVIDENCE_FAMILIES.items():",
        'return [f"evidence_family:{name}" for name in sorted(summarize_evidence_families(tags))]',
        'name, failure = safe_detection_text(raw_name, "stage", "stage_collector_name_unavailable")',
        'suspicious, failure = safe_detection_bool(',
        'error_text, failure = safe_detection_text(raw_error, "stage_collector_error_unavailable", "stage_collector_error_unavailable")',
        'errors.append(f"{name}:{error_text}")',
        'tags.append(f"{name}_stage_error")',
        'return -sum((count / total) * math.log2(count / total) for count in counts.values() if count)',
        'low = str(text or "").lower()',
        '"path": str(path or ""),',
        'str(path or "").lower().endswith((".py", ".pyw"))',
        'low = strip_negated_behavior_phrases(str(text or ""))',
        'return accumulator.to_record(engine=eng, source=str(path or ""))',
        'return 0.85 if str(engine or "").lower() in {"unity", "rpgm", "renpy"} else 1.0',
        'src = str(source or "").replace("\\", "/").lower()',
        'active_profile, profile_failure = safe_detection_text(',
        'tag_text, tag_failure = safe_detection_text(tag, "<unavailable>", "stage_collector_tag_unavailable")',
        'suspicious, suspicious_failure = safe_detection_bool(',
        'error_text, error_failure = safe_detection_text(error, "stage_collector_error_unavailable", "stage_collector_error_unavailable")',
        'path, path_failure = safe_detection_text(self.path, "", "raw_scan_path_unavailable")',
        'strings_blob, strings_failure = safe_detection_text(',
        'strings_already_enriched, strings_enriched_failure = safe_detection_bool(',
        'path, path_failure = safe_detection_text(self.path, "", "normalized_path_unavailable")',
        'node, node_failure = safe_detection_text(self.node, "", "normalized_node_unavailable")',
        'curr_stage, stage_failure = safe_detection_text(self.curr_stage, "unknown", "normalized_stage_unavailable")',
    )
    failure_tags_source = FAILURE_TAGS.read_text(encoding="utf-8")
    contextual_identity_source = CONTEXTUAL_IDENTITY.read_text(encoding="utf-8")
    normalization_source = NORMALIZATION.read_text(encoding="utf-8")
    stage_collector_source = STAGE_COLLECTOR_MERGE.read_text(encoding="utf-8")
    extra_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            EVASION_SIGNALS,
            DOWNLOADER,
            GAME_ENGINE_CORE,
            GAME_ENGINE_ENGINE_RULES,
            GAME_ENGINE_THREATS,
            SCRIPT_EXECUTION,
            ENRICHED_STAGE_OUTPUTS,
            DETECTION_EVIDENCE,
            INPUT_STAGE_OUTPUTS,
        )
    )
    combined = probabilistic_source + "\n" + semantics_source + "\n" + failure_tags_source + "\n" + contextual_identity_source + "\n" + normalization_source + "\n" + stage_collector_source + "\n" + extra_sources
    assert [snippet for snippet in forbidden if snippet in combined] == []
    assert _joined_str_lines(PROBABILISTIC) == []
    assert _joined_str_lines(SEMANTICS) == []
    assert _joined_str_lines(FAILURE_TAGS) == []
    assert _joined_str_lines(CONTEXTUAL_IDENTITY) == []
    assert _joined_str_lines(NORMALIZATION) == []
    assert _joined_str_lines(STAGE_COLLECTOR_MERGE) == []
    assert _joined_str_lines(EVASION_SIGNALS) == []
    assert _joined_str_lines(DOWNLOADER) == []
    assert _joined_str_lines(GAME_ENGINE_CORE) == []
    assert _joined_str_lines(GAME_ENGINE_ENGINE_RULES) == []
    assert _joined_str_lines(GAME_ENGINE_THREATS) == []
    assert _joined_str_lines(SCRIPT_EXECUTION) == []
    assert _joined_str_lines(ENRICHED_STAGE_OUTPUTS) == []
    assert _joined_str_lines(DETECTION_EVIDENCE) == []
    assert _joined_str_lines(INPUT_STAGE_OUTPUTS) == []


def test_stage2015_semantic_private_context_rejects_without_hooks() -> None:
    HostileContext.touched = 0
    HostileIterable.touched = 0

    texts, reasons = _semantic_sequence_texts(HostileIterable(), context=HostileContext())

    assert texts == ()
    assert reasons == ("semantic_reason_context_rejected",)
    assert HostileContext.touched == 0
    assert HostileIterable.touched == 0


def test_stage2015_probabilistic_and_vector_boundaries_still_reject_hostile_inputs() -> None:
    HostileNumber.touched = 0
    HostileMappingLike.touched = 0
    prob = probabilistic_semantics.probabilistic_evidence_semantics(raw_confidence=HostileNumber())
    vector = semantics.semantic_evidence_vector_overlay(
        oddity=HostileMappingLike(),
        markov=HostileMappingLike(),
        graph=HostileMappingLike(),
        risk=HostileNumber(),
    )

    assert HostileNumber.touched == 0
    assert HostileMappingLike.touched == 0
    assert prob["failure_evidence_recorded"] is True
    assert vector["failure_evidence_recorded"] is True
    assert vector["vector"]["risk"] == 0.0
