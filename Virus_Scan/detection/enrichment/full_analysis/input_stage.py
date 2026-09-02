"""Input normalization for full observe-only detection analysis."""

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from Virus_Scan.contracts.detection_observation import artifact_observations_for_path_tags
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import scan_strings
from Virus_Scan.detection.models.input_stage_outputs import NormalizedFacts, RawScanFacts
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.evidence.yara_assimilation import assimilate_reviewed_yara_evidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.evidence_generation import (
    finalize_tag_evidence_generation,
    merge_tag_evidence_inputs,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.utils.stages import normalize_stage
from Virus_Scan.contracts.yara_hits import normalize_yara_hits
from Virus_Scan.detection.enrichment.full_analysis.boundaries import fa_list
from Virus_Scan.routing.artifact_platform import canonical_artifact_platform


PLR2004N262144 = 262144


def prepare_analysis_inputs(
    path: object,
    *,
    tags: object=None,
    yara_hits: object=None,
    curr_stage: object=None,
    strings_blob: object='',
    strings_already_enriched: object=False,
    scan_strings_func: object=scan_strings,
    router_identity: object=None,
    artifact_read_snapshot: object,
    attack_repository_digest: object,
) -> object:
    """Normalize raw analyzer inputs and own string enrichment setup."""
    snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    raw_facts = RawScanFacts.from_inputs(
        path=path,
        tags=tags,
        yara_hits=yara_hits,
        curr_stage=curr_stage,
        strings_blob=strings_blob,
        strings_already_enriched=strings_already_enriched,
    )
    path = raw_facts.path
    tags = raw_facts.tags
    yara_evidence = raw_facts.yara_hits
    yara_hits = raw_facts.yara_hits
    curr_stage = raw_facts.curr_stage
    strings_blob = raw_facts.strings_blob
    strings_already_enriched = raw_facts.strings_already_enriched
    failure_evidence = []

    if strings_already_enriched and strings_blob and len(str(strings_blob)) > PLR2004N262144:
        strings_blob = str(strings_blob)[:262144]

    tag_generation = None
    if type(tags) is TagEvidence:
        tag_evidence = tags
    else:
        tag_generation = finalize_tag_evidence_generation(
            fa_list(tags), path=path, strings_blob=strings_blob, source="analyzer_generation_0",
        )
        tag_evidence = tag_generation.evidence
    tags = tag_evidence.tags
    yara_hits = normalize_yara_hits(yara_evidence)
    node = path

    if curr_stage is None:
        curr_stage = normalize_stage(get_scan_extension(path))

    if strings_blob == "":
        if strings_already_enriched:
            strings_blob = ''
        else:
            try:
                raw = snapshot.read_prefix(2000000)
                strings_blob = raw.decode('latin1', errors='ignore')
            except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
                failure_evidence.append(recoverable_failure_evidence(
                    stage_name='input_file_read',
                    error=e,
                    error_source='read_file_bytes',
                    affected_context=path,
                ))
                strings_blob = ''

    artifact_platform = canonical_artifact_platform(
        path, router_identity=router_identity, strings_blob=strings_blob,
    )

    if not strings_already_enriched:
        try:
            string_tags = scan_strings_func(strings_blob, path=node)
            string_observations = artifact_observations_for_path_tags(
                fa_list(string_tags),
                producer_id="full_analysis_string_scanner",
                stage_id="string_enrichment",
                path=path,
                strings_blob=strings_blob,
                modality="static_string",
                platform=artifact_platform,
            )
            string_evidence = normalize_tag_evidence(
                string_observations,
                source_detector="strings",
                source_stage="string_enrichment",
                derive=True,
            )
            merged = merge_tag_evidence_inputs((tag_evidence, string_evidence))
            tag_generation = finalize_tag_evidence_generation(
                merged, path=path, strings_blob=strings_blob,
                source="input_merge", previous_generation=tag_generation,
            )
            tag_evidence = tag_generation.evidence
            tags = tag_evidence.tags
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
            failure_evidence.append(recoverable_failure_evidence(
                stage_name='string_enrichment',
                error=e,
                error_source='scan_strings',
                affected_context=path,
            ))
    else:
        tag_generation = finalize_tag_evidence_generation(
            tag_evidence, path=path, strings_blob=strings_blob,
            source="strings_pre_enriched", previous_generation=tag_generation,
        )
        tag_evidence = tag_generation.evidence
        tags = tag_evidence.tags

    assimilated_tag_evidence = assimilate_reviewed_yara_evidence(
        tag_evidence,
        yara_evidence,
        platform=artifact_platform,
        repository_digest=(
            str.__str__(attack_repository_digest)
            if type(attack_repository_digest) is str
            else ""
        ),
    )
    if assimilated_tag_evidence is not tag_evidence:
        tag_generation = finalize_tag_evidence_generation(
            assimilated_tag_evidence,
            path=path,
            strings_blob=strings_blob,
            source="reviewed_yara_assimilation",
            previous_generation=tag_generation,
        )
        tag_evidence = tag_generation.evidence
        tags = tag_evidence.tags

    return NormalizedFacts.from_values(
        path=path,
        node=node,
        tags=tags,
        yara_hits=yara_hits,
        curr_stage=curr_stage,
        strings_blob=strings_blob,
        strings_already_enriched=strings_already_enriched,
        yara_evidence=yara_evidence,
        failure_evidence=tuple(failure.to_record() if hasattr(failure, "to_record") else failure for failure in failure_evidence),
        tag_evidence=tag_evidence,
        artifact_platform=artifact_platform,
    )
